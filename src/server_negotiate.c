#include "packetutils.h"
#include "simplestring.h"
#include "mcserver.h"
#include "logging.h"
#include "settings.h"
#include <lcbio/lcbio.h>
#include <cbsasl/cbsasl.h>

#define LOGARGS(ctx, lvl) \
    ctx->inner->settings, "negotiation", LCB_LOG_##lvl, __FILE__, __LINE__

static void cleanup_pending(mc_pSASLREQ);
static void cleanup_negotiated(mc_pSASLINFO);
static void bail_pending(mc_pSASLREQ sreq);

/**
 * Inner negotiation structure which is maintained as part of a 'protocol
 * context'.
 */
struct mc_SASLINFO {
    lcbio_PROTOCTX base;
    cbsasl_conn_t *sasl;
    char *mech;
    unsigned int nmech;
    lcb_settings *settings;
    lcbio_CONNDONE_cb complete;
    union {
        cbsasl_secret_t secret;
        char buffer[256];
    } u_auth;
    cbsasl_callback_t sasl_callbacks[4];
};

/**
 * Structure used only for initialization. This is only used for the duration
 * of the request for negotiation and is deleted once negotiation has
 * completed (or failed).
 */
typedef struct mc_SASLREQ {
    lcbio_CTX *ctx;
    lcbio_CONNDONE_cb cb;
    void *data;
    lcb_timer_t timer;
    lcb_error_t err;
    mc_pSASLINFO inner;
} neg_PENDING;

static int
sasl_get_username(void *context, int id, const char **result, unsigned int *len)
{
    struct mc_SASLINFO *ctx = context;
    if (!context || !result || (id != CBSASL_CB_USER && id != CBSASL_CB_AUTHNAME)) {
        return SASL_BADPARAM;
    }

    *result = ctx->settings->username;
    if (len) {
        *len = (unsigned int)strlen(*result);
    }

    return SASL_OK;
}

static int
sasl_get_password(cbsasl_conn_t *conn, void *context, int id,
                  cbsasl_secret_t **psecret)
{
    struct mc_SASLINFO *ctx = context;
    if (!conn || ! psecret || id != CBSASL_CB_PASS || ctx == NULL) {
        return SASL_BADPARAM;
    }

    *psecret = &ctx->u_auth.secret;
    return SASL_OK;
}

static lcb_error_t
setup_sasl_params(struct mc_SASLINFO *ctx)
{
    int ii;
    cbsasl_callback_t *callbacks = ctx->sasl_callbacks;
    const char *password = ctx->settings->password;

    callbacks[0].id = CBSASL_CB_USER;
    callbacks[0].proc = (int( *)(void)) &sasl_get_username;

    callbacks[1].id = CBSASL_CB_AUTHNAME;
    callbacks[1].proc = (int( *)(void)) &sasl_get_username;

    callbacks[2].id = CBSASL_CB_PASS;
    callbacks[2].proc = (int( *)(void)) &sasl_get_password;

    callbacks[3].id = CBSASL_CB_LIST_END;
    callbacks[3].proc = NULL;
    callbacks[3].context = NULL;

    for (ii = 0; ii < 3; ii++) {
        callbacks[ii].context = ctx;
    }

    memset(&ctx->u_auth, 0, sizeof(ctx->u_auth));

    if (password) {
        unsigned long pwlen;
        lcb_size_t maxlen;

        pwlen = (unsigned long)strlen(password);
        maxlen = sizeof(ctx->u_auth.buffer) - offsetof(cbsasl_secret_t, data);
        ctx->u_auth.secret.len = pwlen;

        if (pwlen < maxlen) {
            memcpy(ctx->u_auth.secret.data, password, pwlen);
        } else {
            return LCB_EINVAL;
        }
    }
    return LCB_SUCCESS;
}

static void
close_cb(lcbio_SOCKET *s, int reusable, void *arg)
{
    *(lcbio_SOCKET **)arg = s;
    lcbio_ref(s);
    lcb_assert(reusable);
}

static void
negotiation_success(mc_pSASLREQ sreq)
{
    /** Dislodge the connection, and return it back to the caller */
    lcbio_SOCKET *s;

    lcbio_ctx_close(sreq->ctx, close_cb, &s);
    sreq->ctx = NULL;

    lcbio_protoctx_add(s, &sreq->inner->base);
    sreq->inner = NULL;

    /** Invoke the callback, marking it a success */
    sreq->cb(s, sreq->data, LCB_SUCCESS, 0);
    lcbio_unref(s);
    cleanup_pending(sreq);
}

static void
bail_pending(mc_pSASLREQ sreq)
{
    sreq->cb(NULL, sreq->data, sreq->err, 0);
    cleanup_pending(sreq);
}

static void
set_error_ex(mc_pSASLREQ sreq, lcb_error_t err, const char *msg)
{
    lcb_log(LOGARGS(sreq, ERR), "Received error for SASL req %p: 0x%x, %s", sreq, err, msg);
    if (sreq->err == LCB_SUCCESS) {
        sreq->err = err;
    }
}

static void
timeout_handler(lcb_timer_t tm, lcb_t i, const void *cookie)
{
    mc_pSASLREQ sreq = (void *)cookie;
    set_error_ex(sreq, LCB_ETIMEDOUT, "Negotiation timed out");
    bail_pending(sreq);
    (void)tm; (void)i;
}

/**
 * Called to retrive the mechlist from the packet.
 */
static int
set_chosen_mech(mc_pSASLREQ sreq, lcb_string *mechlist, const char **data,
                unsigned int *ndata)
{
    cbsasl_error_t saslerr;
    const char *chosenmech;
    mc_pSASLINFO ctx = sreq->inner;

    lcb_assert(sreq->inner);
    if (ctx->settings->sasl_mech_force) {
        char *forcemech = ctx->settings->sasl_mech_force;
        if (!strstr(mechlist->base, forcemech)) {
            /** Requested mechanism not found */
            set_error_ex(sreq, LCB_SASLMECH_UNAVAILABLE, mechlist->base);
            return -1;
        }

        lcb_string_clear(mechlist);
        if (lcb_string_appendz(mechlist, forcemech)) {
            set_error_ex(sreq, LCB_CLIENT_ENOMEM, NULL);
            return -1;
        }
    }

    saslerr = cbsasl_client_start(ctx->sasl, mechlist->base,
                                  NULL, data, ndata, &chosenmech);
    if (saslerr != SASL_OK) {
        set_error_ex(sreq, LCB_EINTERNAL, "Couldn't start SASL client");
        return -1;
    }

    ctx->nmech = strlen(chosenmech);
    if (! (ctx->mech = strdup(chosenmech)) ) {
        set_error_ex(sreq, LCB_CLIENT_ENOMEM, NULL);
        return -1;
    }

    return 0;
}

/**
 * Given the specific mechanisms, send the auth packet to the server.
 */
static int
send_sasl_auth(neg_PENDING *pend, const char *sasl_data, unsigned ndata)
{
    mc_pSASLINFO ctx = pend->inner;
    protocol_binary_request_no_extras req;
    protocol_binary_request_header *hdr = &req.message.header;
    memset(&req, 0, sizeof(req));

    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.opcode = PROTOCOL_BINARY_CMD_SASL_AUTH;
    hdr->request.keylen = htons((lcb_uint16_t)ctx->nmech);
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr->request.bodylen = htonl((lcb_uint32_t)ndata + ctx->nmech);

    lcbio_ctx_put(pend->ctx, req.bytes, sizeof(req.bytes));
    lcbio_ctx_put(pend->ctx, ctx->mech, ctx->nmech);
    lcbio_ctx_put(pend->ctx, sasl_data, ndata);
    lcbio_ctx_rwant(pend->ctx, 24);
    return 0;
}

static int
send_sasl_step(mc_pSASLREQ sreq, packet_info *packet)
{
    protocol_binary_request_no_extras req;
    protocol_binary_request_header *hdr = &req.message.header;
    cbsasl_error_t saslerr;
    const char *step_data;
    unsigned int ndata;
    mc_pSASLINFO ctx = sreq->inner;

    saslerr = cbsasl_client_step(
            ctx->sasl, packet->payload, PACKET_NBODY(packet), NULL, &step_data,
            &ndata);

    if (saslerr != SASL_CONTINUE) {
        set_error_ex(sreq, LCB_EINTERNAL, "Unable to perform SASL STEP");
        return -1;
    }

    memset(&req, 0, sizeof(req));
    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.opcode = PROTOCOL_BINARY_CMD_SASL_STEP;
    hdr->request.keylen = htons((uint16_t)ctx->nmech);
    hdr->request.bodylen = htonl((uint32_t)ndata + ctx->nmech);
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;

    lcbio_ctx_put(sreq->ctx, req.bytes, sizeof(req.bytes));
    lcbio_ctx_put(sreq->ctx, ctx->mech, ctx->nmech);
    lcbio_ctx_put(sreq->ctx, step_data, ndata);
    lcbio_ctx_rwant(sreq->ctx, 24);
    return 0;
}

/**
 * It's assumed the server buffers will be reset upon close(), so we must make
 * sure to _not_ release the ringbuffer if that happens.
 */
static void
handle_read(lcbio_CTX *ioctx, unsigned nb)
{
    mc_pSASLREQ sreq = lcbio_ctx_data(ioctx);
    packet_info info;
    int rv;
    int is_done = 0;
    unsigned required;
    uint16_t status;

    memset(&info, 0, sizeof(info));
    rv = lcb_pktinfo_ectx_get(&info, ioctx, &required);
    if (rv == 0) {
        LCBIO_CTX_RSCHEDULE(ioctx, required);
        return;
    }

    status = PACKET_STATUS(&info);

    switch (PACKET_OPCODE(&info)) {
    case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS: {
        lcb_string str;
        const char *mechlist_data;
        unsigned int nmechlist_data;
        if (lcb_string_init(&str)) {
            set_error_ex(sreq, LCB_CLIENT_ENOMEM, NULL);
            rv = -1;
            break;
        }

        if (lcb_string_append(&str, info.payload, PACKET_NBODY(&info))) {
            lcb_string_release(&str);
            set_error_ex(sreq, LCB_CLIENT_ENOMEM, NULL);
            rv = -1;
            break;
        }

        rv = set_chosen_mech(sreq, &str, &mechlist_data, &nmechlist_data);
        if (rv == 0) {
            rv = send_sasl_auth(sreq, mechlist_data, nmechlist_data);
        }

        lcb_string_release(&str);
        break;
    }

    case PROTOCOL_BINARY_CMD_SASL_AUTH: {
        if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
            rv = 0;
            is_done = 1;
            break;
        }

        if (status != PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE) {
            set_error_ex(sreq, LCB_AUTH_ERROR, "SASL AUTH failed");
            rv = -1;
            break;
        }
        rv = send_sasl_step(sreq, &info);
        break;
    }

    case PROTOCOL_BINARY_CMD_SASL_STEP: {
        if (status != PROTOCOL_BINARY_RESPONSE_SUCCESS) {
            set_error_ex(sreq, LCB_AUTH_ERROR, "SASL Step Failed");
            rv = -1;
        } else {
            rv = 0;
            is_done = 1;
        }
        break;
    }

    default: {
        rv = -1;
        set_error_ex(sreq, LCB_NOT_SUPPORTED, "Received unknown response");
        break;
    }
    }

    lcb_pktinfo_ectx_done(&info, ioctx);
    if (sreq->err != LCB_SUCCESS) {
        bail_pending(sreq);
    } else if (is_done) {
        negotiation_success(sreq);
    } else {
        lcbio_ctx_schedule(ioctx);
    }
}

static void
handle_ioerr(lcbio_CTX *ctx, lcb_error_t err)
{
    mc_pSASLREQ sreq = lcbio_ctx_data(ctx);
    set_error_ex(sreq, err, "IO Error");
    bail_pending(sreq);
}

static void
cleanup_negotiated(mc_pSASLINFO ctx)
{
    if (ctx->sasl) {
        cbsasl_dispose(&ctx->sasl);
    }
    if (ctx->mech) {
        free(ctx->mech);
    }
    free(ctx);
}

static void
cleanup_pending(mc_pSASLREQ sreq)
{
    if (sreq->inner) {
        cleanup_negotiated(sreq->inner);
        sreq->inner = NULL;
    }
    if (sreq->timer) {
        lcb_timer_destroy(NULL, sreq->timer);
        sreq->timer = NULL;
    }
    if (sreq->ctx) {
        lcbio_ctx_close(sreq->ctx, NULL, NULL);
        sreq->ctx = NULL;
    }
    free(sreq);
}

void
mc_sasl_cancel(mc_pSASLREQ sreq)
{
    cleanup_pending(sreq);
}

mc_pSASLREQ
mc_sasl_start(lcbio_SOCKET *sock, lcb_settings *settings,
              uint32_t tmo, lcbio_CONNDONE_cb callback, void *data)
{
    lcb_error_t err;
    cbsasl_error_t saslerr;
    protocol_binary_request_no_extras req;
    const lcb_host_t *curhost;
    struct lcbio_NAMEINFO nistrs;
    mc_pSASLREQ sreq;
    mc_pSASLINFO sasl;
    lcbio_EASYPROCS procs;

    if ((sreq = calloc(1, sizeof(*sreq))) == NULL) {
        return NULL;
    }

    if ((sasl = calloc(1, sizeof(*sasl))) == NULL) {
        cleanup_pending(sreq);
        return NULL;
    }

    procs.cb_err = handle_ioerr;
    procs.cb_read = handle_read;

    lcbio_get_nameinfo(sock, &nistrs);
    sreq->cb = callback;
    sreq->data = data;
    sreq->inner = sasl;
    sreq->ctx = lcbio_ctx_new(sock, sreq, &procs);
    sreq->timer = lcb_timer_create_simple(sock->io, sreq, tmo, timeout_handler);

    if (!tmo) {
        lcb_timer_disarm(sreq->timer);
    }

    sasl->base.id = LCBIO_PROTOCTX_SASL;
    sasl->base.dtor = (void (*)(struct lcbio_PROTOCTX *))cleanup_negotiated;
    sasl->settings = settings;

    err = setup_sasl_params(sasl);
    if (err != LCB_SUCCESS) {
        cleanup_pending(sreq);
        return NULL;
    }


    curhost = lcbio_get_host(sock);
    saslerr = cbsasl_client_new(
            "couchbase", curhost->host, nistrs.local, nistrs.remote,
            sasl->sasl_callbacks, 0, &sasl->sasl);

    if (saslerr != SASL_OK) {
        cleanup_pending(sreq);
        return NULL;
    }

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SASL_LIST_MECHS;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = 0;
    req.message.header.request.keylen = 0;
    req.message.header.request.opaque = 0;

    lcbio_ctx_put(sreq->ctx, req.bytes, sizeof(req.bytes));
    LCBIO_CTX_RSCHEDULE(sreq->ctx, 24);
    return sreq;
}

mc_pSASLINFO
mc_sasl_get(lcbio_SOCKET *sock)
{
    return (void *)lcbio_protoctx_get(sock, LCBIO_PROTOCTX_SASL);
}

const char *
mc_sasl_getmech(mc_pSASLINFO info)
{
    return info->mech;
}
