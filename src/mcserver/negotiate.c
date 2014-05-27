#include "packetutils.h"
#include "simplestring.h"
#include "mcserver.h"
#include "logging.h"
#include "settings.h"
#include <lcbio/lcbio.h>
#include <lcbio/timer-ng.h>
#include <cbsasl/cbsasl.h>
#include "negotiate.h"

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
    lcb_U16 features[MEMCACHED_TOTAL_HELLO_FEATURES+1];
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
    lcbio_pTIMER timer;
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
timeout_handler(void *arg)
{
    mc_pSASLREQ sreq = arg;
    set_error_ex(sreq, LCB_ETIMEDOUT, "Negotiation timed out");
    bail_pending(sreq);
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

static int
send_hello(mc_pSASLREQ sreq)
{
    protocol_binary_request_no_extras req;
    protocol_binary_request_header *hdr = &req.message.header;
    unsigned ii;
    static const char client_id[] = LCB_VERSION_STRING;
    lcb_U16 features[] = {
            PROTOCOL_BINARY_FEATURE_TLS,
            PROTOCOL_BINARY_FEATURE_DATATYPE };

    lcb_SIZE nfeatures = sizeof features / sizeof *features;
    lcb_SIZE nclistr = strlen(client_id);

    memset(&req, 0, sizeof req);
    hdr->request.opcode = PROTOCOL_BINARY_CMD_HELLO;
    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.keylen = htons((lcb_U16)nclistr);
    hdr->request.bodylen = htonl((lcb_U32)(nclistr+sizeof features));
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;

    lcbio_ctx_put(sreq->ctx, req.bytes, sizeof req.bytes);
    lcbio_ctx_put(sreq->ctx, client_id, strlen(client_id));
    for (ii = 0; ii < nfeatures; ii++) {
        lcb_U16 tmp = htons(features[ii]);
        lcbio_ctx_put(sreq->ctx, &tmp, sizeof tmp);
    }
    lcbio_ctx_rwant(sreq->ctx, 24);
    return 0;
}

static int
parse_hello(mc_pSASLREQ sreq, packet_info *packet)
{
    /* some caps */
    const char *cur;
    const char *payload = PACKET_BODY(packet);
    const char *limit = payload + PACKET_NBODY(packet);
    for (cur = payload; cur < limit; cur += 2) {
        lcb_U16 tmp;
        memcpy(&tmp, cur, sizeof(tmp));
        tmp = ntohs(tmp);
        lcb_log(LOGARGS(sreq, DEBUG), "Found feature 0x%x (%s)", tmp, protocol_feature_2_text(tmp));
        sreq->inner->features[tmp] = 1;
    }
    return 0;
}


typedef enum {
    SREQ_S_WAIT,
    SREQ_S_AUTHDONE,
    SREQ_S_HELLODONE,
    SREQ_S_ERROR
} sreq_STATE;

/**
 * It's assumed the server buffers will be reset upon close(), so we must make
 * sure to _not_ release the ringbuffer if that happens.
 */
static void
handle_read(lcbio_CTX *ioctx, unsigned nb)
{
    mc_pSASLREQ sreq = lcbio_ctx_data(ioctx);
    packet_info info;
    unsigned required;
    uint16_t status;
    sreq_STATE state = SREQ_S_WAIT;
    int rc;

    GT_NEXT_PACKET:

    memset(&info, 0, sizeof(info));
    rc = lcb_pktinfo_ectx_get(&info, ioctx, &required);
    if (rc == 0) {
        LCBIO_CTX_RSCHEDULE(ioctx, required);
        return;
    } else if (rc < 0) {
        state = SREQ_S_ERROR;
    }

    status = PACKET_STATUS(&info);

    switch (PACKET_OPCODE(&info)) {
    case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS: {
        lcb_string str;
        const char *mechlist_data;
        unsigned int nmechlist_data;
        if (lcb_string_init(&str)) {
            set_error_ex(sreq, LCB_CLIENT_ENOMEM, NULL);
            state = SREQ_S_ERROR;
            break;
        }

        if (lcb_string_append(&str, info.payload, PACKET_NBODY(&info))) {
            lcb_string_release(&str);
            set_error_ex(sreq, LCB_CLIENT_ENOMEM, NULL);
            state = SREQ_S_ERROR;
            break;
        }
        if (0 == set_chosen_mech(sreq, &str, &mechlist_data, &nmechlist_data) &&
                0 == send_sasl_auth(sreq, mechlist_data, nmechlist_data)) {
            state = SREQ_S_WAIT;
        } else {
            state = SREQ_S_ERROR;
        }
        lcb_string_release(&str);
        break;
    }

    case PROTOCOL_BINARY_CMD_SASL_AUTH: {
        if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
            send_hello(sreq);
            state = SREQ_S_AUTHDONE;
            break;
        }

        if (status != PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE) {
            set_error_ex(sreq, LCB_AUTH_ERROR, "SASL AUTH failed");
            state = SREQ_S_ERROR;
            break;
        }
        if (send_sasl_step(sreq, &info) == 0 && send_hello(sreq) == 0) {
            state = SREQ_S_WAIT;
        } else {
            state = SREQ_S_ERROR;
        }
        break;
    }

    case PROTOCOL_BINARY_CMD_SASL_STEP: {
        if (status != PROTOCOL_BINARY_RESPONSE_SUCCESS) {
            set_error_ex(sreq, LCB_AUTH_ERROR, "SASL Step Failed");
            state = SREQ_S_ERROR;
        } else {
            /* Wait for pipelined HELLO response */
            state = SREQ_S_AUTHDONE;
        }
        break;
    }

    case PROTOCOL_BINARY_CMD_HELLO: {
        state = SREQ_S_HELLODONE;
        if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
            parse_hello(sreq, &info);
        } else if (status == PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND ||
                status == PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED) {
            lcb_log(LOGARGS(sreq, DEBUG), "Server does not support HELLO");
            /* nothing */
        } else {
            set_error_ex(sreq, LCB_PROTOCOL_ERROR, "Hello response unexpected");
            state = SREQ_S_ERROR;
        }
        break;
    }

    default: {
        state = SREQ_S_ERROR;
        lcb_log(LOGARGS(sreq, ERROR), "Received unknown response. OP=0x%x. RC=0x%x", PACKET_OPCODE(&info), PACKET_STATUS(&info));
        set_error_ex(sreq, LCB_NOT_SUPPORTED, "Received unknown response");
        break;
    }
    }

    lcb_pktinfo_ectx_done(&info, ioctx);
    if (sreq->err != LCB_SUCCESS) {
        bail_pending(sreq);
    } else if (state == SREQ_S_ERROR) {
        set_error_ex(sreq, LCB_ERROR, "FIXME: Error code set without description");
    } else if (state == SREQ_S_HELLODONE) {
        negotiation_success(sreq);
    } else {
        goto GT_NEXT_PACKET;
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
        lcbio_timer_destroy(sreq->timer);
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
    sreq->timer = lcbio_timer_new(sock->io, sreq, timeout_handler);
    sreq->ctx->subsys = "sasl";

    if (tmo) {
        lcbio_timer_rearm(sreq->timer, tmo);
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

int
mc_sasl_chkfeature(mc_pSASLINFO info, lcb_U16 feature)
{
    if (feature > MEMCACHED_TOTAL_HELLO_FEATURES) {
        return 0;
    }
    return info->features[feature];
}
