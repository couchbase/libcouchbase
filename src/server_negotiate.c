#include "internal.h" /* lcb_t, lcb_error_handler */
#include "packetutils.h"
#include "simplestring.h"
#include "lcbio.h"
#include "mcserver.h"

static void negotiation_success(lcb_server_t *server)
{
    server->negotiation->complete(server->negotiation, LCB_SUCCESS);
}

static void negotiation_set_error_ex(lcb_server_t *server,
                                     lcb_error_t err, const char *msg)
{
    struct negotiation_context *ctx = server->negotiation;
    ctx->errinfo.err = err;
    if (msg) {
        ctx->errinfo.msg = strdup(msg);
    }
}

static void negotiation_set_error(lcb_server_t *server, const char *msg)
{
    negotiation_set_error_ex(server, LCB_AUTH_ERROR, msg);
}

static void negotiation_bail(struct negotiation_context *ctx)
{
    lcb_error_handler(ctx->server->instance,
                      ctx->errinfo.err,
                      ctx->errinfo.msg);
    lcb_connection_close(&ctx->server->connection);
    ctx->server->inside_handler = 0;
    ctx->complete(ctx, ctx->errinfo.err);
}

/**
 * Called to retrive the mechlist from the packet.
 */
static int set_chosen_mech(lcb_server_t *server,
                           lcb_string *mechlist,
                           const char **data,
                           unsigned int *ndata)
{
    cbsasl_error_t saslerr;
    const char *chosenmech;
    struct negotiation_context *ctx = server->negotiation;

    if (server->instance->sasl_mech_force) {
        char *forcemech = server->instance->sasl_mech_force;
        if (!strstr(mechlist->base, forcemech)) {
            /** Requested mechanism not found */
            negotiation_set_error_ex(server,
                                 LCB_SASLMECH_UNAVAILABLE,
                                 mechlist->base);
            return -1;
        }

        lcb_string_clear(mechlist);
        if (lcb_string_appendz(mechlist, forcemech)) {
            negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
            return -1;
        }
    }

    saslerr = cbsasl_client_start(ctx->sasl, mechlist->base,
                                  NULL, data, ndata, &chosenmech);
    if (saslerr != SASL_OK) {
        negotiation_set_error(server, "Couldn't start SASL client");
        return -1;
    }

    ctx->nmech = strlen(chosenmech);
    if (! (ctx->mech = strdup(chosenmech)) ) {
        negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
        return -1;
    }

    return 0;
}

/**
 * Given the specific mechanisms, send the auth packet to the server.
 */
static int send_sasl_auth(lcb_server_t *server,
                          const char *sasl_data,
                          unsigned int ndata)
{
    protocol_binary_request_no_extras req;
    protocol_binary_request_header *hdr = &req.message.header;
    lcb_connection_t conn = &server->connection;
    lcb_size_t to_write;
    struct negotiation_context *ctx = server->negotiation;

    memset(&req, 0, sizeof(req));

    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.opcode = PROTOCOL_BINARY_CMD_SASL_AUTH;
    hdr->request.keylen = htons((lcb_uint16_t)ctx->nmech);
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr->request.bodylen = htonl((lcb_uint32_t)ndata + ctx->nmech);

    /** Write the packet */
    if (!conn->output) {
        if (! (conn->output = calloc(1, sizeof(*conn->output)))) {
            negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
            return -1;
        }
    }

    to_write = sizeof(req.bytes) + ctx->nmech + ndata;

    if (!ringbuffer_ensure_capacity(conn->output, to_write)) {
        negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
        return -1;
    }

    ringbuffer_write(conn->output, req.bytes, sizeof(req.bytes));
    ringbuffer_write(conn->output, ctx->mech, ctx->nmech);
    ringbuffer_write(conn->output, sasl_data, ndata);
    lcb_sockrw_set_want(conn, LCB_WRITE_EVENT, 0);
    return 0;
}

static int send_sasl_step(lcb_server_t *server, packet_info *packet)
{
    protocol_binary_request_no_extras req;
    protocol_binary_request_header *hdr = &req.message.header;
    struct negotiation_context *ctx = server->negotiation;
    lcb_connection_t conn = &server->connection;
    cbsasl_error_t saslerr;
    const char *step_data;
    unsigned int ndata;
    lcb_size_t to_write;

    saslerr = cbsasl_client_step(ctx->sasl,
                                 packet->payload,
                                 PACKET_NBODY(packet),
                                 NULL,
                                 &step_data,
                                 &ndata);

    if (saslerr != SASL_CONTINUE) {
        negotiation_set_error(server, "Unable to perform SASL STEP");
        return -1;
    }


    memset(&req, 0, sizeof(req));
    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.opcode = PROTOCOL_BINARY_CMD_SASL_STEP;
    hdr->request.keylen = htons((lcb_uint16_t)ctx->nmech);
    hdr->request.bodylen = htonl((lcb_uint32_t)ndata + ctx->nmech);
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;

    to_write = sizeof(req) + ctx->nmech + ndata;
    if (!conn->output) {
        if ( (conn->output = calloc(1, sizeof(*conn->output))) == NULL) {
            negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
            return -1;
        }
    }

    if (!ringbuffer_ensure_capacity(conn->output, to_write)) {
        negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
        return -1;
    }

    ringbuffer_write(conn->output, req.bytes, sizeof(req.bytes));
    ringbuffer_write(conn->output, ctx->mech, ctx->nmech);
    ringbuffer_write(conn->output, step_data, ndata);
    lcb_sockrw_set_want(conn, LCB_WRITE_EVENT, 0);
    return 0;
}

/**
 * It's assumed the server buffers will be reset upon close(), so we must make
 * sure to _not_ release the ringbuffer if that happens.
 */
static void packet_handler(lcb_server_t *server)
{
    packet_info info;
    int rv;
    int is_done = 0;
    lcb_uint16_t status;
    lcb_connection_t conn = &server->connection;
    memset(&info, 0, sizeof(info));


    rv = lcb_packet_read_ringbuffer(&info, conn->input);
    if (rv == 0) {
        lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
        lcb_sockrw_apply_want(conn);
        return;
    }

    if (rv == -1) {
        printf("Packet parser error!\n");
        negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
        return;
    }

    status = PACKET_STATUS(&info);

    switch (PACKET_OPCODE(&info)) {
    case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS: {
        lcb_string str;
        const char *mechlist_data;
        unsigned int nmechlist_data;

        if (lcb_string_init(&str)) {
            negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
            rv = -1;
            break;
        }

        if (lcb_string_append(&str, info.payload, PACKET_NBODY(&info))) {
            lcb_string_release(&str);
            negotiation_set_error_ex(server, LCB_CLIENT_ENOMEM, NULL);
            rv = -1;
            break;
        }

        rv = set_chosen_mech(server, &str, &mechlist_data, &nmechlist_data);
        if (rv == 0) {
            rv = send_sasl_auth(server, mechlist_data, nmechlist_data);
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
            negotiation_set_error(server, "SASL AUTH failed");
            rv = -1;
            break;
        }
        rv = send_sasl_step(server, &info);
        break;
    }

    case PROTOCOL_BINARY_CMD_SASL_STEP: {
        if (status != PROTOCOL_BINARY_RESPONSE_SUCCESS) {
            negotiation_set_error(server, "SASL Step Failed");
            rv = -1;
        } else {
            rv = 0;
            is_done = 1;
        }
        break;
    }

    default: {
        rv = -1;
        negotiation_set_error_ex(server, LCB_NOT_SUPPORTED,
                             "Received unknown response");
        break;
    }
    }

    if (rv == 0) {
        lcb_packet_release_ringbuffer(&info, conn->input);
    }

    if (server->negotiation->errinfo.err) {
        negotiation_bail(server->negotiation);
        return;
    }

    if (is_done) {
        server->inside_handler = 0;
        negotiation_success(server);
    } else if (rv == 0) {
        lcb_sockrw_apply_want(conn);
        server->inside_handler = 0;
    }
}

static void v0_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_server_t *c = arg;
    lcb_connection_t conn = &c->connection;
    lcb_sockrw_status_t status;
    c->inside_handler = 1;

    if (which & LCB_WRITE_EVENT) {
        status = lcb_sockrw_v0_write(conn, conn->output);
        if (status == LCB_SOCKRW_WROTE) {
            lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);

        } else if (status != LCB_SOCKRW_WOULDBLOCK) {
            negotiation_set_error_ex(c, LCB_NETWORK_ERROR, "Couldn't write");
            negotiation_bail(c->negotiation);
            return;

        } else {
            lcb_sockrw_set_want(conn, LCB_WRITE_EVENT, 0);
        }
        if (! (which & LCB_READ_EVENT)) {
            lcb_sockrw_apply_want(conn);
        }
    }

    if (which & LCB_READ_EVENT) {
        status = lcb_sockrw_v0_slurp(conn, conn->input);
        if (status != LCB_SOCKRW_READ && status != LCB_SOCKRW_WOULDBLOCK) {
            negotiation_set_error_ex(c, LCB_NETWORK_ERROR, "Couldn't read");
            negotiation_bail(c->negotiation);
            return;
        }
        packet_handler(c);
    }

    c->inside_handler = 0;

    (void)sock;
}

static void v1_write(lcb_sockdata_t *sockptr, lcb_io_writebuf_t *wbuf,
                     int status)
{
    lcb_server_t *c;


    if (!lcb_sockrw_v1_cb_common(sockptr, wbuf, (void **)&c)) {
        return;
    }

    if (status) {
        negotiation_set_error_ex(c, LCB_NETWORK_ERROR, "Couldn't write");
        negotiation_bail(c->negotiation);
    } else {
        lcb_sockrw_set_want(&c->connection, LCB_READ_EVENT, 1);
        lcb_sockrw_apply_want(&c->connection);
    }
}

static void v1_read(lcb_sockdata_t *sockptr, lcb_ssize_t nr)
{
    lcb_server_t *c;
    if (!lcb_sockrw_v1_cb_common(sockptr, NULL, (void **)&c)) {
        return;
    }

    lcb_sockrw_v1_onread_common(sockptr, &c->connection.input, nr);
    if (nr < 1) {
        negotiation_set_error_ex(c, LCB_NETWORK_ERROR, "Couldn't read");
        negotiation_bail(c->negotiation);
        return;
    }

    c->inside_handler = 1;
    packet_handler(c);
}

static void v1_error(lcb_sockdata_t *sockptr)
{
    lcb_server_t *c;
    if (!lcb_sockrw_v1_cb_common(sockptr, NULL, (void **)&c)) {
        return;
    }
    negotiation_set_error_ex(c, LCB_NETWORK_ERROR, NULL);
    negotiation_bail(c->negotiation);
}

lcb_error_t lcb_negotiation_init(lcb_server_t *server,
                                 const char *remote,
                                 const char *local,
                                 negotiation_callback callback)
{
    cbsasl_error_t saslerr;
    protocol_binary_request_no_extras req;
    lcb_connection_t conn = &server->connection;
    struct negotiation_context *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL) {
        return LCB_CLIENT_ENOMEM;
    }

    lcb_assert(server->negotiation == NULL);

    server->negotiation = ctx;
    ctx->server = server;
    ctx->complete = callback;

    saslerr = cbsasl_client_new("couchbase", conn->host,
                                local, remote,
                                server->instance->sasl.callbacks, 0,
                                &ctx->sasl);

    if (saslerr != SASL_OK) {
        return LCB_CLIENT_ENOMEM;
    }

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SASL_LIST_MECHS;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = 0;
    req.message.header.request.keylen = 0;
    req.message.header.request.opaque = 0;

    if (!conn->output) {
        if ((conn->output = calloc(1, sizeof(*conn->output))) == NULL) {
            return LCB_CLIENT_ENOMEM;
        }
    } else {
        lcb_assert(conn->output->nbytes == 0);
    }

    if (!ringbuffer_ensure_capacity(conn->output, sizeof(req.bytes))) {
        return LCB_CLIENT_ENOMEM;
    }

    if (ringbuffer_write(conn->output, req.bytes, sizeof(req.bytes)) != sizeof(req.bytes)) {
        return LCB_EINTERNAL;
    }

    /** Set up the I/O handlers */
    conn->evinfo.handler = v0_handler;
    conn->completion.write = v1_write;
    conn->completion.read = v1_read;
    conn->completion.error = v1_error;


    lcb_sockrw_set_want(conn, LCB_WRITE_EVENT, 1);
    lcb_sockrw_apply_want(conn);
    return LCB_SUCCESS;
}


void lcb_negotiation_destroy(lcb_server_t *server)
{
    if (!server->negotiation) {
        return;
    }

    if (server->negotiation->sasl) {
        cbsasl_dispose(&server->negotiation->sasl);
    }

    if (server->negotiation->mech) {
        free(server->negotiation->mech);
    }

    free(server->negotiation->errinfo.msg);
    free(server->negotiation);
    server->negotiation = NULL;
}
