#include "internal.h"
#include "mcserver.h"
#include "logging.h"
#include "vb-aliases.h"

#define LOGARGS(c, lvl) \
    &(c)->instance->settings, "server", LCB_LOG_##lvl, __FILE__, __LINE__
#define LOG(c, lvl, msg) lcb_log(LOGARGS(c, lvl), msg)

static void flush_noop(mc_PIPELINE *pipeline) {
    (void)pipeline;
}
static void server_close(mc_SERVER *server, lcb_error_t reason);
static void server_connect(mc_SERVER *server);

typedef enum {
    REFRESH_ALWAYS,
    REFRESH_ONFAILED,
    REFRESH_NEVER
} mc_REFRESHPOLICY;

static void
fail_callback(mc_PIPELINE *pipeline, mc_PACKET *pkt, lcb_error_t err, void *arg)
{
    int rv;
    packet_info info;
    protocol_binary_request_header hdr;
    protocol_binary_response_header *res = &info.res;

    memset(&info, 0, sizeof(info));
    memcpy(hdr.bytes, SPAN_BUFFER(&pkt->kh_span), sizeof(hdr.bytes));

    res->response.status = ntohs(PROTOCOL_BINARY_RESPONSE_EINVAL);
    res->response.opcode = hdr.request.opcode;
    res->response.opaque = hdr.request.opaque;

    rv = mcreq_dispatch_response(pipeline, pkt, &info, err);
    lcb_assert(rv == 0);
    (void)arg;
}

static void
purge_single_server(lcb_server_t *server, lcb_error_t error,
                    hrtime_t thresh, hrtime_t *next, int policy)
{
    unsigned affected;
    mc_PIPELINE *pl = &server->pipeline;

    if (thresh) {
        affected = mcreq_pipeline_timeout(
                pl, error, fail_callback, NULL, thresh, next);

    } else {
        mcreq_pipeline_fail(pl, error, fail_callback, NULL);
        affected = -1;
    }

    if (affected) {
        server->dirty = 1;
    }

    if (policy == REFRESH_NEVER) {
        return;
    }

    if (affected || policy == REFRESH_ALWAYS) {
        lcb_bootstrap_errcount_incr(server->instance);
    }
}

/** Called to handle a socket error */
void
mcserver_socket_error(mc_SERVER *server, lcb_error_t err)
{
    lcbconn_t conn = &server->connection;

    if (conn->state != LCBCONN_S_UNINIT && conn->poolinfo != NULL) {
        connmgr_detach(server->instance->memd_sockpool, conn);
    }

    mcserver_errflush(server);
    lcbconn_close(conn);
    server->pipeline.flush_start = (mcreq_flushstart_fn)server_connect;
    purge_single_server(server, err, 0, NULL, REFRESH_ALWAYS);
    lcb_maybe_breakout(server->instance);
}

void
mcserver_fail_chain(mc_SERVER *server, lcb_error_t err)
{
    mcserver_errflush(server);
    purge_single_server(server, err, 0, NULL, REFRESH_NEVER);
}

static int
server_is_ready(lcb_server_t *server)
{
    if (!server->connection.protoctx) {
        return 0;
    }
    if (!MCCONN_IS_NEGOTIATING(&server->connection)) {
        return 1;
    }
    return 0;
}

static void
timeout_server(lcb_server_t *server)
{
    hrtime_t now, min_valid, next_ns = 0;
    lcb_uint32_t next_us = 0;

    lcb_log(LOGARGS(server, ERR), "Server %p timed out", server);

    if (!server_is_ready(server)) {
        purge_single_server(server, LCB_ETIMEDOUT, 0, NULL, REFRESH_ALWAYS);
        lcb_maybe_breakout(server->instance);
        return;
    }

    now = gethrtime();
    min_valid = now - LCB_US2NS(MCSERVER_TIMEOUT(server));
    purge_single_server(server, LCB_ETIMEDOUT, min_valid, &next_ns,
                        REFRESH_ONFAILED);

    /**
     * The new timeout will be calculated when the next command actually
     * expires. To determine the next expiration, we:
     * (1) Add the timeout interval to the next_ns marker, giving us the
     * absolute timeout value
     * (2) Subtract now from the next absolute timeout, giving us the relative
     * timeout.
     */
    if (next_ns) {
        hrtime_t abstmo = next_ns + LCB_US2NS(MCSERVER_TIMEOUT(server));
        next_us = LCB_NS2US(abstmo - now);

    } else {
        next_us = MCSERVER_TIMEOUT(server);
    }

    lcb_log(LOGARGS(server, INFO),
            "%p, Scheduling next timeout for %u ms", server, next_us / 1000);

    lcb_timer_rearm(server->io_timer, next_us);
    lcb_maybe_breakout(server->instance);
}

/**
 * Called when we're connected to the server
 */
static void
start_operations(lcb_server_t *server)
{
    lcb_log(LOGARGS(server, DEBUG),
            "Starting server=%p operations now..", server);
    server->pipeline.flush_start = (mcreq_flushstart_fn)mcserver_flush;
    mcserver_flush(server);
}

static void
negotiation_done(struct negotiation_context *ctx, lcb_error_t err)
{
    lcb_server_t *server = ctx->data;
    mcserver_wire_io(server, NULL);

    if (err != LCB_SUCCESS) {
        mcserver_socket_error(server, err);

    } else {
        lcbconn_reset_bufs(&server->connection);
        start_operations(server);
    }
}

static void
server_free(mc_SERVER *server)
{
    lcb_assert(server->connreq == NULL && "Cannot free connected server!");
    lcbconn_cleanup(&server->connection);
    mcreq_pipeline_cleanup(&server->pipeline);

    if (server->io_timer) {
        lcb_timer_destroy(NULL, server->io_timer);
    }

    free(server->resthost);
    free(server->viewshost);
    free(server->datahost);
    free(server);
}

void
mcserver_decref(mc_SERVER *server, int ok)
{
    if (--server->refcount) {
        return;
    }
    server_close(server, ok ? LCB_SUCCESS : LCB_ERROR);
    server_free(server);
}

int
mcserver_is_clean(mc_SERVER *server)
{
    return 0;

    if (server->connreq) {
        return 0;
    }

    if (server->connection.state == LCBCONN_S_UNINIT) {
        return 0;
    }

    if (server->dirty) {
        return 0;
    }

    if (server->connection.want) {
        return 0;
    }

    if (netbuf_has_flushdata(&server->pipeline.nbmgr)) {
        return 0;
    }

    if (!SLLIST_IS_EMPTY(&server->pipeline.requests)) {
        return 0;
    }

    if (MCCONN_IS_NEGOTIATING(&server->connection)) {
        return 0;
    }
    return 1;
}

static void
server_close(mc_SERVER *server, lcb_error_t reason)
{
    int can_release = 0;

    if (server->connreq) {
        connmgr_cancel(server->instance->memd_sockpool, server->connreq);
        free(server->connreq);
        server->connreq = NULL;
        return;
    }

    if (server->connection.state == LCBCONN_S_UNINIT) {
        return;
    }

    if (server->connection.poolinfo == NULL) {
        lcbconn_close(&server->connection);
        return;
    }

    if (reason == LCB_SUCCESS) {
        can_release = mcserver_is_clean(server);
    }

    if (can_release) {
        connmgr_put(server->instance->memd_sockpool, &server->connection);
    } else {
        connmgr_discard(server->instance->memd_sockpool, &server->connection);
    }
}

static void
socket_connected(connmgr_request *req)
{
    mc_SERVER *server = req->data;
    lcb_error_t err;
    lcbconn_t conn = req->conn;
    struct negotiation_context *saslctx;
    struct lcb_nibufs_st nistrs;

    if (!conn) {
        err = req->err ? req->err : LCB_CONNECT_ERROR;
    } else {
        err = LCB_SUCCESS;
    }
    free(req);
    server->connreq = NULL;

    if (err != LCB_SUCCESS) {
        mcserver_socket_error(server, err);
        return;
    }

    mcserver_wire_io(server, conn);
    conn = &server->connection;

    if (conn->protoctx) {
        start_operations(server);
        return;
    }

    if (!lcb_get_nameinfo(conn, &nistrs)) {
        mcserver_socket_error(server, LCB_EINTERNAL);
        return;
    }

    saslctx = lcb_negotiation_create(
            conn, conn->settings, MCSERVER_TIMEOUT(server),
            nistrs.local, nistrs.remote, &err);

    if (err != LCB_SUCCESS) {
        mcserver_socket_error(server, err);
        return;
    }

    saslctx->data = server;
    saslctx->complete = negotiation_done;
    server->pipeline.flush_start = flush_noop;
}

static void
server_connect(mc_SERVER *server)
{
    connmgr_request *req = server->connreq;
    lcb_host_t *curhost = &server->curhost;
    /** Already have a pending request */
    if (req) {
        return;
    }

    if (server->connection.state != LCBCONN_S_UNINIT) {
        /** Already connected */
        return;
    }

    req = calloc(1, sizeof(*req));
    connmgr_req_init(req, curhost->host, curhost->port, socket_connected);
    req->data = server;
    server->connreq = req;
    server->pipeline.flush_start = flush_noop;
    connmgr_get(server->instance->memd_sockpool, req, MCSERVER_TIMEOUT(server));
}

static char *
dupstr_or_null(const char *s) {
    if (s) {
        return strdup(s);
    }
    return NULL;
}

/** Dispatch for timeout handler callback */
static void
tmo_thunk(lcb_timer_t tm, lcb_t i, const void *cookie)
{
    lcb_server_t *server = (lcb_server_t *)cookie;
    timeout_server(server);
    (void)tm; (void)i;
}

mc_SERVER *
mcserver_alloc(lcb_t instance, int ix)
{
    lcb_settings *settings = &instance->settings;
    mc_CMDQUEUE *cq = &instance->cmdq;
    mc_SERVER *ret;
    lcb_error_t err;

    ret = calloc(1, sizeof(*ret));
    if (!ret) {
        return ret;
    }

    ret->refcount = 1;
    ret->instance = instance;
    mcreq_pipeline_init(&ret->pipeline);
    err = lcbconn_init(&ret->connection, settings->io, settings);
    if (err != LCB_SUCCESS) {
        server_free(ret);
        return NULL;
    }

    ret->pipeline.flush_start = (mcreq_flushstart_fn)server_connect;
    ret->connection.data = ret;
    ret->datahost = dupstr_or_null(VB_NODESTR(cq->config, ix));
    ret->resthost = dupstr_or_null(VB_RESTURL(cq->config, ix));
    ret->viewshost = dupstr_or_null(VB_VIEWSURL(cq->config, ix));
    lcb_host_parsez(&ret->curhost, ret->datahost, 11210);

    ret->io_timer = lcb_timer_create_simple(
            settings->io, ret, MCSERVER_TIMEOUT(ret), tmo_thunk);
    lcb_timer_disarm(ret->io_timer);
    return ret;
}
