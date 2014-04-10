/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2014 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "internal.h"
#include "logging.h"
#include "vb-aliases.h"
#include "settings.h"

#include "bucketconfig/clconfig.h"
#include "mc/mcreq-flush-inl.h"

#define LOGARGS(c, lvl) \
    (c)->settings, "server", LCB_LOG_##lvl, __FILE__, __LINE__
#define LOG(c, lvl, msg) lcb_log(LOGARGS(c, lvl), msg)

#define MCREQ_MAXIOV 32
#define LCBCONN_UNWANT(conn, flags) (conn)->want &= ~(flags)

static int check_closed(mc_SERVER *);

static void
on_flush_ready(lcbio_CTX *ctx)
{
    mc_SERVER *server = lcbio_ctx_data(ctx);
    nb_IOV iov[MCREQ_MAXIOV];
    int ready;

    do {
        int niov = 0;
        unsigned nb;
        nb = mcreq_flush_iov_fill(&server->pipeline, iov, MCREQ_MAXIOV, &niov);
        if (!nb) {
            break;
        }
        ready = lcbio_ctx_put_ex(ctx, (lcb_IOV *)iov, niov, nb);
    } while (ready);
}

static void
on_flush_done(lcbio_CTX *ctx, unsigned expected, unsigned actual)
{
    mc_SERVER *server = lcbio_ctx_data(ctx);
    mcreq_flush_done(&server->pipeline, actual, expected);
    check_closed(server);
}

static void
on_error(lcbio_CTX *ctx, lcb_error_t err)
{
    mc_SERVER *server = lcbio_ctx_data(ctx);
    lcb_log(LOGARGS(server, WARN), "Got socket [%p] error 0x%x", server, err);
    if (check_closed(server)) {
        return;
    }
    mcserver_socket_error(server, err);
}

void
mcserver_flush(mc_SERVER *server)
{
    /** Call into the wwant stuff.. */
    if (!server->connctx->rdwant) {
        lcbio_ctx_rwant(server->connctx, 24);
    }

    lcbio_ctx_wwant(server->connctx);
    lcbio_ctx_schedule(server->connctx);

    if (!lcb_timer_armed(server->io_timer)) {
        lcb_timer_rearm(server->io_timer, MCSERVER_TIMEOUT(server));
    }
}

void
mcserver_errflush(mc_SERVER *server)
{
    unsigned toflush;
    nb_IOV iov;
    mc_PIPELINE *pl = &server->pipeline;
    while ((toflush = mcreq_flush_iov_fill(pl, &iov, 1, NULL))) {
        mcreq_flush_done(pl, toflush, toflush);
    }
}

/**
 * Invoked when get a NOT_MY_VBUCKET response. If the response contains a JSON
 * payload then we refresh the configuration with it.
 *
 * This function returns 1 if the operation was successfully rescheduled;
 * otherwise it returns 0. If it returns 0 then we give the error back to the
 * user.
 */
static int
handle_nmv(lcb_server_t *oldsrv, packet_info *resinfo, mc_PACKET *oldpkt)
{
    int idx;
    mc_PACKET *newpkt;
    lcb_server_t *newsrv;
    lcb_error_t err = LCB_ERROR;
    int vb;
    lcb_t instance = oldsrv->instance;
    mc_CMDQUEUE *cq = &instance->cmdq;
    mc_REQDATA *rd = MCREQ_PKT_RDATA(oldpkt);
    protocol_binary_request_header hdr;
    mcreq_read_hdr(oldpkt, &hdr);
    vb = ntohs(hdr.request.vbucket);

    lcb_log(LOGARGS(oldsrv, WARN),
            "NOT_MY_VBUCKET; Server=%p,ix=%d,real_start=%lu,vb=%d",
            (void*)oldsrv, oldsrv->pipeline.index, (unsigned long)rd->start, vb);


    if (PACKET_NBODY(resinfo)) {
        lcb_string s;
        clconfig_provider *cccp;

        lcb_string_init(&s);
        cccp = lcb_confmon_get_provider(instance->confmon, LCB_CLCONFIG_CCCP);
        lcb_string_append(&s, PACKET_VALUE(resinfo), PACKET_NVALUE(resinfo));
        err = lcb_cccp_update(cccp, oldsrv->curhost.host, &s);
        lcb_string_release(&s);
    }


    if (err != LCB_SUCCESS) {
        lcb_bootstrap_refresh(instance);
    }

    /* re-schedule command to new server */
    if (!oldsrv->settings->vb_noguess) {
        idx = VB_REMAP(cq->config, vb, (int)oldsrv->pipeline.index);
    } else {
        idx = oldsrv->pipeline.index;
    }

    if (idx == -1) {
        lcb_log(LOGARGS(oldsrv, ERR), "no alternate server");
        return 0;
    }

    lcb_log(LOGARGS(oldsrv, INFO), "Mapped key to new server %d -> %d",
            oldsrv->pipeline.index, idx);

    newpkt = mcreq_dup_packet(oldpkt);
    newpkt->flags &= ~MCREQ_STATE_FLAGS;
    newpkt->opaque = ++cq->seq;
    mcreq_read_hdr(newpkt, &hdr);
    hdr.request.opaque = newpkt->opaque;
    mcreq_write_hdr(newpkt, &hdr);

    newsrv = (lcb_server_t *)instance->cmdq.pipelines[idx];
    mcreq_packet_handled(&oldsrv->pipeline, oldpkt);

    lcb_assert((lcb_size_t)idx < cq->npipelines);
    newsrv = (lcb_server_t *)cq->pipelines[idx];
    mcreq_enqueue_packet(&newsrv->pipeline, newpkt);
    newsrv->pipeline.flush_start(&newsrv->pipeline);
    return 1;
}

static void
handle_single_packet(lcb_server_t *server, packet_info *info)
{
    int is_final_response = 1;
    mc_PACKET *packet;
    mc_PIPELINE *pl = &server->pipeline;

    if (PACKET_OPCODE(info) == PROTOCOL_BINARY_CMD_STAT && PACKET_NKEY(info) != 0) {
        is_final_response = 0;
    }

    if (is_final_response) {
        packet = mcreq_pipeline_remove(&server->pipeline, PACKET_OPAQUE(info));
    } else {
        packet = mcreq_pipeline_find(&server->pipeline, PACKET_OPAQUE(info));
    }

    if (!packet) {
        lcb_log(LOGARGS(server, WARN),
                "Found stale packet (OP=0x%x, RC=0x%x, SEQ=%u)",
                PACKET_OPCODE(info), PACKET_STATUS(info), PACKET_OPAQUE(info));
        return;
    }

    /** Check for NOT_MY_VBUCKET; relocate as needed */
    if (PACKET_STATUS(info) == PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET) {
        if (handle_nmv(server, info, packet)) {
            /** Handled */
            return;
        }
    }
    if (! (packet->flags & MCREQ_F_UFWD)) {
        mcreq_dispatch_response(pl, packet, info, LCB_SUCCESS);
    }
    if (is_final_response) {
        mcreq_packet_handled(pl, packet);
    }
}

static void
on_read(lcbio_CTX *ctx, unsigned nb)
{
    packet_info info;
    mc_SERVER *server = lcbio_ctx_data(ctx);
    rdb_IOROPE *ior = &ctx->ior;

    if (check_closed(server)) {
        return;
    }

    (void)nb;

    while (1) {
        int rv;
        unsigned required;
        rv = lcb_pktinfo_ior_get(&info, ior, &required);
        if (!rv) {
            if (mcserver_has_pending(server)) {
                lcbio_ctx_rwant(ctx, required);
            }
            lcbio_ctx_schedule(ctx);
            lcb_maybe_breakout(server->instance);
            return;
        }
        handle_single_packet(server, &info);
        lcb_pktinfo_ior_done(&info, ior);
    }
    lcb_maybe_breakout(server->instance);
}

int
mcserver_has_pending(mc_SERVER *server)
{
    return !SLLIST_IS_EMPTY(&server->pipeline.requests);
}

static void flush_noop(mc_PIPELINE *pipeline) {
    (void)pipeline;
}
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
    lcbio_connreq_cancel(&server->connreq);
    if (server->connctx) {
        lcbio_mgr_detach(lcbio_ctx_sock(server->connctx));
    }

    server->pipeline.flush_start = (mcreq_flushstart_fn)server_connect;

    mcserver_errflush(server);
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
    return server->connctx != NULL;
}

static void
timeout_server(lcb_timer_t tm, lcb_t i, const void *arg)
{
    mc_SERVER *server = (void *)arg;
    hrtime_t now, min_valid, next_ns = 0;
    uint32_t next_us = 0;

    (void)tm; (void)i;

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

    lcb_log(LOGARGS(server, INFO), "%p, Scheduling next timeout for %u ms", server, next_us / 1000);

    lcb_timer_rearm(server->io_timer, next_us);
    lcb_maybe_breakout(server->instance);
}

int
mcserver_is_clean(mc_SERVER *server)
{
    return 0;
}

static void
on_connected(lcbio_SOCKET *sock, void *data, lcb_error_t err, lcbio_OSERR syserr)
{
    mc_SERVER *server = data;
    lcbio_EASYPROCS procs;
    LCBIO_CONNREQ_CLEAR(&server->connreq);

    if (err != LCB_SUCCESS) {
        lcb_log(LOGARGS(server, ERR), "Got error for connection! (OS=%d)", syserr);
        mcserver_socket_error(server, err);
        return;
    }

    lcb_assert(sock);

    /** Do we need sasl? */
    if (lcbio_protoctx_get(sock, LCBIO_PROTOCTX_SASL) == NULL) {
        mc_pSASLREQ sreq;
        lcb_log(LOGARGS(server, INFO), "SASL Not yet negotiated. Negotiating");
        sreq = mc_sasl_start(
                sock, server->settings, MCSERVER_TIMEOUT(server),
                on_connected, data);
        LCBIO_CONNREQ_MKGENERIC(&server->connreq, sreq, mc_sasl_cancel);
        return;
    }

    procs.cb_err = on_error;
    procs.cb_read = on_read;
    procs.cb_flush_done = on_flush_done;
    procs.cb_flush_ready = on_flush_ready;
    server->connctx = lcbio_ctx_new(sock, server, &procs);
    server->connctx->subsys = "memcached";
    server->pipeline.flush_start = (mcreq_flushstart_fn)mcserver_flush;
    lcb_log(LOGARGS(server, INFO), "Starting initial flush for server!");
    mcserver_flush(server);
}

static void
server_connect(mc_SERVER *server)
{
    lcbio_pMGRREQ mr;
    mr = lcbio_mgr_get(server->instance->memd_sockpool, &server->curhost,
                       MCSERVER_TIMEOUT(server), on_connected, server);
    LCBIO_CONNREQ_MKPOOLED(&server->connreq, mr);
    server->pipeline.flush_start = flush_noop;
}

static char *
dupstr_or_null(const char *s) {
    if (s) {
        return strdup(s);
    }
    return NULL;
}

mc_SERVER *
mcserver_alloc(lcb_t instance, int ix)
{
    mc_CMDQUEUE *cq = &instance->cmdq;
    mc_SERVER *ret;

    ret = calloc(1, sizeof(*ret));
    if (!ret) {
        return ret;
    }

    ret->instance = instance;
    ret->settings = instance->settings;
    ret->datahost = dupstr_or_null(VB_NODESTR(cq->config, ix));
    ret->resthost = dupstr_or_null(VB_RESTURL(cq->config, ix));
    ret->viewshost = dupstr_or_null(VB_VIEWSURL(cq->config, ix));

    lcb_settings_ref(ret->settings);

    mcreq_pipeline_init(&ret->pipeline);
    ret->pipeline.flush_start = (mcreq_flushstart_fn)server_connect;
    lcb_host_parsez(&ret->curhost, ret->datahost, 11210);

    ret->io_timer = lcb_timer_create_simple(
            instance->iotable, ret, MCSERVER_TIMEOUT(ret), timeout_server);
    lcb_timer_disarm(ret->io_timer);
    return ret;
}


static void
server_free(mc_SERVER *server)
{
    mcreq_pipeline_cleanup(&server->pipeline);

    if (server->io_timer) {
        lcb_timer_destroy(NULL, server->io_timer);
    }

    free(server->resthost);
    free(server->viewshost);
    free(server->datahost);
    lcb_settings_unref(server->settings);
    free(server);
}

static void
close_cb(lcbio_SOCKET *sock, int reusable, void *arg)
{
    if (reusable) {
        reusable = *(int *)arg;
    }
    lcbio_ref(sock);
    if (reusable) {
        lcbio_mgr_put(sock);
    } else {
        /* kill the socket */
        lcbio_mgr_discard(sock);
    }
}

void
mcserver_close(mc_SERVER *server, int isok)
{
    lcbio_CTX *ctx = server->connctx;

    lcb_assert(!server->closed);
    lcbio_connreq_cancel(&server->connreq);

    if (server->io_timer) {
        lcb_timer_destroy(NULL, server->io_timer);
        server->io_timer = NULL;
    }

    if (!ctx) {
        server_free(server);
        return;
    }

    if (ctx->npending == 0) {
        lcb_log(LOGARGS(server, INFO), "Server %p may be closed. No pending events", server);
        lcbio_ctx_close(ctx, close_cb, &isok);
        server_free(server);

    } else {
        lcb_log(LOGARGS(server, WARN), "Server %p still has pending I/O. N=%d, Write=%d, Read=%d", server, ctx->npending, ctx->wwant, ctx->rdwant);
        lcbio_ctx_schedule(ctx);
        lcbio_shutdown(ctx->sock);
        server->closed = 1;
    }
}

/**
 * This little function checks to see if the server struct is still valid, or
 * whether it should just be cleaned once no pending I/O remainds.
 *
 * If this function returns false then the server is still valid; otherwise it
 * is invalid and must not be used further.
 */
static int
check_closed(mc_SERVER *server)
{
    int isok = 0;
    if (!server->closed) {
        return 0;
    }

    lcb_log(LOGARGS(server, INFO), "Server %p got handler after close. Checking pending calls", server);
    if (!server->connctx->npending) {
        lcbio_ctx_close(server->connctx, close_cb, &isok);
        server_free(server);
    }
    return 1;
}
