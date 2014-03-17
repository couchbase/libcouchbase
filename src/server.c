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

#include "bucketconfig/clconfig.h"
#include "mc/mcreq-flush-inl.h"

#define LOGARGS(c, lvl) \
    &(c)->instance->settings, "server", LCB_LOG_##lvl, __FILE__, __LINE__
#define LOG(c, lvl, msg) lcb_log(LOGARGS(c, lvl), msg)

#define MCREQ_MAXIOV 32
#define LCBCONN_UNWANT(conn, flags) (conn)->want &= ~(flags)

/**
 * Called immediately from the flush_start handler on a connected socket.
 * This will try to flush to the socket until we either don't have any more
 * data to send or we get an EWOULDBLOCK.
 *
 * Only applicable on "Event"-style I/O backends
 */
static void
do_Eflush(lcb_server_t *server)
{
    mc_PIPELINE *pl = &server->pipeline;
    lcbconn_t conn = &server->connection;
    lcb_iotable *iot = conn->iotable;
    nb_IOV iov[MCREQ_MAXIOV];
    nb_SIZE toflush;
    int niov;
    int fd = conn->u_model.e.sockfd;

    while ((toflush = mcreq_flush_iov_fill(pl, iov, MCREQ_MAXIOV, &niov))) {
        lcb_ssize_t nw;
        nw = IOT_V0IO(iot).sendv(
                IOT_ARG(iot), fd, (struct lcb_iovec_st *)iov, niov);

        /** Handle the errors.. */
        if (nw > 0) {
            mcreq_flush_done(pl, nw, toflush);
            if (nw == toflush && niov < MCREQ_MAXIOV) {
                LCBCONN_UNWANT(conn, LCB_WRITE_EVENT);
                break;
            }

        } else if (nw == -1) {
            switch (IOT_ERRNO(iot)) {
            case EWOULDBLOCK:
            #ifdef USE_EAGAIN
            case EAGAIN:
            #endif
                mcreq_flush_done(pl, 0, toflush);
                lcbconn_set_want(conn, LCB_WRITE_EVENT, 0);
                goto GT_SCHEDNEXT;

            case EINTR:
                continue;

            default:
                /**
                 * XXX:
                 * For error handling with event models on flush, the data
                 * is considered already to be flushed _immediately_. We rely
                 * on the assumption that an error here will lead to an error
                 * on subsequent flushes and so on.
                 */
                mcreq_flush_done(pl, toflush, toflush);
                lcbconn_senderr(conn, conn->last_error);
                return;
            }
        } else {
            LCBCONN_UNWANT(conn, LCB_WRITE_EVENT);
            break;
        }
    }

    GT_SCHEDNEXT:
    if (toflush == 0) {
        LCBCONN_UNWANT(conn, LCB_WRITE_EVENT);
    }

    conn->want |= LCB_READ_EVENT;
    if (!server->entered) {
        lcbconn_apply_want(conn);
    }
}

/**
 * Write callback for the write invoked by do_Cflush. This callback decrements
 * the flush count and invokes the 'flush_done' from mcreq
 */
static void
handle_Cwr(lcb_sockdata_t *sd, int status, void *wdata)
{
    lcb_server_t *server = sd->lcbconn->data;
    lcb_size_t nw = (uintptr_t)wdata;
    server->nwpending--;

    mcreq_flush_done(&server->pipeline, nw, nw);
    if (server->cflush_errsize) {
        mcreq_flush_done(&server->pipeline,
                         server->cflush_errsize, server->cflush_errsize);
        server->cflush_errsize = 0;
    }

    /**
     * Complain about a socket error only if the server did not already
     * acquire a new socket.
     */

    if (status && sd == server->connection.u_model.c.sockptr) {
        mcserver_socket_error(server, status);
    }

    mcserver_decref(server, status == 0);
}

/**
 * Starts flushing data for Completion-style I/O backends. This sends multiple
 * write requests if more IOVs are needed than are statically allocated for.
 */
static void
do_Cflush(lcb_server_t *server)
{
    nb_SIZE toflush;
    mc_PIPELINE *pl = &server->pipeline;
    lcbconn_t conn = &server->connection;
    lcb_iotable *iot = conn->iotable;
    lcbio_Cctx *c = &conn->u_model.c;
    nb_IOV iov[MCREQ_MAXIOV];
    int niov;

    while ((toflush = mcreq_flush_iov_fill(pl, iov, MCREQ_MAXIOV, &niov))) {
        int status = IOT_V1(iot).write2(
                IOT_ARG(iot), c->sockptr, (struct lcb_iovec_st *)iov, niov,
                (void *)(uintptr_t)toflush, handle_Cwr);

        if (status) {
            /**
             * If we get an error here, we can't just immediately call
             * flush_done because there may be prior flushes that are awaiting
             * completion. If so, we increase a counter indicating the next
             * flush size to use.
             */
            if (server->nwpending) {
                server->cflush_errsize += toflush;
            } else {
                /**
                 * No pending flushes, and therefore we will never get another
                 * flush callback
                 */
                mcreq_flush_done(pl, toflush, toflush);
            }
            lcbconn_senderr(conn, LCB_NETWORK_ERROR);
            break;
        }
        server->refcount++;
        server->nwpending++;
    }

    if (c->sockptr->is_reading == 0 && server->entered == 0) {
        conn->want = LCB_READ_EVENT;
        lcbconn_apply_want(conn);
    }
}

void
mcserver_flush(mc_SERVER *server)
{
    lcb_assert(!MCCONN_IS_NEGOTIATING(&server->connection));
    if (IOT_IS_EVENT(server->connection.iotable)) {
        do_Eflush(server);
        lcbconn_apply_want(&server->connection);
    } else {
        do_Cflush(server);
    }

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

    if (server->nwpending) {
        return;
    }

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
    if (!instance->settings.vb_noguess) {
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

static lcb_error_t
parse_packet(lcb_server_t *server)
{
    lcbconn_t conn = &server->connection;

    packet_info info;
    while (1) {
        int rv;
        rv = lcb_packet_read_ringbuffer(&info, conn->input);

        if (rv == -1) {
            return LCB_PROTOCOL_ERROR;

        } else if (rv == 0) {
            return LCB_SUCCESS;
        }

        handle_single_packet(server, &info);
        lcb_packet_release_ringbuffer(&info, conn->input);
    }
    return LCB_SUCCESS;
}

#define HANDLER_MAXTIME LCB_US2NS(5000)
static void
handler_E(lcb_socket_t sock, short which, void *arg)
{
    lcbconn_t conn = arg;
    lcb_server_t *server = conn->data;
    hrtime_t now = gethrtime();

    server->entered++;

    if (which & LCB_READ_EVENT) {
        lcbio_status_t status;
        lcb_error_t err = LCB_SUCCESS;
        do {
            status = lcbconn_Erb_read(conn);
            err = parse_packet(server);
        } while (status == LCBIO_STATUS_CANREAD && err == LCB_SUCCESS &&
                now - gethrtime() < HANDLER_MAXTIME);

        if (!LCBIO_IS_OK(status) || err != LCB_SUCCESS) {
            mcserver_socket_error(server, LCB_NETWORK_ERROR);
            server->entered--;
            return;
        }

        if (!SLLIST_IS_EMPTY(&server->pipeline.requests)) {
            conn->want |= LCB_READ_EVENT;
        } else {
            conn->want &= ~LCB_READ_EVENT;
        }
    }

    if ((which & LCB_WRITE_EVENT) || (conn->want & LCB_WRITE_EVENT)) {
        do_Eflush(server);
    }

    server->entered--;
    lcbconn_apply_want(conn);
    lcb_maybe_breakout(server->instance);
    (void)sock;
}

static void
handle_Crd(lcb_sockdata_t *sd, lcb_ssize_t nr)
{
    lcb_error_t err;
    lcb_server_t *server;

    if (!lcbconn_Crb_enter(sd, LCB_READ_EVENT, nr, NULL, (void **)&server)) {
        return;
    }

    server->entered++;

    if (nr > 0) {
        err = parse_packet(server);
    } else {
        err = LCB_NETWORK_ERROR;
    }

    if (err != LCB_SUCCESS) {
        mcserver_socket_error(server, err);
        server->entered--;
        return;
    }

    server->entered--;

    lcbconn_apply_want(sd->lcbconn);
    lcb_maybe_breakout(server->instance);
}

static void
handle_CEerr(lcbconn_t conn)
{
    mc_SERVER *server = conn->data;
    mcserver_socket_error(server, LCB_NETWORK_ERROR);
}

void
mcserver_wire_io(mc_SERVER *server, lcbconn_t src)
{
    struct lcb_io_use_st use;
    lcbconn_use_ex(&use, server, handler_E, handle_Crd, handle_Cwr, handle_CEerr);

    if (src) {
        lcbconn_transfer(src, &server->connection, &use);
    } else {
        lcbconn_use(&server->connection, &use);
    }

    lcbconn_reset_bufs(&server->connection);
}

int
mcserver_has_pending(mc_SERVER *server)
{
    return !SLLIST_IS_EMPTY(&server->pipeline.requests);
}
