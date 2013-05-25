/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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

/**
 * This file contains routines for reading and writing data from and to a
 * socket
 * @author Mark Nunberg
 */

#include "internal.h"

lcb_sockrw_status_t lcb_sockrw_read(lcb_connection_t conn, ringbuffer_t *buf)
{
    struct lcb_iovec_st iov[2];
    lcb_ssize_t nr;

    if (!ringbuffer_ensure_capacity(buf, 8192)) {
        lcb_error_handler(conn->instance, LCB_CLIENT_ENOMEM, NULL);
        return LCB_SOCKRW_GENERIC_ERROR;
    }

    ringbuffer_get_iov(buf, RINGBUFFER_WRITE, iov);

    nr = conn->instance->io->v.v0.recvv(conn->instance->io, conn->sockfd, iov, 2);
    if (nr == -1) {
        switch (conn->instance->io->v.v0.error) {
        case EINTR:
            break;
        case EWOULDBLOCK:
#ifdef USE_EAGAIN
        case EAGAIN:
#endif
            return LCB_SOCKRW_WOULDBLOCK;
        default:
            return LCB_SOCKRW_IO_ERROR;
            return -1;
        }

    } else if (nr == 0) {
        assert((iov[0].iov_len + iov[1].iov_len) != 0);
        /* TODO stash error message somewhere
         * "Connection closed... we should resend to other nodes or reconnect!!" */
        return LCB_SOCKRW_IO_ERROR;

    } else {
        ringbuffer_produced(buf, (lcb_size_t)nr);
    }

    return LCB_SOCKRW_READ;
}

lcb_sockrw_status_t lcb_sockrw_slurp(lcb_connection_t conn, ringbuffer_t *buf)
{
    lcb_sockrw_status_t status;
    while ((status = lcb_sockrw_read(conn, buf)) == LCB_SOCKRW_READ) {
        ;
    }
    return status;

}


lcb_sockrw_status_t lcb_sockrw_write(lcb_connection_t conn,
                                        ringbuffer_t *buf)
{
    while (buf->nbytes > 0) {
        struct lcb_iovec_st iov[2];
        lcb_ssize_t nw;
        ringbuffer_get_iov(buf, RINGBUFFER_READ, iov);
        nw = conn->instance->io->v.v0.sendv(conn->instance->io, conn->sockfd, iov, 2);
        if (nw == -1) {
            switch (conn->instance->io->v.v0.error) {
            case EINTR:
                /* retry */
                break;
            case EWOULDBLOCK:
#ifdef USE_EAGAIN
            case EAGAIN:
#endif
                return LCB_SOCKRW_WOULDBLOCK;

            default:
                return LCB_SOCKRW_IO_ERROR;
            }
        } else if (nw > 0) {
            ringbuffer_consumed(buf, (lcb_size_t)nw);
        }
    }

    return LCB_SOCKRW_WROTE;
}

void lcb_sockrw_set_want(lcb_connection_t conn, short events, int clear_existing)
{

    if (clear_existing) {
        conn->want = events;
    } else {
        conn->want |= events;
    }
}

void lcb_sockrw_apply_want(lcb_connection_t conn)
{
    lcb_io_opt_t io = conn->instance->io;

    if (!conn->want) {
        if (conn->evinfo.active) {
            conn->evinfo.active = 0;
            io->v.v0.delete_event(io, conn->sockfd, conn->evinfo.ptr);
        }
        return;
    }

    conn->evinfo.active = 1;
    io->v.v0.update_event(io,
                          conn->sockfd,
                          conn->evinfo.ptr,
                          conn->want,
                          conn->data,
                          conn->evinfo.handler);
}

int lcb_sockrw_flushed(lcb_connection_t conn)
{
    if (conn->output && conn->output->nbytes == 0) {
        return 1;
    }
    return 0;
}
