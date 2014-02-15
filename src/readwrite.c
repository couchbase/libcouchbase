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
#include "iotable.h"

lcb_sockrw_status_t lcb_sockrw_v0_read(lcb_connection_t conn, ringbuffer_t *buf)
{
    struct lcb_iovec_st iov[2];
    lcb_ssize_t nr;
    lcb_iotable *iot = conn->iotable;

    if (!ringbuffer_ensure_capacity(buf,
                                    conn->settings ? conn->settings->rbufsize :
                                    LCB_DEFAULT_RBUFSIZE)) {
        return LCB_SOCKRW_GENERIC_ERROR;
    }

    ringbuffer_get_iov(buf, RINGBUFFER_WRITE, iov);
    nr = IOT_V0IO(iot).recvv(IOT_ARG(iot), conn->sockfd, iov, 2);
    if (nr == -1) {
        switch (IOT_ERRNO(iot)) {
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
        lcb_assert((iov[0].iov_len + iov[1].iov_len) != 0);
        /* TODO stash error message somewhere
         * "Connection closed... we should resend to other nodes or reconnect!!" */
        return LCB_SOCKRW_SHUTDOWN;

    } else {
        ringbuffer_produced(buf, (lcb_size_t)nr);
    }

    return LCB_SOCKRW_READ;
}

lcb_sockrw_status_t lcb_sockrw_v0_slurp(lcb_connection_t conn, ringbuffer_t *buf)
{
    lcb_sockrw_status_t status;
    while ((status = lcb_sockrw_v0_read(conn, buf)) == LCB_SOCKRW_READ) {
        ;
    }
    return status;

}


lcb_sockrw_status_t lcb_sockrw_v0_write(lcb_connection_t conn,
                                        ringbuffer_t *buf)
{
    lcb_iotable *iot = conn->iotable;

    while (buf->nbytes > 0) {
        struct lcb_iovec_st iov[2];
        lcb_ssize_t nw;
        ringbuffer_get_iov(buf, RINGBUFFER_READ, iov);
        nw = IOT_V0IO(iot).sendv(IOT_ARG(iot), conn->sockfd, iov, 2);
        if (nw == -1) {
            switch (IOT_ERRNO(iot)) {
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

static void apply_want_v0(lcb_connection_t conn)
{
    lcb_iotable *iot = conn->iotable;

    if (!conn->want) {
        if (conn->evinfo.active) {
            conn->evinfo.active = 0;
            IOT_V0EV(iot).cancel(IOT_ARG(iot), conn->sockfd, conn->evinfo.ptr);
        }
        return;
    }

    conn->evinfo.active = 1;
    IOT_V0EV(iot).watch(IOT_ARG(iot),
                        conn->sockfd,
                        conn->evinfo.ptr,
                        conn->want,
                        conn,
                        conn->evinfo.handler);
}

static void apply_want_v1(lcb_connection_t conn)
{
    if (!conn->want) {
        return;
    }
    if (!conn->sockptr) {
        return;
    }
    if (conn->sockptr->closed) {
        return;
    }

    if (conn->want & LCB_READ_EVENT) {
        lcb_sockrw_v1_start_read(conn, &conn->input, conn->completion.read);
    }

    if (conn->want & LCB_WRITE_EVENT) {

        if (conn->output == NULL || conn->output->nbytes == 0) {
            return;
        }

        lcb_sockrw_v1_start_write(conn, &conn->output, conn->completion.write);
    }

}

void lcb_sockrw_apply_want(lcb_connection_t conn)
{
    if (conn->iotable == NULL) {
        return;
    }
    if (IOT_IS_EVENT(conn->iotable)) {
        apply_want_v0(conn);
    } else {
        apply_want_v1(conn);
    }
}

int lcb_sockrw_flushed(lcb_connection_t conn)
{
    if (!IOT_IS_EVENT(conn->iotable)) {
        if (conn->output && conn->output->nbytes == 0) {
            return 1;
        } else {
            return 0;
        }
    } else {
        if (conn->output && conn->output->nbytes == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * Request a read of data into the buffer
 * @param conn the connection object
 * @param buf a ringbuffer structure. If the read request is successful,
 * the ringbuffer is destroyed. Its allocated data is owned by the IO plugin
 * for the duration of the operation. It may be restored via
 * ringbuffer_take_buffer once the operation has finished.
 */
lcb_sockrw_status_t lcb_sockrw_v1_start_read(lcb_connection_t conn,
                                             ringbuffer_t **buf,
                                             lcb_io_read_cb callback)
{
    int ret;
    lcb_iotable *io;
    struct lcb_buf_info *bi = &conn->sockptr->read_buffer;

    if (conn->sockptr->is_reading) {
        return LCB_SOCKRW_PENDING;
    }

    ringbuffer_ensure_capacity(*buf,
                               conn->settings ? conn->settings->rbufsize :
                               LCB_DEFAULT_RBUFSIZE);
    ringbuffer_get_iov(*buf, RINGBUFFER_WRITE, bi->iov);

    lcb_assert(bi->ringbuffer == NULL);
    lcb_assert(bi->root == NULL);

    bi->ringbuffer = *buf;
    bi->root = bi->ringbuffer->root;

    *buf = NULL;


    io = conn->iotable;
    ret = IOT_V1(io).read(IOT_ARG(io), conn->sockptr, callback);

    if (ret == 0) {
        conn->sockptr->is_reading = 1;
        return LCB_SOCKRW_PENDING;

    } else {
        *buf = bi->ringbuffer;
        memset(bi, 0, sizeof(*bi));
        lcb_async_signal(conn->as_err);
    }

    return LCB_SOCKRW_IO_ERROR;
}

/**
 * Request that a write begin.
 * @param conn the connection object
 * @param buf a pointer to a ringbuffer_t*. If the write request is successful,
 * the IO system takes exclusive ownership of the buffer, and the contents
 * of *buf are zeroed.
 */
lcb_sockrw_status_t lcb_sockrw_v1_start_write(lcb_connection_t conn,
                                              ringbuffer_t **buf,
                                              lcb_ioC_write2_callback callback)
{
    int ret;
    lcb_iotable *io;
    struct lcb_iovec_st iov[2];
    ringbuffer_t *rb = *buf;
    io = conn->iotable;
    *buf = NULL;

    ringbuffer_get_iov(rb, RINGBUFFER_READ, iov);
    ret = IOT_V1(io).write2(IOT_ARG(io), conn->sockptr, iov, 2, rb, callback);
    if (ret == 0) {
        return LCB_SOCKRW_PENDING;

    } else {
        lcb_async_signal(conn->as_err);
        return LCB_SOCKRW_IO_ERROR;
    }
}

void lcb_sockrw_v1_onread_common(lcb_sockdata_t *sock,
                                 ringbuffer_t **dst,
                                 lcb_ssize_t nr)
{
    struct lcb_buf_info *bi = &sock->read_buffer;

    lcb_assert(*dst == NULL);

    *dst = bi->ringbuffer;
    memset(bi, 0, sizeof(*bi));

    sock->is_reading = 0;

    if (nr > 0) {
        ringbuffer_produced(*dst, nr);
    }

}

void lcb_sockrw_v1_onwrite_common(lcb_sockdata_t *sock, void *arg,
                                  ringbuffer_t **dst)
{
    ringbuffer_t *orig = arg;
    if (*dst) {
        ringbuffer_destruct(orig);
        free(orig);
        return;
    }

    *dst = orig;
    ringbuffer_reset(*dst);
    (void)sock;
}


unsigned int lcb_sockrw_v1_cb_common(lcb_sockdata_t *sock,
                                     void *wdata,
                                     void **datap)
{
    int is_closed;

    lcb_connection_t conn = sock->lcbconn;
    is_closed = sock->closed;

    if (is_closed) {
        if (wdata) {
            ringbuffer_t *orig = wdata;
            ringbuffer_destruct(orig);
            free(orig);
        }
        return 0;
    }

    if (datap && conn) {
        *datap = conn->data;
    }

    return 1;
}

static void v0_generic_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_connection_t conn = arg;
    lcb_sockrw_status_t status;
    lcb_size_t oldnr, newnr;

    lcb_assert(sock != INVALID_SOCKET);

    if (which & LCB_WRITE_EVENT) {
        status = lcb_sockrw_v0_write(conn, conn->output);
        if (status == LCB_SOCKRW_WROTE) {
            if ((which & LCB_READ_EVENT) == 0) {
                lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
                lcb_sockrw_apply_want(conn);
            }

        } else if (status == LCB_SOCKRW_WOULDBLOCK) {
            lcb_sockrw_set_want(conn, LCB_WRITE_EVENT, 0);
            lcb_sockrw_apply_want(conn);

        } else {
            conn->errcb(conn);
            return;
        }
    }

    if ( (which & LCB_READ_EVENT) == 0) {
        return;
    }

    oldnr = conn->input->nbytes;
    status = lcb_sockrw_v0_slurp(conn, conn->input);
    newnr = conn->input->nbytes;

    if (status != LCB_SOCKRW_READ &&
            status != LCB_SOCKRW_WOULDBLOCK && oldnr == newnr) {

        conn->errcb(conn);
    } else {
        conn->easy.read(conn);
    }
}

static void v1_generic_write_handler(lcb_sockdata_t *sd,
                                     int status,
                                     void *wdata)
{
    lcb_t instance;
    lcb_connection_t conn = sd->lcbconn;

    if (!lcb_sockrw_v1_cb_common(sd, wdata, (void **)&instance)) {
        return;
    }

    lcb_sockrw_v1_onwrite_common(sd, wdata, &sd->lcbconn->output);

    if (status) {
        conn->errcb(conn);
    } else {
        lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
        lcb_sockrw_apply_want(conn);
    }
}

static void v1_generic_read_handler(lcb_sockdata_t *sd, lcb_ssize_t nr)
{
    lcb_connection_t conn = sd->lcbconn;
    if (!lcb_sockrw_v1_cb_common(sd, NULL, NULL)) {
        return;
    }

    lcb_sockrw_v1_onread_common(sd, &sd->lcbconn->input, nr);
    if (nr < 1) {
        conn->errcb(conn);
        return;

    } else {
        conn->easy.read(conn);
    }
}

void lcb__io_wire_easy(struct lcb_io_use_st *use)
{
    use->easy = 0;
    use->u.ex.v0_handler = v0_generic_handler;
    use->u.ex.v1_read = v1_generic_read_handler;
    use->u.ex.v1_write = v1_generic_write_handler;
}
