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
 * This file contains common connection routines for anything that requires
 * an outgoing TCP socket.
 *
 * @author Mark Nunberg
 */

#include "internal.h"
#include "logging.h"

static lcb_connection_result_t v0_connect(lcbconn_t conn, int nocb, short events);
static lcb_connection_result_t v1_connect(lcbconn_t conn, int nocb);
#define LOGARGS(conn, lvl) \
    conn->settings, "connection", LCB_LOG_##lvl, __FILE__, __LINE__
#define LOG(conn, lvl, msg) lcb_log(LOGARGS(conn, lvl), msg)

#define CN_E(conn) (&(conn)->u_model.e)
#define CN_C(conn) (&(conn)->u_model.c)

struct lcb_ioconnect_st {
    /** Timer to use for connection */
    lcb_timer_t timer;
    lcb_connection_handler callback;
    struct addrinfo *ai;
    struct addrinfo *root_ai;
    lcb_error_t pending_err;
};

/**
 * This just wraps the connect routine again
 */
static void v0_reconnect_handler(lcb_socket_t sockfd, short which, void *data)
{
    v0_connect((struct lcb_connection_st *)data, 0, which);
    (void)which;
    (void)sockfd;
}

/**
 * Replaces the entry with the next addrinfo in the list of addrinfos.
 * Returns 0 on success, -1 on failure (i.e. no more AIs left)
 */
static int conn_next_ai(struct lcb_connection_st *conn)
{
    lcb_ioconnect_t ioconn = conn->ioconn;
    if (ioconn->ai == NULL || ioconn->ai->ai_next == NULL) {
        return -1;
    }

    ioconn->ai = ioconn->ai->ai_next;
    return 0;
}

/**
 * Do some basic connection failure handling. Cycles through the addrinfo
 * structures, and closes the socket. Returns 0 if there are more addrinfo
 * structures to try, -1 on error
 */
static int handle_conn_failure(struct lcb_connection_st *conn)
{
    lcb_ioconnect_t ioconn = conn->ioconn;
    conn->ioconn = NULL;

    /** This actually closes ioconn as well, so maintain it here */
    lcbconn_close(conn);
    conn->ioconn = ioconn;

    if (conn_next_ai(conn) == 0) {
        conn->state = LCBCONN_S_PENDING;
        return 0;
    }

    return -1;
}

static void destroy_connstart(lcbconn_t conn)
{
    if (!conn->ioconn) {
        return;
    }


    if (conn->ioconn->timer) {
        lcb_timer_destroy(NULL, conn->ioconn->timer);
    }

    if (conn->ioconn->root_ai) {
        freeaddrinfo(conn->ioconn->root_ai);
    }
    free(conn->ioconn);
    conn->ioconn = NULL;
}

/**
 * Helper function to invoke the completion callback with an error of some
 * sort
 */
static void conn_do_callback(struct lcb_connection_st *conn,
                             int nocb,
                             lcb_error_t err)
{
    lcb_connection_handler handler;
    if (nocb) {
        LOG(conn, DEBUG, "Not invoking event because nocb specified");
        return;
    }

    handler = conn->ioconn->callback;
    lcb_assert(handler != NULL);
    destroy_connstart(conn);
    lcb_sockrw_set_want(conn, 0, 1);
    lcb_sockrw_apply_want(conn);
    handler(conn, err);
}

static void connection_success(lcbconn_t conn)
{
    lcb_log(LOGARGS(conn, INFO),
            "Connection=%p,%s:%s completed succesfully",
            conn, conn->cur_host_->host, conn->cur_host_->port);

    conn->state = LCBCONN_S_CONNECTED;
    conn_do_callback(conn, 0, LCB_SUCCESS);
}

static void timeout_handler(lcb_timer_t tm, lcb_t instance, const void *cookie)
{
    lcbconn_t conn = (lcbconn_t)cookie;

    lcb_log(LOGARGS(conn, ERR),
            "%p: Connection to %s:%s timed out. Last OS Error=%d",
            conn, conn->cur_host_->host, conn->cur_host_->port,
            (int)conn->last_error);

    conn_do_callback(conn, 0, LCB_ETIMEDOUT);
    (void)tm;
    (void)instance;
}

/**
 * IOPS v0 connection routines. This is the standard select()/poll() model.
 * Returns a status indicating whether the connection has been scheduled
 * successfuly or not.
 */
static lcb_connection_result_t v0_connect(struct lcb_connection_st *conn,
                                          int nocb, short events)
{
    int retry;
    int retry_once = 0;
    int save_errno;
    lcb_connect_status_t connstatus;
    lcb_ioconnect_t ioconn = conn->ioconn;
    lcb_iotable *io = conn->iotable;
    lcbio_Ectx *e = CN_E(conn);

    do {
        if (e->sockfd == INVALID_SOCKET) {
            e->sockfd = lcb_gai2sock(io, &ioconn->ai, &save_errno);
        }

        if (ioconn->ai == NULL) {
            conn->last_error = IOT_ERRNO(io);

            lcb_log(LOGARGS(conn, WARN),
                    "%p, %s:%s No more addrinfo structures remaining",
                    (void *)conn,
                    conn->cur_host_->host,
                    conn->cur_host_->port);
            /* this means we're not going to retry!! add an error here! */
            return LCB_CONN_ERROR;
        }

        retry = 0;
        if (events & LCB_ERROR_EVENT) {
            socklen_t errlen = sizeof(int);
            int sockerr = 0;
            getsockopt(e->sockfd,
                       SOL_SOCKET, SO_ERROR, (char *)&sockerr, &errlen);
            conn->last_error = sockerr;

        } else {
            if (IOT_V0IO(io).connect0(IOT_ARG(io),
                                      e->sockfd,
                                      ioconn->ai->ai_addr,
                                      (unsigned int)ioconn->ai->ai_addrlen) == 0) {
                /**
                 * Connected.
                 * XXX: In the odd event that this does connect immediately, we
                 * still enqueue it! - this is because we likely want to invoke some
                 * other callbacks after this, and we can't be sure that it's safe to
                 * do so until the event loop has control. Therefore we actually rely
                 * on EISCONN!.
                 * This isn't a whole lot of overhead as we shouldn't be connecting
                 * too much in the first place
                 */
                if (nocb) {
                    return LCB_CONN_INPROGRESS;

                } else {
                    connection_success(conn);
                    return LCB_CONN_CONNECTED;
                }
            } else {
                conn->last_error = IOT_ERRNO(io);
            }
        }

        connstatus = lcb_connect_status(conn->last_error);
        switch (connstatus) {

        case LCB_CONNECT_EINTR:
            retry = 1;
            break;

        case LCB_CONNECT_EISCONN:
            connection_success(conn);
            return LCB_CONN_CONNECTED;

        case LCB_CONNECT_EINPROGRESS: /*first call to connect*/
            IOT_V0EV(io).watch(IOT_ARG(io),
                               e->sockfd,
                               e->ptr,
                               LCB_WRITE_EVENT,
                               conn, v0_reconnect_handler);
            e->active = 1;

            return LCB_CONN_INPROGRESS;

        case LCB_CONNECT_EALREADY: /* Subsequent calls to connect */
            return LCB_CONN_INPROGRESS;

        case LCB_CONNECT_EINVAL:
            if (!retry_once) {     /* First time get WSAEINVAL error - do retry */
                retry = 1;
                retry_once = 1;
                break;
            } else {               /* Second time get WSAEINVAL error - it is permanent error */
                retry_once = 0;    /* go to LCB_CONNECT_EFAIL brench (no break or return) */
            }

        case LCB_CONNECT_EFAIL:
        default:
            if (handle_conn_failure(conn) == -1) {
                conn_do_callback(conn, nocb, LCB_CONNECT_ERROR);
                return LCB_CONN_ERROR;
            }

            /* Try next AI */
            retry = 1;
            break;
        }
    } while (retry);

    lcb_assert("this statement shouldn't be reached" && 0);
    return LCB_CONN_ERROR;
}

static void v1_connect_handler(lcb_sockdata_t *sockptr, int status)
{
    lcbconn_t conn = (lcbconn_t)sockptr->lcbconn;
    if (!conn) {
        /* closed? */
        return;
    }
    if (status) {
        v1_connect(conn, 0);
    } else {
        connection_success(conn);
    }
}

static lcb_connection_result_t v1_connect(lcbconn_t conn, int nocb)
{
    int save_errno;
    int rv;
    int retry = 1;
    int retry_once = 0;
    lcb_connect_status_t status;
    lcb_iotable *io = conn->iotable;
    lcb_ioconnect_t ioconn = conn->ioconn;
    lcbio_Cctx *c = CN_C(conn);

    do {

        if (!c->sockptr) {
            c->sockptr = lcb_gai2sock_v1(io, &ioconn->ai, &save_errno);
        }

        if (c->sockptr) {
            c->sockptr->lcbconn = conn;
            c->sockptr->parent = io->p;
        } else {
            conn->last_error = IOT_ERRNO(io);
            if (handle_conn_failure(conn) == -1) {
                conn_do_callback(conn, nocb, LCB_CONNECT_ERROR);
                return LCB_CONN_ERROR;
            }
        }

        rv = IOT_V1(io).connect(io->p,
                                c->sockptr,
                                ioconn->ai->ai_addr,
                                (unsigned int)ioconn->ai->ai_addrlen,
                                v1_connect_handler);

        if (rv == 0) {
            return LCB_CONN_INPROGRESS;
        }

        status = lcb_connect_status(IOT_ERRNO(io));
        switch (status) {

        case LCB_CONNECT_EINTR:
            retry = 1;
            break;

        case LCB_CONNECT_EISCONN:
            connection_success(conn);
            return LCB_CONN_CONNECTED;

        case LCB_CONNECT_EALREADY:
        case LCB_CONNECT_EINPROGRESS:
            return LCB_CONN_INPROGRESS;

        case LCB_CONNECT_EINVAL:
            /** TODO: do we still need this for v1? */
            conn->last_error = IOT_ERRNO(io);
            if (!retry_once) {
                retry = 1;
                retry_once = 1;
                break;
            } else {
                retry_once = 0;
            }

        case LCB_CONNECT_EFAIL:
            conn->last_error = IOT_ERRNO(io);
            if (handle_conn_failure(conn) == -1) {
                conn_do_callback(conn, nocb, LCB_CONNECT_ERROR);
                return LCB_CONN_ERROR;
            }
            break;

        default:
            conn->last_error = IOT_ERRNO(io);
            return LCB_CONN_ERROR;

        }
    } while (retry);

    return LCB_CONN_ERROR;
}

static void async_error_callback(lcb_timer_t tm, lcb_t i, const void *cookie)
{
    lcbconn_t conn = (lcbconn_t)cookie;
    conn_do_callback(conn, 0, conn->ioconn->pending_err);
    (void)tm;
    (void)i;
}

static void setup_async_error(lcbconn_t conn, lcb_error_t err)
{
    lcb_ioconnect_t ioconn = conn->ioconn;
    lcb_error_t dummy;

    if (ioconn->timer) {
        lcb_timer_destroy(NULL, ioconn->timer);
    }
    ioconn->pending_err = err;
    ioconn->timer = lcb_async_create(conn->iotable,
                                     conn, async_error_callback, &dummy);
}

lcb_connection_result_t lcbconn_connect(lcbconn_t conn,
                                        const lcbconn_params *params,
                                        lcb_connstart_opts_t options)
{
    lcb_connection_result_t result;
    lcb_iotable *io = conn->iotable;

    /** Basic sanity checking */
    lcb_assert(conn->state == LCBCONN_S_UNINIT);
    lcb_assert(conn->ioconn == NULL);
    lcb_assert(params->destination);
    lcb_assert(params->handler);

    conn->state = LCBCONN_S_PENDING;

    lcb_log(LOGARGS(conn, INFO),
            "Starting connection (%p) to %s:%s", conn,
            params->destination->host,
            params->destination->port);

    conn->ioconn = calloc(1, sizeof(*conn->ioconn));
    conn->ioconn->callback = params->handler;

    if (!conn->cur_host_) {
        conn->cur_host_ = malloc(sizeof(*conn->cur_host_));
    }

    *conn->cur_host_ = *params->destination;

    if (params->timeout) {
        conn->ioconn->timer = lcb_timer_create_simple(io, conn,
                                                      params->timeout,
                                                      timeout_handler);
    }

    lcb_getaddrinfo(conn->settings,
                    params->destination->host,
                    params->destination->port,
                    &conn->ioconn->root_ai);

    if (!conn->ioconn->root_ai) {
        setup_async_error(conn, LCB_UNKNOWN_HOST);
    }

    conn->ioconn->ai = conn->ioconn->root_ai;
    if (IOT_IS_EVENT(io)) {
        if (!CN_E(conn)->ptr) {
            CN_E(conn)->ptr = IOT_V0EV(io).create(io->p);
        }
        result = v0_connect(conn, options & LCB_CONNSTART_NOCB, 0);

    } else {
        result = v1_connect(conn, options & LCB_CONNSTART_NOCB);
    }

    if (result != LCB_CONN_INPROGRESS) {
        lcb_log(LOGARGS(conn, INFO),
                "Scheduling connection for %p failed with code 0x%x",
                conn, result);

        if (options & LCB_CONNSTART_ASYNCERR) {
            setup_async_error(conn, LCB_CONNECT_ERROR);
            return LCB_CONN_INPROGRESS;
        }
    }

    return result;
}

void lcbconn_close(lcbconn_t conn)
{
    lcb_iotable *io;
    conn->state = LCBCONN_S_UNINIT;
    destroy_connstart(conn);
    if (conn->iotable == NULL) {
        return;
    }

    io = conn->iotable;
    if (IOT_IS_EVENT(io)) {
        lcbio_Ectx *e = CN_E(conn);
        if (e->sockfd != INVALID_SOCKET) {
            if (e->ptr) {
                IOT_V0EV(io).cancel(io->p, e->sockfd, e->ptr);
            }
            IOT_V0IO(io).close(io->p, e->sockfd);
            e->sockfd = INVALID_SOCKET;
        }

    } else {
        lcbio_Cctx *c = CN_C(conn);
        if (c->sockptr) {
            c->sockptr->closed = 1;
            c->sockptr->lcbconn = NULL;
            io->u_io.completion.close(io->p, c->sockptr);
            c->sockptr = NULL;
        }
    }

    if (conn->input) {
        ringbuffer_reset(conn->input);
    }

    if (conn->output) {
        ringbuffer_reset(conn->output);
    }
    if (conn->as_err) {
        lcb_async_cancel(conn->as_err);
    }
}

int lcb_getaddrinfo(lcb_settings *settings, const char *hostname,
                    const char *servname, struct addrinfo **res)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    switch (settings->ipv6) {
    case LCB_IPV6_DISABLED:
        hints.ai_family = AF_INET;
        break;
    case LCB_IPV6_ONLY:
        hints.ai_family = AF_INET6;
        break;
    default:
        hints.ai_family = AF_UNSPEC;
    }

    return getaddrinfo(hostname, servname, &hints, res);
}

void lcbconn_cleanup(lcbconn_t conn)
{
    destroy_connstart(conn);

    if (conn->protoctx) {
        conn->protoctx_dtor(conn->protoctx);
    }

    if (conn->input) {
        ringbuffer_destruct(conn->input);
        free(conn->input);
        conn->input = NULL;
    }

    if (conn->output) {
        ringbuffer_destruct(conn->output);
        free(conn->output);
        conn->output = NULL;
    }

    if (conn->as_err) {
        lcb_async_destroy(NULL, conn->as_err);
        conn->as_err = NULL;
    }

    free(conn->cur_host_);
    conn->cur_host_ = NULL;
    lcbconn_close(conn);

    if (conn->iotable && IOT_IS_EVENT(conn->iotable) && CN_E(conn)->ptr) {
        IOT_V0EV(conn->iotable).destroy(conn->iotable->p, CN_E(conn)->ptr);
        CN_E(conn)->ptr = NULL;
    }

    memset(conn, 0, sizeof(*conn));
}

static lcb_error_t reset_buffer(ringbuffer_t **rb, lcb_size_t defsz)
{
    if (*rb) {
        ringbuffer_reset(*rb);
        return LCB_SUCCESS;
    }

    *rb = calloc(1, sizeof(**rb));

    if (*rb == NULL) {
        return LCB_CLIENT_ENOMEM;
    }

    if (!ringbuffer_initialize(*rb, defsz)) {
        return LCB_CLIENT_ENOMEM;
    }

    return LCB_SUCCESS;
}

lcb_error_t lcbconn_reset_bufs(lcbconn_t conn)
{
    if (reset_buffer(&conn->input, conn->settings->rbufsize) != LCB_SUCCESS) {
        return LCB_CLIENT_ENOMEM;
    }
    if (reset_buffer(&conn->output, conn->settings->wbufsize) != LCB_SUCCESS) {
        return LCB_CLIENT_ENOMEM;
    }
    return LCB_SUCCESS;
}


static void async_error_trigger(lcb_timer_t t, lcb_t i, const void *arg)
{
    lcbconn_t conn = (lcbconn_t )arg;
    conn->errcb(conn);
    (void)t; (void)i;
}

lcb_error_t lcbconn_init(lcbconn_t conn,
                                lcb_iotable *iotable,
                                lcb_settings *settings)
{
    conn->iotable = iotable;
    conn->settings = settings;

    if (IOT_IS_EVENT(iotable)) {
        CN_E(conn)->sockfd = INVALID_SOCKET;
    } else {
        CN_C(conn)->sockptr = NULL;
    }

    conn->state = LCBCONN_S_UNINIT;
    conn->as_err = lcb_timer_create_simple(iotable, conn, 0, async_error_trigger);
    lcb_async_cancel(conn->as_err);


    if (LCB_SUCCESS != lcbconn_reset_bufs(conn)) {
        lcbconn_cleanup(conn);
        return LCB_CLIENT_ENOMEM;
    }

    return LCB_SUCCESS;
}

void lcbconn_use(lcbconn_t conn, const struct lcb_io_use_st *use)
{
    struct lcb_io_use_st use_proxy;

    conn->data = use->udata;
    conn->errcb = use->error;

    if (use->easy) {
        conn->easy.read = use->u.easy.read;
        memset(&use_proxy, 0, sizeof(use_proxy));
        lcb__io_wire_easy(&use_proxy);
        use = &use_proxy;
    }

    if (IOT_IS_EVENT(conn->iotable)) {
        CN_E(conn)->handler = use->u.ex.v0_handler;
        lcb_assert(CN_E(conn)->handler);
    } else {
        CN_C(conn)->read = use->u.ex.v1_read;
        CN_C(conn)->write = use->u.ex.v1_write;
        lcb_assert(CN_C(conn)->read);
        lcb_assert(CN_C(conn)->write);
    }

    lcb_assert(conn->errcb);
}

void lcbconn_use_ex(struct lcb_io_use_st *use,
                    void *udata,
                    lcb_event_handler_cb v0_handler,
                    lcb_io_read_cb v1_read,
                    lcb_ioC_write2_callback v1_write,
                    lcb_io_generic_cb error)
{
    lcb_assert(udata != NULL);
    lcb_assert(v0_handler != NULL);
    lcb_assert(v1_read != NULL);
    lcb_assert(v1_write != NULL);
    lcb_assert(error != NULL);

    memset(use, 0, sizeof(*use));
    use->udata = udata;
    use->error = error;

    use->u.ex.v0_handler = v0_handler;
    use->u.ex.v1_read = v1_read;
    use->u.ex.v1_write = v1_write;
}

void lcbconn_use_easy(struct lcb_io_use_st *use,
                      void *data,
                      lcb_io_generic_cb read_cb,
                      lcb_io_generic_cb err_cb)
{
    lcb_assert(data != NULL);
    lcb_assert(read_cb != NULL);
    lcb_assert(err_cb != NULL);

    use->easy = 1;
    use->u.easy.read = read_cb;
    use->error = err_cb;
    use->udata = data;
}

LCB_INTERNAL_API
void lcbconn_transfer(lcbconn_t from, lcbconn_t to,
                      const struct lcb_io_use_st *use)
{
    lcbio_Ectx *esrc = CN_E(from), *edst = CN_E(to);
    lcbio_Cctx *csrc = CN_C(from), *cdst = CN_C(to);

    if (from == to) {
        return;
    }

    lcb_assert(to->state == LCBCONN_S_UNINIT);
    lcb_assert(to->ioconn == NULL && from->ioconn == NULL);
    if (IOT_IS_EVENT(from->iotable) && esrc->active) {
        IOT_V0EV(from->iotable).cancel(from->iotable->p,
                                       esrc->sockfd, esrc->ptr);
        esrc->active = 0;
    }

    to->iotable = from->iotable;
    to->settings = from->settings;

    if (IOT_IS_EVENT(from->iotable)) {
        edst->ptr = esrc->ptr; esrc->ptr = NULL;
        edst->sockfd = esrc->sockfd; esrc->sockfd = INVALID_SOCKET;
    } else {
        cdst->sockptr = csrc->sockptr; csrc->sockptr = NULL;
        if (cdst->sockptr) {
            cdst->sockptr->lcbconn = to;
        }
    }

    to->protoctx = from->protoctx; from->protoctx = NULL;
    to->protoctx_dtor = from->protoctx_dtor; from->protoctx_dtor = NULL;
    to->last_error = from->last_error;
    to->state = from->state; from->state = LCBCONN_S_UNINIT;
    to->cur_host_ = from->cur_host_; from->cur_host_ = NULL;
    to->poolinfo = from->poolinfo; from->poolinfo = NULL;
    lcbconn_use(to, use);
}

const lcb_host_t * lcbconn_get_host(const lcbconn_t conn)
{
    static lcb_host_t dummy = { { '\0' }, { '\0' } };
    if (conn->cur_host_) {
        return conn->cur_host_;
    } else {
        return &dummy;
    }
}
