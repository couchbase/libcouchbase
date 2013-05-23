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
static lcb_connection_result_t v0_connect(lcb_connection_t conn, int nocb);

/**
 * This just wraps the connect routine again
 */
static void v0_reconnect_handler(lcb_socket_t sockfd, short which, void *data)
{
    v0_connect((struct lcb_connection_st*)data, 0);
    (void)which;
    (void)sockfd;
}

/**
 * Replaces the entry with the next addrinfo in the list of addrinfos.
 * Returns 0 on success, -1 on failure (i.e. no more AIs left)
 */
static int conn_next_ai(struct lcb_connection_st *conn)
{
    if (conn->curr_ai == NULL || conn->curr_ai->ai_next == NULL) {
        return -1;
    }
    conn->curr_ai = conn->curr_ai->ai_next;
    return 0;
}

/**
 * Do some basic connection failure handling. Cycles through the addrinfo
 * structures, and closes the socket. Returns 0 if there are more addrinfo
 * structures to try, -1 on error
 */
static int conn_failed(struct lcb_connection_st *conn)
{
    if (conn_next_ai(conn) == 0) {
        lcb_connection_close(conn);
        return 0;
    }
    return -1;
}

/**
 * Helper function to invoke the completion callback with an error of some
 * sort
 */
static void conn_do_callback(struct lcb_connection_st *conn,
                             int nocb,
                             lcb_error_t err)
{
    if (nocb) {
        return;
    }
    lcb_connection_handler handler = conn->on_connect_complete;
    if (!handler) {
        return;
    }
    conn->on_connect_complete = NULL;
    handler(conn, err);
}

static void connection_success(lcb_connection_t conn)
{
    lcb_connection_delete_timer(conn);
    conn->connected = 1;
    conn_do_callback(conn, 0, LCB_SUCCESS);
}

/**
 * This is called when we still 'own' the timer. This dispatches
 * to the generic timeout handler
 */
static void initial_connect_timeout_handler(lcb_socket_t sock,
                                            short which,
                                            void *arg)
{
    lcb_connection_t conn = (lcb_connection_t)arg;
    lcb_connection_close(conn);
    lcb_connection_delete_timer(conn);
    conn_do_callback(conn, 0, LCB_ETIMEDOUT);
    (void)which;
    (void)sock;
}

/**
 * This is called for the user-defined timeout handler
 */
static void timeout_handler_dispatch(lcb_socket_t sock,
                                     short which,
                                     void *arg)
{
    lcb_connection_t conn = (lcb_connection_t)arg;
    lcb_connection_delete_timer(conn);
    if (conn->on_timeout) {
        lcb_connection_handler handler = conn->on_timeout;
        conn->on_timeout = NULL;
        handler(conn, LCB_ETIMEDOUT);
    }

    (void)which;
    (void)sock;
}

/**
 * IOPS v0 connection routines. This is the standard select()/poll() model.
 * Returns a status indicating whether the connection has been scheduled
 * successfuly or not.
 */
static lcb_connection_result_t v0_connect(struct lcb_connection_st *conn,
                                          int nocb)
{
    int retry;
    int retry_once = 0;
    int save_errno;
    lcb_connect_status_t connstatus;

    struct lcb_io_opt_st *io = conn->instance->io;

    do {
        if (conn->sockfd == INVALID_SOCKET) {
            conn->sockfd = lcb_gai2sock(conn->instance,
                                        &conn->curr_ai,
                                        &save_errno);
        }

        if (conn->curr_ai == NULL) {
            /*TODO: Maybe check save_errno now? */

            /* this means we're not going to retry!! add an error here! */
            return LCB_CONN_ERROR;
        }

        retry = 0;
        if (io->v.v0.connect(io,
                             conn->sockfd,
                             conn->curr_ai->ai_addr,
                             (unsigned int)conn->curr_ai->ai_addrlen) == 0) {
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
        }

        connstatus = lcb_connect_status(io->v.v0.error);
        switch (connstatus) {

        case LCB_CONNECT_EINTR:
            retry = 1;
            break;

        case LCB_CONNECT_EISCONN:
            connection_success(conn);
            return LCB_CONN_CONNECTED;

        case LCB_CONNECT_EINPROGRESS: /*first call to connect*/
            io->v.v0.update_event(io,
                                  conn->sockfd,
                                  conn->event,
                                  LCB_WRITE_EVENT,
                                  conn, v0_reconnect_handler);
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
            if (conn_failed(conn) == -1) {
                conn_do_callback(conn, nocb, LCB_CONNECT_ERROR);
                return LCB_CONN_ERROR;
            }

            /* Try next AI */
            break;

        }
    } while (retry);

    /* not reached */
    abort();
    return LCB_CONN_ERROR;;
}

lcb_connection_result_t lcb_connection_start(lcb_connection_t conn,
                                             int nocb,
                                             lcb_uint32_t timeout)
{
    lcb_connection_result_t result;
    if (!conn->event) {
        conn->event = conn->instance->io->v.v0.create_event(conn->instance->io);
    }

    result = v0_connect(conn, nocb);

    if (result == LCB_CONN_INPROGRESS && timeout > 0) {
        if (!conn->timer) {
            conn->timer = conn->instance->io->v.v0.create_timer(conn->instance->io);

        } else {
            lcb_connection_delete_timer(conn);
        }
        conn->instance->io->v.v0.update_timer(conn->instance->io,
                                              conn->timer,
                                              timeout,
                                              conn,
                                              initial_connect_timeout_handler);
        conn->timeout_active = 1;
    }

    return result;
}

void lcb_connection_close(lcb_connection_t conn)
{
    lcb_io_opt_t io = conn->instance->io;
    if (conn->sockfd != INVALID_SOCKET) {
        if (conn->event) {
            io->v.v0.delete_event(io, conn->sockfd, conn->event);
        }
        io->v.v0.close(io, conn->sockfd);
        conn->sockfd = INVALID_SOCKET;
    }

    if (conn->input) {
        ringbuffer_reset(conn->input);
    }

    if (conn->output) {
        ringbuffer_reset(conn->output);
    }
}

int lcb_getaddrinfo(lcb_t instance, const char *hostname,
                    const char *servname, struct addrinfo **res)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    switch (instance->ipv6) {
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


int lcb_connection_getaddrinfo(lcb_connection_t conn, int refresh)
{
    int ret;
    if (conn->ai && refresh) {
        freeaddrinfo(conn->ai);
    }

    conn->ai = NULL;
    conn->curr_ai = NULL;

    ret = lcb_getaddrinfo(conn->instance,
                          conn->host,
                          conn->port,
                          &conn->ai);
    if (ret == 0) {
        conn->curr_ai = conn->ai;
    }
    return ret;
}

void lcb_connection_cleanup(lcb_connection_t conn)
{
    if (conn->ai) {
        freeaddrinfo(conn->ai);
        conn->ai = NULL;
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


    lcb_connection_close(conn);

    if (conn->event) {
        conn->instance->io->v.v0.destroy_event(conn->instance->io,
                                               conn->event);
        conn->event = NULL;
    }

    lcb_connection_delete_timer(conn);

    if (conn->timer) {
        conn->instance->io->v.v0.destroy_timer(conn->instance->io,
                                               conn->timer);
        conn->timer = NULL;
    }
    memset(conn, 0, sizeof(*conn));
}

void lcb_connection_delete_timer(lcb_connection_t conn)
{
    if (conn->timer != NULL && conn->timeout_active != 0) {
        conn->instance->io->v.v0.delete_timer(conn->instance->io, conn->timer);
        conn->timeout_active = 0;
    }
}

void lcb_connection_update_timer(lcb_connection_t conn,
                                 lcb_uint32_t usec,
                                 lcb_connection_handler handler)
{
    lcb_connection_delete_timer(conn);
    if (!conn->timer) {
        conn->timer = conn->instance->io->v.v0.create_timer(conn->instance->io);
    }

    conn->timeout_active = 1;
    conn->on_timeout = handler;
    conn->instance->io->v.v0.update_timer(conn->instance->io,
                                          conn->timer,
                                          usec,
                                          conn,
                                          timeout_handler_dispatch);
}

lcb_error_t lcb_connection_init(lcb_connection_t conn, lcb_t instance)
{
    conn->instance = instance;
    if (!conn->input) {
        conn->input = calloc(1, sizeof(*conn->input));
    }

    if (!conn->output) {
        conn->output = calloc(1, sizeof(*conn->output));
    }

    conn->sockfd = INVALID_SOCKET;

    if (conn->input == NULL || conn->output == NULL) {
        lcb_connection_cleanup(conn);
        return LCB_CLIENT_ENOMEM;
    }
    if (ringbuffer_initialize(conn->input, 8092) == 0 ||
            ringbuffer_initialize(conn->output, 8092) == 0) {
        lcb_connection_cleanup(conn);
        return LCB_CLIENT_ENOMEM;
    }

    return LCB_SUCCESS;
}
