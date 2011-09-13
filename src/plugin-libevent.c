/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc.
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
 * This file contains IO operations that use libevent
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"

#include <libcouchbase/libevent_io_opts.h>
#include <event.h>

static ssize_t libcouchbase_io_recv(struct libcouchbase_io_opt_st *iops,
                                    libcouchbase_socket_t sock,
                                    void *buffer,
                                    size_t len,
                                    int flags)
{
    ssize_t ret = recv(sock, buffer, len, flags);
    if (ret < 0) {
        iops->error = errno;
    }
    return ret;
}

static ssize_t libcouchbase_io_send(struct libcouchbase_io_opt_st *iops,
                                    libcouchbase_socket_t sock,
                                    const void *msg,
                                    size_t len,
                                    int flags)
{
    ssize_t ret = send(sock, msg, len, flags);
    if (ret < 0) {
        iops->error = errno;
    }
    return ret;
}

static libcouchbase_socket_t libcouchbase_io_socket(struct libcouchbase_io_opt_st *iops,
                                                    int domain,
                                                    int type,
                                                    int protocol)
{
    libcouchbase_socket_t sock = socket(domain, type, protocol);
    if (sock == INVALID_SOCKET) {
        iops->error = errno;
    } else {
        if (evutil_make_socket_nonblocking(sock) != 0) {
            int error = errno;
            iops->close(iops, sock);
            iops->error = error;
            sock = INVALID_SOCKET;
        }
    }

    return sock;
}

static void libcouchbase_io_close(struct libcouchbase_io_opt_st *iops,
                                  libcouchbase_socket_t sock)
{
    (void)iops;
    EVUTIL_CLOSESOCKET(sock);
}

static int libcouchbase_io_connect(struct libcouchbase_io_opt_st *iops,
                                   libcouchbase_socket_t sock,
                                   const struct sockaddr *name,
                                   int namelen)
{
    int ret = connect(sock, name, (socklen_t)namelen);
    if (ret < 0) {
        iops->error = errno;
    }
    return ret;
}

static void *libcouchbase_io_create_event(struct libcouchbase_io_opt_st *iops)
{
    return event_new(iops->cookie, INVALID_SOCKET, 0, NULL, NULL);
}

static int libcouchbase_io_update_event(struct libcouchbase_io_opt_st *iops,
                                        libcouchbase_socket_t sock,
                                        void *event,
                                        short flags,
                                        void *cb_data,
                                        void (*handler)(libcouchbase_socket_t sock,
                                                        short which,
                                                        void *cb_data))
{
    flags |= EV_PERSIST;
    if (flags == event_get_events(event) &&
        handler == event_get_callback(event)) {
        // no change!
        return 0;
    }

    if (event_pending(event, EV_READ|EV_WRITE, 0)) {
        event_del(event);
    }

    event_assign(event, iops->cookie, sock, flags, handler, cb_data);
    return event_add(event, NULL);
}

static void libcouchbase_io_destroy_event(struct libcouchbase_io_opt_st *iops,
                                          void *event)
{
    (void)iops;
    if (event_pending(event, EV_READ|EV_WRITE, 0)) {
        event_del(event);
    }
    event_free(event);
}

static void libcouchbase_io_delete_event(struct libcouchbase_io_opt_st *iops,
                                          libcouchbase_socket_t sock,
                                          void *event)
{
    (void)iops; (void)sock;
    if (event_del(event) == -1) {
        fprintf(stderr, "Failed to release event\n");
    }
    event_assign(event, iops->cookie, -1, 0, NULL, NULL);
}

static void libcouchbase_io_stop_event_loop(struct libcouchbase_io_opt_st *iops)
{
    event_base_loopbreak(iops->cookie);
}

static void libcouchbase_io_run_event_loop(struct libcouchbase_io_opt_st *iops)
{
     event_base_loop(iops->cookie, 0);
}

static void libcouchbase_destroy_io_opts(struct libcouchbase_io_opt_st *instance)
{
    free(instance);
}

LIBCOUCHBASE_API
struct libcouchbase_io_opt_st *libcouchbase_create_libevent_io_opts(struct event_base *base)
{
    struct libcouchbase_io_opt_st *ret;
    if ((ret = calloc(1, sizeof(*ret))) == NULL) {
        return NULL;
    }

    // setup io iops!
    ret->recv = libcouchbase_io_recv;
    ret->send = libcouchbase_io_send;
    ret->socket = libcouchbase_io_socket;
    ret->close = libcouchbase_io_close;
    ret->connect = libcouchbase_io_connect;
    ret->delete_event = libcouchbase_io_delete_event;
    ret->destroy_event = libcouchbase_io_destroy_event;
    ret->create_event = libcouchbase_io_create_event;
    ret->update_event = libcouchbase_io_update_event;
    ret->run_event_loop = libcouchbase_io_run_event_loop;
    ret->stop_event_loop = libcouchbase_io_stop_event_loop;
    ret->destructor = libcouchbase_destroy_io_opts;
    if (base == NULL) {
        ret->cookie = event_base_new();
        if (ret->cookie == NULL) {
            free(ret);
            ret = NULL;
        }
    } else {
        ret->cookie = base;
    }

    return ret;
}
