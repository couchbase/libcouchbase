/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011 Couchbase, Inc.
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
#include <sys/types.h>
#include <sys/socket.h>

#ifndef HAVE_LIBEVENT2
/* libevent 1.x compatibility layer */

typedef void (*event_callback_fn)(evutil_socket_t, short, void *);

static int
event_assign(struct event *ev,
             struct event_base *base,
             evutil_socket_t fd,
             short events,
             event_callback_fn callback,
             void *arg)
{
    event_base_set(base, ev);
    ev->ev_callback = callback;
    ev->ev_arg = arg;
    ev->ev_fd = fd;
    ev->ev_events = events;
    ev->ev_res = 0;
    ev->ev_flags = EVLIST_INIT;
    ev->ev_ncalls = 0;
    ev->ev_pncalls = NULL;

    return 0;
}

static struct event *
event_new(struct event_base *base,
          evutil_socket_t fd,
          short events,
          event_callback_fn cb,
          void *arg)
{
    struct event *ev;
    ev = malloc(sizeof(struct event));
    if (ev == NULL) {
        return NULL;
    }
    if (event_assign(ev, base, fd, events, cb, arg) < 0) {
        free(ev);
        return NULL;
    }
    return ev;
}

static void
event_free(struct event *ev)
{
    /* make sure that this event won't be coming back to haunt us. */
    free(ev);

}
static short
event_get_events(const struct event *ev)
{
    return ev->ev_events;
}

static event_callback_fn
event_get_callback(const struct event *ev)
{
    return ev->ev_callback;
}
#endif
static libcouchbase_ssize_t libcouchbase_io_recv(struct libcouchbase_io_opt_st *iops,
                                    libcouchbase_socket_t sock,
                                    void *buffer,
                                    libcouchbase_size_t len,
                                    int flags)
{
    libcouchbase_ssize_t ret = recv(sock, buffer, len, flags);
    if (ret < 0) {
        iops->error = errno;
    }
    return ret;
}

static libcouchbase_ssize_t libcouchbase_io_recvv(struct libcouchbase_io_opt_st *iops,
                                     libcouchbase_socket_t sock,
                                     struct libcouchbase_iovec_st *iov,
                                     libcouchbase_size_t niov)
{
    struct msghdr msg;
    struct iovec vec[2];
    libcouchbase_ssize_t ret;

    assert(niov == 2);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = vec;
    msg.msg_iovlen = iov[1].iov_len ? (libcouchbase_size_t)2 : (libcouchbase_size_t)1;
    msg.msg_iov[0].iov_base = iov[0].iov_base;
    msg.msg_iov[0].iov_len = iov[0].iov_len;
    msg.msg_iov[1].iov_base = iov[1].iov_base;
    msg.msg_iov[1].iov_len = iov[1].iov_len;
    ret = recvmsg(sock, &msg, 0);

    if (ret < 0) {
        iops->error = errno;
    }

    return ret;
}

static libcouchbase_ssize_t libcouchbase_io_send(struct libcouchbase_io_opt_st *iops,
                                    libcouchbase_socket_t sock,
                                    const void *msg,
                                    libcouchbase_size_t len,
                                    int flags)
{
    libcouchbase_ssize_t ret = send(sock, msg, len, flags);
    if (ret < 0) {
        iops->error = errno;
    }
    return ret;
}

static libcouchbase_ssize_t libcouchbase_io_sendv(struct libcouchbase_io_opt_st *iops,
                                     libcouchbase_socket_t sock,
                                     struct libcouchbase_iovec_st *iov,
                                     libcouchbase_size_t niov)
{
    struct msghdr msg;
    struct iovec vec[2];
    libcouchbase_ssize_t ret;

    assert(niov == 2);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = vec;
    msg.msg_iovlen = iov[1].iov_len ? (libcouchbase_size_t)2 : (libcouchbase_size_t)1;
    msg.msg_iov[0].iov_base = iov[0].iov_base;
    msg.msg_iov[0].iov_len = iov[0].iov_len;
    msg.msg_iov[1].iov_base = iov[1].iov_base;
    msg.msg_iov[1].iov_len = iov[1].iov_len;
    ret = sendmsg(sock, &msg, 0);

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
        /* no change! */
        return 0;
    }

    if (event_pending(event, EV_READ|EV_WRITE, 0)) {
        event_del(event);
    }

    event_assign(event, iops->cookie, sock, flags, handler, cb_data);
    return event_add(event, NULL);
}


static void libcouchbase_io_delete_timer(struct libcouchbase_io_opt_st *iops,
                                         void *event)
{
    (void)iops;
    if(event_pending(event, EV_TIMEOUT, 0) != 0 && event_del(event) == -1) {
        fprintf(stderr, "Failed to release timer\n");
    }
    event_assign(event, iops->cookie, -1, 0, NULL, NULL);
}

static int libcouchbase_io_update_timer(struct libcouchbase_io_opt_st *iops,
                                        void *timer,
                                        libcouchbase_uint32_t usec,
                                        void *cb_data,
                                        void (*handler)(libcouchbase_socket_t sock,
                                                        short which,
                                                        void *cb_data))
{
    short flags = EV_TIMEOUT | EV_PERSIST;
    struct timeval tmo;
    if (flags == event_get_events(timer) &&
        handler == event_get_callback(timer)) {
        /* no change! */
        return 0;
    }

    if (event_pending(timer, EV_TIMEOUT, 0)) {
        event_del(timer);
    }

    event_assign(timer, iops->cookie, -1, flags, handler, cb_data);
    tmo.tv_sec = usec / 1000000;
    tmo.tv_usec = usec % 1000000;
    return event_add(timer, &tmo);
}

static void libcouchbase_io_destroy_event(struct libcouchbase_io_opt_st *iops,
                                          void *event)
{
    (void)iops;
    if (event_pending(event, EV_READ|EV_WRITE|EV_TIMEOUT, 0)) {
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

    /* setup io iops! */
    ret->recv = libcouchbase_io_recv;
    ret->send = libcouchbase_io_send;
    ret->recvv = libcouchbase_io_recvv;
    ret->sendv = libcouchbase_io_sendv;
    ret->socket = libcouchbase_io_socket;
    ret->close = libcouchbase_io_close;
    ret->connect = libcouchbase_io_connect;
    ret->delete_event = libcouchbase_io_delete_event;
    ret->destroy_event = libcouchbase_io_destroy_event;
    ret->create_event = libcouchbase_io_create_event;
    ret->update_event = libcouchbase_io_update_event;

    ret->delete_timer = libcouchbase_io_delete_timer;
    ret->destroy_timer = libcouchbase_io_destroy_event;
    ret->create_timer = libcouchbase_io_create_event;
    ret->update_timer = libcouchbase_io_update_timer;

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
