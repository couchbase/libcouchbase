/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2012 Couchbase, Inc.
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
 * This file contains an implementation of the IO functions that should
 * work on Microsoft Windows. The current implementation use select(),
 * and the default implementation of select() doesn't support more than
 * 64 sockets. Since this is a quick'n'dirty prototype for Windows, I'm
 * not going to try to make it smarter (I want to reimplement it to use
 * IOCP anyway)
 *
 * @author Trond Norbye
 * @todo Rewrite to use IOCP
 */

#include "internal.h"
#include "winsock_io_opts.h"

struct winsock_event {
    WSAEVENT event;
    SOCKET sock;
    short flags;
    void *cb_data;
    void (*handler)(lcb_socket_t sock, short which, void *cb_data);
    struct winsock_event *next;
};

struct winsock_timer {
    int active;
    hrtime_t exptime;
    void *cb_data;
    void (*handler)(lcb_socket_t sock, short which, void *cb_data);
    struct winsock_timer *next;
};

struct winsock_io_cookie {
    struct winsock_event *events;
    struct winsock_timer *timers;

    fd_set readfds[FD_SETSIZE];
    fd_set writefds[FD_SETSIZE];
    fd_set exceptfds[FD_SETSIZE];

    int event_loop;
};

#include "event_lists.h"

static int getError(lcb_socket_t sock)
{
    DWORD error = WSAGetLastError();
    int ext = 0;
    int len = sizeof(ext);

    /* Retrieves extended error status and clear */
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&ext, &len);
    switch (error) {
    case WSAECONNRESET:
    case WSAECONNABORTED:
        return ECONNRESET;
    case WSAEWOULDBLOCK:
        return EWOULDBLOCK;
    case WSAEINVAL:
        return EINVAL;
    case WSAEINPROGRESS:
        return EINPROGRESS;
    case WSAEALREADY:
        return EALREADY;
    case WSAEISCONN:
        return EISCONN;
    case WSAENOTCONN:
        return ENOTCONN;
    case WSAECONNREFUSED:
        return ECONNREFUSED;

    default:
        fprintf(stdout, "Unknown error code: %u\n", error);
        abort();
        return EINVAL;
    }

    return EINVAL;
}

static lcb_ssize_t lcb_io_recv(struct lcb_io_opt_st *iops,
                               lcb_socket_t sock,
                               void *buffer,
                               lcb_size_t len,
                               int flags)
{
    DWORD fl = 0;
    DWORD nr;
    WSABUF wsabuf = { (ULONG)len, buffer };
    (void)flags;

    if (WSARecv(sock, &wsabuf, 1, &nr, &fl, NULL, NULL) == SOCKET_ERROR) {
        iops->v.v0.error = getError(sock);

        // recv on a closed socket should return 0
        if (iops->v.v0.error == ECONNRESET) {
            return 0;
        }
        return -1;
    }

    return (lcb_ssize_t)nr;
}

static lcb_ssize_t lcb_io_recvv(struct lcb_io_opt_st *iops,
                                lcb_socket_t sock,
                                struct lcb_iovec_st *iov,
                                lcb_size_t niov)
{
    DWORD fl = 0;
    DWORD nr;
    WSABUF wsabuf[2];

    assert(niov == 2);
    wsabuf[0].buf = iov[0].iov_base;
    wsabuf[0].len = (ULONG)iov[0].iov_len;
    wsabuf[1].buf = iov[1].iov_base;
    wsabuf[1].len = (ULONG)iov[1].iov_len;

    if (WSARecv(sock, wsabuf, iov[1].iov_len ? 2 : 1,
                &nr, &fl, NULL, NULL) == SOCKET_ERROR) {
        iops->v.v0.error = getError(sock);

        // recv on a closed socket should return 0
        if (iops->v.v0.error == ECONNRESET) {
            return 0;
        }
        return -1;
    }

    return (lcb_ssize_t)nr;
}


static lcb_ssize_t lcb_io_send(struct lcb_io_opt_st *iops,
                               lcb_socket_t sock,
                               const void *msg,
                               lcb_size_t len,
                               int flags)
{
    DWORD fl = 0;
    DWORD nw;
    WSABUF wsabuf = { (ULONG)len, (char *)msg };
    (void)flags;

    if (WSASend(sock, &wsabuf, 1, &nw, fl, NULL, NULL) == SOCKET_ERROR) {
        iops->v.v0.error = getError(sock);
        return -1;
    }

    return (lcb_ssize_t)nw;
}

static lcb_ssize_t lcb_io_sendv(struct lcb_io_opt_st *iops,
                                lcb_socket_t sock,
                                struct lcb_iovec_st *iov,
                                lcb_size_t niov)
{
    DWORD fl = 0;
    DWORD nw;
    WSABUF wsabuf[2];

    assert(niov == 2);
    wsabuf[0].buf = iov[0].iov_base;
    wsabuf[0].len = (ULONG)iov[0].iov_len;
    wsabuf[1].buf = iov[1].iov_base;
    wsabuf[1].len = (ULONG)iov[1].iov_len;

    if (WSASend(sock, wsabuf, iov[1].iov_len ? 2 : 1,
                &nw, fl, NULL, NULL) == SOCKET_ERROR) {
        iops->v.v0.error = getError(sock);
        return -1;
    }

    return (lcb_ssize_t)nw;
}

static lcb_socket_t lcb_io_socket(struct lcb_io_opt_st *iops,
                                  int domain,
                                  int type,
                                  int protocol)
{
    lcb_socket_t sock = WSASocket(domain, type, protocol, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        iops->v.v0.error = getError(sock);
    } else {
        u_long noblock = 1;
        if (ioctlsocket(sock, FIONBIO, &noblock) == SOCKET_ERROR) {
            iops->v.v0.error = getError(sock);
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
    }

    return sock;
}

static void lcb_io_close(struct lcb_io_opt_st *iops,
                         lcb_socket_t sock)
{
    (void)iops;
    closesocket(sock);
}

static int lcb_io_connect(struct lcb_io_opt_st *iops,
                          lcb_socket_t sock,
                          const struct sockaddr *name,
                          unsigned int namelen)
{
    int ret = WSAConnect(sock, name, (int)namelen, NULL, NULL, NULL, NULL);
    if (ret == SOCKET_ERROR) {
        iops->v.v0.error = getError(sock);
    }
    return ret;
}

static void *lcb_io_create_event(struct lcb_io_opt_st *iops)
{
    struct winsock_event *ret = calloc(1, sizeof(*ret));
    if (ret != NULL) {
        link_event(iops->v.v0.cookie, ret);
    }

    return ret;
}

static int lcb_io_update_event(struct lcb_io_opt_st *iops,
                               lcb_socket_t sock,
                               void *event,
                               short flags,
                               void *cb_data,
                               void (*handler)(lcb_socket_t sock,
                                               short which,
                                               void *cb_data))
{
    int mask = 0;
    struct winsock_event *ev = event;
    ev->sock = sock;
    ev->handler = handler;
    ev->cb_data = cb_data;
    ev->flags = flags;
    return 0;
}

static void lcb_io_destroy_event(struct lcb_io_opt_st *iops,
                                 void *event)
{
    struct winsock_event *ev = event;
    unlink_event(iops->v.v0.cookie, event);
    free(ev);
}

static void lcb_io_delete_event(struct lcb_io_opt_st *iops,
                                lcb_socket_t sock,
                                void *event)
{
    struct winsock_event *ev = event;
    ev->flags = 0;
    ev->cb_data = NULL;
    ev->handler = NULL;
}

void *lcb_io_create_timer(struct lcb_io_opt_st *iops)
{
    struct winsock_timer *timer;
    timer = calloc(1, sizeof(*timer));
    if (timer != NULL) {
        link_timer(iops->v.v0.cookie, timer);
    }
    return timer;
}

void lcb_io_destroy_timer(struct lcb_io_opt_st *iops,
                          void *timer)
{
    struct winsock_timer *tm = timer;
    unlink_timer(iops->v.v0.cookie, tm);
    free(tm);
}

void lcb_io_delete_timer(struct lcb_io_opt_st *iops,
                         void *timer)
{
    struct winsock_timer *tm = timer;
    tm->active = 0;
}

int lcb_io_update_timer(struct lcb_io_opt_st *iops,
                        void *timer,
                        lcb_uint32_t usec,
                        void *cb_data,
                        void (*handler)(lcb_socket_t sock,
                                        short which,
                                        void *cb_data))
{
    struct winsock_timer *tm = timer;
    tm->exptime = gethrtime() + (usec * (hrtime_t)1000);
    tm->cb_data = cb_data;
    tm->handler = handler;
    tm->active = 1;
    return 0;
}

static void lcb_io_stop_event_loop(struct lcb_io_opt_st *iops)
{
    struct winsock_io_cookie *instance = iops->v.v0.cookie;
    instance->event_loop = 0;
}

static void lcb_io_run_event_loop(struct lcb_io_opt_st *iops)
{
    struct winsock_io_cookie *instance = iops->v.v0.cookie;
    int nevents;
    struct winsock_event *n;

    instance->event_loop = 1;
    do {
        struct winsock_timer *tm;
        struct timeval tmo, *t;
        int ret;

        FD_ZERO(instance->readfds);
        FD_ZERO(instance->writefds);
        FD_ZERO(instance->exceptfds);
        nevents = 0;

        for (n = instance->events; n != NULL; n = n->next) {
            if (n->flags != 0) {
                if (n->flags & LCB_READ_EVENT) {
                    FD_SET(n->sock, instance->readfds);
                }

                if (n->flags & LCB_WRITE_EVENT) {
                    FD_SET(n->sock, instance->writefds);
                }
                ++nevents;
            }
        }

        if (nevents == 0) {
            instance->event_loop = 0;
            return;
        }

        t = NULL;
        if (instance->timers != NULL) {
            hrtime_t now = gethrtime();
            hrtime_t min = 0;
            tmo.tv_sec = 0;
            tmo.tv_usec = 0;

            for (tm = instance->timers; tm != NULL; tm = tm->next) {
                if (tm->active && now < tm->exptime
                        && (min == 0 || min > tm->exptime)) {
                    min = tm->exptime;
                }
            }
            if (min > 0) {
                hrtime_t delta = min - now;
                delta /= 1000;
                tmo.tv_sec = (long)(delta / 1000000);
                tmo.tv_usec = delta % 1000000;
                t = &tmo;
            }
        }
        ret = select(FD_SETSIZE, instance->readfds, instance->writefds,
                     instance->exceptfds, t);

        if (ret == SOCKET_ERROR) {
            fprintf(stderr, "lcb_io_run_event_loop: select() call returned SOCKET_ERROR\n");
            return ;
        }

        if (ret == 0) {
            hrtime_t now = gethrtime();
            struct winsock_timer *t = instance->timers;
            while (t != NULL) {
                tm = t;
                t = t->next;
                if (tm->active && now > tm->exptime) {
                    tm->handler(-1, 0, tm->cb_data);
                }
            }
        } else {
            struct winsock_event *ev = instance->events;
            while (ev != NULL) {
                n = ev;
                ev = ev->next;
                if (n->flags != 0) {
                    short flags = 0;

                    if (FD_ISSET(n->sock, instance->readfds)) {
                        flags |= LCB_READ_EVENT;
                    }

                    if (FD_ISSET(n->sock, instance->writefds)) {
                        flags |= LCB_WRITE_EVENT;
                    }

                    if (flags != 0) {
                        n->handler(n->sock, flags, n->cb_data);
                    }
                }
            }
        }
    } while (instance->event_loop);
}

static void lcb_destroy_io_opts(struct lcb_io_opt_st *iops)
{
    struct winsock_io_cookie *instance = iops->v.v0.cookie;
    struct winsock_event *ev;
    struct winsock_timer *tm;

    assert(instance->event_loop == 0);
    for (ev = instance->events; ev != NULL; ev = ev->next) {
        lcb_io_destroy_event(iops, ev);
    }
    assert(instance->events == NULL);
    for (tm = instance->timers; tm != NULL; tm = tm->next) {
        lcb_io_destroy_timer(iops, tm);
    }
    assert(instance->timers == NULL);
    free(iops->v.v0.cookie);
    free(iops);
}


LIBCOUCHBASE_API
struct lcb_io_opt_st *lcb_create_winsock_io_opts(void) {
    struct lcb_io_opt_st *ret;
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
        fprintf(stderr, "Socket Initialization Error. Program aborted\n");
        return NULL;
    }

    if ((ret = calloc(1, sizeof(*ret))) == NULL) {
        return NULL;
    }

    // setup io iops!
    ret->version = 0;
    ret->destructor = lcb_destroy_io_opts;
    /* consider that struct isn't allocated by the library,
     * `need_cleanup' flag might be set in lcb_create() */
    ret->v.v0.need_cleanup = 0;
    ret->v.v0.recv = lcb_io_recv;
    ret->v.v0.send = lcb_io_send;
    ret->v.v0.recvv = lcb_io_recvv;
    ret->v.v0.sendv = lcb_io_sendv;
    ret->v.v0.socket = lcb_io_socket;
    ret->v.v0.close = lcb_io_close;
    ret->v.v0.connect = lcb_io_connect;
    ret->v.v0.delete_event = lcb_io_delete_event;
    ret->v.v0.destroy_event = lcb_io_destroy_event;
    ret->v.v0.create_event = lcb_io_create_event;
    ret->v.v0.update_event = lcb_io_update_event;
    ret->v.v0.delete_timer = lcb_io_delete_timer;
    ret->v.v0.destroy_timer = lcb_io_destroy_timer;
    ret->v.v0.create_timer = lcb_io_create_timer;
    ret->v.v0.update_timer = lcb_io_update_timer;
    ret->v.v0.run_event_loop = lcb_io_run_event_loop;
    ret->v.v0.stop_event_loop = lcb_io_stop_event_loop;
    ret->v.v0.cookie = calloc(1, sizeof(struct winsock_io_cookie));

    if (ret->v.v0.cookie == NULL) {
        free(ret);
        ret = NULL;
    }

    return ret;
}
