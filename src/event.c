/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Membase, Inc.
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
 * This file contains the callback functions used by libevent.
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"

static void do_read_data(libmembase_server_t *c)
{
    size_t processed;
    const int operations_per_call = 1000;
    int operations = 0;
    grow_buffer(&c->input, 8192);
    protocol_binary_response_header *res = (protocol_binary_response_header*)c->input.data;
    protocol_binary_request_header *req = (protocol_binary_request_header*)c->input.data;
    do {
        while (++operations < operations_per_call &&
               c->input.avail >= sizeof(*req) &&
               c->input.avail >= (ntohl(req->request.bodylen) + sizeof(*req))) {

            if (c->instance->packet_filter(c->instance, c->input.data)) {
                switch (req->request.magic) {
                case PROTOCOL_BINARY_REQ:
                    c->instance->request_handler[req->request.opcode](c, req);
                    break;
                case PROTOCOL_BINARY_RES:
                    libmembase_server_purge_implicit_responses(c, res->response.opaque);
                    c->instance->response_handler[res->response.opcode](c, res);
                    req = (protocol_binary_request_header*)c->cmd_log.data;
                    processed = ntohl(req->request.bodylen) + sizeof(*req);
                    assert(c->cmd_log.avail >= processed);
                    memmove(c->cmd_log.data, c->cmd_log.data + processed,
                            c->cmd_log.avail - processed);
                    c->cmd_log.avail -= processed;
                    req = (protocol_binary_request_header*)c->input.data;
                    break;
                default:
                    abort();
                }
            }

            processed = ntohl(req->request.bodylen) + sizeof(*req);
            memmove(c->input.data, c->input.data + processed,
                    c->input.avail - processed);
            c->input.avail -= processed;
        }

        if (operations == operations_per_call) {
            // allow some other connections to process some data as well
            return ;
        }

        ssize_t nr = recv(c->sock,
                          c->input.data + c->input.avail,
                          c->input.size - c->input.avail,
                          0);

        if (nr == -1) {
            switch (errno) {
            case EINTR:
                break;
            case EWOULDBLOCK:
                return;
            default:
                abort();
            }
        } else if (nr == 0) {
            abort();
        } else {
            c->input.avail += (size_t)nr;
        }
    } while (true);
}

static void do_send_data(libmembase_server_t *c)
{
    do {
        ssize_t nw = send(c->sock, c->output.data, c->output.avail, 0);
        if (nw == -1) {
            switch (errno) {
            case EINTR:
                // retry
                break;
            case EWOULDBLOCK:
                return;
            default:
                // FIXME!
                fprintf(stderr, "Failed to write data: %s\n",
                        strerror(errno));
                fflush(stderr);
                abort();
            }
        } else {
            grow_buffer(&c->cmd_log, (size_t)nw);
            memcpy(c->cmd_log.data + c->cmd_log.avail,
                   c->output.data, (size_t)nw);
            c->cmd_log.avail += (size_t)nw;

            if ((size_t)nw == c->output.avail) {
                c->output.avail = 0;
            } else {
                memmove(c->output.data, c->output.data + nw,
                        c->output.avail - (size_t)nw);
                c->output.avail -= (size_t)nw;
            }
        }
    } while (c->output.avail > 0);
}

void libmembase_server_event_handler(evutil_socket_t sock, short which, void *arg) {
    (void)sock;
    libmembase_server_t *c = (libmembase_server_t *)arg;

    if (which & EV_READ) {
        do_read_data(c);
    }

    if (which & EV_WRITE) {
        do_send_data(c);
    }

    if (c->output.avail == 0) {
        libmembase_server_update_event(c, EV_READ,
                                       libmembase_server_event_handler);
    } else {
        libmembase_server_update_event(c, EV_READ | EV_WRITE,
                                       libmembase_server_event_handler);
    }

    if (c->instance->execute) {
        bool done = true;
        libmembase_t instance = c->instance;
        for (size_t ii = 0; ii < instance->nservers; ++ii) {
            c = instance->servers + ii;
            if (c->cmd_log.avail || c->output.avail || c->input.avail) {
                done = false;
                break;
            }
        }
        if (done) {
            event_base_loopbreak(instance->ev_base);
        }
    }
}

void libmembase_server_update_event(libmembase_server_t *c, short flags,
                                    EVENT_HANDLER handler) {
    if (c->ev_flags == flags && c->ev_handler == handler) {
        /* no change */
        return;
    }
    c->ev_handler = handler;

    if (c->ev_flags != 0) {
        if (event_del(&c->ev_event) == -1) {
            abort();
        }
    }
    c->ev_flags = flags;
    event_set(&c->ev_event, c->sock, flags | EV_PERSIST, handler, c);
    event_base_set(c->instance->ev_base, &c->ev_event);
    if (event_add(&c->ev_event, NULL) == -1) {
        abort();
    }
}

static void breakout_vbucket_state_listener(libmembase_server_t *server)
{
    event_base_loopbreak(server->instance->ev_base);
}

void libmembase_ensure_vbucket_config(libmembase_t instance)
{
    if (instance->vbucket_config == NULL) {
        vbucket_state_listener_t old = instance->vbucket_state_listener;
        instance->vbucket_state_listener = breakout_vbucket_state_listener;
        event_base_loop(instance->ev_base, 0);
        instance->vbucket_state_listener = old;
    }
}
