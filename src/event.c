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
 * This file contains the callback functions used by libevent.
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"

static int do_read_data(libcouchbase_server_t *c)
{
    size_t processed;
    const int operations_per_call = 1000;
    int operations = 0;
    protocol_binary_response_header *res;
    protocol_binary_request_header *req;

    grow_buffer(&c->input, 8192);
    res = (void*)c->input.data;
    req = (void*)c->input.data;

    do {
        ssize_t nr;
        hrtime_t stop = gethrtime();
        while (++operations < operations_per_call &&
               c->input.avail >= sizeof(*req) &&
               c->input.avail >= (ntohl(req->request.bodylen) + sizeof(*req))) {

            if (c->instance->packet_filter(c->instance, c->input.data)) {
                struct libcouchbase_command_data_st *ct = (void*)c->output_cookies.data;

                switch (req->request.magic) {
                case PROTOCOL_BINARY_REQ:
                    c->instance->request_handler[req->request.opcode](c,
                                                                      ct->cookie,
                                                                      req);
                    break;
                case PROTOCOL_BINARY_RES:
                    if (libcouchbase_server_purge_implicit_responses(c, res->response.opaque, stop) != 0) {
                        // TODO: Print an error message here.
                        return -1;
                    }
                    if (ct->start != 0 && c->instance->histogram) {
                        libcouchbase_record_metrics(c->instance,
                                                    stop - ct->start,
                                                    res->response.opcode);
                    }
                    c->instance->response_handler[res->response.opcode](c,
                                                                        ct->cookie,
                                                                        res);

                    req = (protocol_binary_request_header*)c->cmd_log.data;
                    processed = ntohl(req->request.bodylen) + sizeof(*req);
                    assert(c->cmd_log.avail >= processed);
                    memmove(c->cmd_log.data, c->cmd_log.data + processed,
                            c->cmd_log.avail - processed);
                    c->cmd_log.avail -= processed;
                    req = (protocol_binary_request_header*)c->input.data;
                    c->output_cookies.avail -= sizeof(*ct);
                    memmove(c->output_cookies.data,
                            c->output_cookies.data + sizeof(*ct),
                            c->output_cookies.avail);
                    break;
                default:
                    // TODO: Print an error message here.
                    return -1;
                }
            }

            processed = ntohl(req->request.bodylen) + sizeof(*req);
            memmove(c->input.data, c->input.data + processed,
                    c->input.avail - processed);
            c->input.avail -= processed;
        }

        if (operations == operations_per_call) {
            // allow some other connections to process some data as well
            return 0;
        }

        nr = recv(c->sock,
                  c->input.data + c->input.avail,
                  c->input.size - c->input.avail,
                  0);

        if (nr == -1) {
            switch (errno) {
            case EINTR:
                break;
            case EWOULDBLOCK:
                return 0;
            default:
                // TODO: Print an error message here.
                return -1;
            }
        } else if (nr == 0) {
            assert(c->input.avail != c->input.size);
            // TODO: Print an error message here.
            return -1;
        } else {
            c->input.avail += (size_t)nr;
            if (c->input.avail == c->input.size) {
                grow_buffer(&c->input, 8192);
                res = (void*)c->input.data;
                req = (void*)c->input.data;
            }
        }
    } while (true);
}

static int do_send_data(libcouchbase_server_t *c)
{
    do {
        ssize_t nw = send(c->sock, c->output.data, c->output.avail, 0);
        if (nw == -1) {
            switch (errno) {
            case EINTR:
                // retry
                break;
            case EWOULDBLOCK:
                return 0;
            default:
                // FIXME!
                fprintf(stderr, "Failed to write data: %s\n",
                        strerror(errno));
                fflush(stderr);
                return -1;
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

    return 0;
}

void libcouchbase_server_event_handler(evutil_socket_t sock, short which, void *arg) {
    libcouchbase_server_t *c = arg;
    (void)sock;

    if (which & EV_READ) {
        if (do_read_data(c) != 0) {
            // TODO: Is there a better error for this?
            char errinfo[1024];
            snprintf(errinfo, sizeof(errinfo), "Failed to read from connection"
                     " to \"%s:%s\"", c->hostname, c->port);
            libcouchbase_error_handler(c->instance, LIBCOUCHBASE_NETWORK_ERROR,
                                       errinfo);
            return;
        }
    }

    if (which & EV_WRITE) {
        if (do_send_data(c) != 0) {
            char errinfo[1024];
            snprintf(errinfo, sizeof(errinfo), "Failed to send to the "
                     "connection to \"%s:%s\"", c->hostname, c->port);
            // TODO: Is there a better error for this?
            libcouchbase_error_handler(c->instance, LIBCOUCHBASE_NETWORK_ERROR,
                                       errinfo);
            return;
        }
    }

    if (c->output.avail == 0) {
        libcouchbase_server_update_event(c, EV_READ,
                                         libcouchbase_server_event_handler);
    } else {
        libcouchbase_server_update_event(c, EV_READ | EV_WRITE,
                                         libcouchbase_server_event_handler);
    }

    if (c->instance->execute) {
        bool done = true;
        libcouchbase_t instance = c->instance;
        size_t ii;
        for (ii = 0; ii < instance->nservers; ++ii) {
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

    // Make it known that this was a success.
    libcouchbase_error_handler(c->instance, LIBCOUCHBASE_SUCCESS, NULL);
}

void libcouchbase_server_update_event(libcouchbase_server_t *c, short flags,
                                      EVENT_HANDLER handler) {
    if (c->ev_flags == flags && c->ev_handler == handler) {
        /* no change */
        return;
    }
    c->ev_handler = handler;

    if (c->ev_flags != 0) {
        if (event_del(&c->ev_event) == -1) {
            fprintf(stderr, "Failed to release event\n");
            // Continue anyway.
        }
    }
    c->ev_flags = flags;
    event_set(&c->ev_event, c->sock, flags | EV_PERSIST, handler, c);
    event_base_set(c->instance->ev_base, &c->ev_event);
    if (event_add(&c->ev_event, NULL) == -1) {
        fprintf(stderr, "Failed to add event\n");
        return; // Don't continue.
    }
}

static void breakout_vbucket_state_listener(libcouchbase_server_t *server)
{
    event_base_loopbreak(server->instance->ev_base);
}

void libcouchbase_ensure_vbucket_config(libcouchbase_t instance)
{
    if (instance->vbucket_config == NULL) {
        vbucket_state_listener_t old = instance->vbucket_state_listener;
        instance->vbucket_state_listener = breakout_vbucket_state_listener;
        event_base_loop(instance->ev_base, 0);
        instance->vbucket_state_listener = old;
    }
}
