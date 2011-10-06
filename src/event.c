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
 * This file contains the callback functions used by libevent.
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"

static int do_fill_input_buffer(libcouchbase_server_t *c)
{
    struct libcouchbase_iovec_st iov[2];
    ssize_t nr;

    if (!libcouchbase_ringbuffer_ensure_capacity(&c->input, 8192)) {
        libcouchbase_error_handler(c->instance, LIBCOUCHBASE_ENOMEM, NULL);
        return -1;
    }

    libcouchbase_ringbuffer_get_iov(&c->input, RINGBUFFER_WRITE, iov);

    nr = c->instance->io->recvv(c->instance->io, c->sock, iov, 2);
    if (nr == -1) {
        switch (c->instance->io->error) {
        case EINTR:
            break;
        case EWOULDBLOCK:
            return 0;
        default:
            libcouchbase_error_handler(c->instance, LIBCOUCHBASE_NETWORK_ERROR,
                                       NULL);
            return -1;
        }
    } else if (nr == 0) {
        assert((iov[0].iov_len + iov[1].iov_len) != 0);
        libcouchbase_error_handler(c->instance,
                                   LIBCOUCHBASE_NETWORK_ERROR,
                                   "Connection closed... we should resend to other nodes or reconnect!!");
        return -1;
    } else {
        libcouchbase_ringbuffer_produced(&c->input, (size_t)nr);
    }

    return 1;
}



static int parse_single(libcouchbase_server_t *c, hrtime_t stop)
{
    protocol_binary_response_header header;
    size_t nr;
    char *packet;
    uint32_t packetsize;
    struct libcouchbase_command_data_st ct;

    nr = libcouchbase_ringbuffer_peek(&c->input, header.bytes, sizeof(header));
    if (nr < sizeof(header)) {
        return 0;
    }

    packetsize = ntohl(header.response.bodylen) + (uint32_t)sizeof(header);
    if (c->input.nbytes < packetsize) {
        return 0;
    }

    packet = c->input.read_head;
    // we have everything!

    if (!libcouchbase_ringbuffer_is_continous(&c->input, RINGBUFFER_READ,
                                              packetsize)) {
        // The buffer isn't continous.. for now just copy it out and
        // operate on the copy ;)
        if ((packet = malloc(packetsize)) == NULL) {
            libcouchbase_error_handler(c->instance, LIBCOUCHBASE_ENOMEM, NULL);
            return -1;
        }
        nr = libcouchbase_ringbuffer_read(&c->input, packet, packetsize);
        if (nr != packetsize) {
            libcouchbase_error_handler(c->instance, LIBCOUCHBASE_EINTERNAL,
                                       NULL);
            free(packet);
            return -1;
        }
    }

    nr = libcouchbase_ringbuffer_peek(&c->output_cookies, &ct, sizeof(ct));
    if (nr < sizeof(ct)) {
        libcouchbase_error_handler(c->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
        if (packet != c->input.read_head) {
            free(packet);
        }
        return -1;
    }

    switch (header.response.magic) {
    case PROTOCOL_BINARY_REQ:
        c->instance->request_handler[header.response.opcode](c,ct.cookie,
                                                             (void*)packet);
        break;
    case PROTOCOL_BINARY_RES:
        if (libcouchbase_server_purge_implicit_responses(c,
                                                         header.response.opaque, stop) != 0) {
            if (packet != c->input.read_head) {
                free(packet);
            }
            return -1;
        }


        nr = libcouchbase_ringbuffer_read(&c->output_cookies, &ct, sizeof(ct));
        assert(nr == sizeof(ct));
        if (ct.start != 0 && c->instance->histogram) {
            libcouchbase_record_metrics(c->instance, stop - ct.start,
                                        header.response.opcode);
        }

        c->instance->response_handler[header.response.opcode](c,
                                                              ct.cookie,
                                                              (void*)packet);
        nr = libcouchbase_ringbuffer_read(&c->cmd_log, header.bytes,
                                          sizeof(header));
        assert(nr == sizeof(header));
        libcouchbase_ringbuffer_consumed(&c->cmd_log,
                                         ntohl(header.response.bodylen));
        break;

    default:
        libcouchbase_error_handler(c->instance,
                                   LIBCOUCHBASE_PROTOCOL_ERROR,
                                   NULL);
        if (packet != c->input.read_head) {
            free(packet);
        }
        return -1;
    }

    if (packet != c->input.read_head) {
        free(packet);
    } else {
        libcouchbase_ringbuffer_consumed(&c->input, packetsize);
    }
    return 1;
}


static int do_read_data(libcouchbase_server_t *c)
{
    // Loop and try to parse the data... We don't want to lock up the
    // event loop completely, so set a max number of packets to process
    // before backing off..
    size_t processed = 0;
    // @todo Make the backoff number tunable from the instance
    const size_t operations_per_call = 1000;
    int rv = 0;
    // The timers isn't supposed to be _that_ accurate.. it's better
    // to shave off system calls :)
    hrtime_t stop = gethrtime();

    while (processed < operations_per_call) {
        switch ((rv = parse_single(c, stop))) {
        case -1:
            return -1;
        case 0:
            // need more data
            if ((rv = do_fill_input_buffer(c)) < 1) {
                // error or would block ;)
                return rv;
            }
            break;
        default:
            ++processed;
        }
    }

    return rv;
}

static int do_send_data(libcouchbase_server_t *c)
{
    do {
        struct libcouchbase_iovec_st iov[2];
        ssize_t nw;
        libcouchbase_ringbuffer_get_iov(&c->output, RINGBUFFER_READ, iov);
        nw = c->instance->io->sendv(c->instance->io, c->sock, iov, 2);
        if (nw == -1) {
            switch (c->instance->io->error) {
            case EINTR:
                // retry
                break;
            case EWOULDBLOCK:
                return 0;
            default:
                libcouchbase_error_handler(c->instance,
                                           LIBCOUCHBASE_NETWORK_ERROR, NULL);
                return -1;
            }
        } else {
            int ii = 0;
            if (!libcouchbase_ringbuffer_ensure_capacity(&c->cmd_log, (size_t)nw)) {
                libcouchbase_error_handler(c->instance, LIBCOUCHBASE_ENOMEM, NULL);
                return -1;
            }
            libcouchbase_ringbuffer_consumed(&c->output, (size_t)nw);
            do {
                size_t nb = (size_t)nw < iov[ii].iov_len ? (size_t)nw : iov[ii].iov_len;
                libcouchbase_ringbuffer_write(&c->cmd_log, iov[ii].iov_base,
                                              nb);
                nw -= (ssize_t)nb;
                ++ii;
            } while (nw > 0);
        }
    } while (c->output.nbytes > 0);

    return 0;
}

void libcouchbase_server_event_handler(evutil_socket_t sock, short which, void *arg) {
    libcouchbase_server_t *c = arg;
    (void)sock;

    if (which & LIBCOUCHBASE_READ_EVENT) {
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

    if (which & LIBCOUCHBASE_WRITE_EVENT) {
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

    if (c->output.nbytes == 0) {
        c->instance->io->update_event(c->instance->io, c->sock,
                                      c->event, LIBCOUCHBASE_READ_EVENT,
                                      c, libcouchbase_server_event_handler);
    } else {
        c->instance->io->update_event(c->instance->io, c->sock,
                                      c->event, LIBCOUCHBASE_RW_EVENT,
                                      c, libcouchbase_server_event_handler);
    }

    if (c->instance->wait) {
        bool done = true;
        libcouchbase_t instance = c->instance;
        size_t ii;
        for (ii = 0; ii < instance->nservers; ++ii) {
            c = instance->servers + ii;
            if (c->cmd_log.nbytes || c->output.nbytes || c->input.nbytes) {
                done = false;
                break;
            }
        }

        if (done) {
            c->instance->io->stop_event_loop(c->instance->io);
        }
    }

    // Make it known that this was a success.
    libcouchbase_error_handler(c->instance, LIBCOUCHBASE_SUCCESS, NULL);
}
