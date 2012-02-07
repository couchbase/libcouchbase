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
    libcouchbase_ssize_t nr;

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
            libcouchbase_failout_server(c, LIBCOUCHBASE_NETWORK_ERROR);
            return -1;
        }
    } else if (nr == 0) {
        assert((iov[0].iov_len + iov[1].iov_len) != 0);
        /* TODO stash error message somewhere
         * "Connection closed... we should resend to other nodes or reconnect!!" */
        libcouchbase_failout_server(c, LIBCOUCHBASE_NETWORK_ERROR);
        return -1;
    } else {
        libcouchbase_ringbuffer_produced(&c->input, (libcouchbase_size_t)nr);
    }

    return 1;
}

static int parse_single(libcouchbase_server_t *c, hrtime_t stop)
{
    protocol_binary_request_header req;
    protocol_binary_response_header header;
    libcouchbase_size_t nr;
    char *packet;
    libcouchbase_uint32_t packetsize;
    struct libcouchbase_command_data_st ct;

    nr = libcouchbase_ringbuffer_peek(&c->input, header.bytes, sizeof(header));
    if (nr < sizeof(header)) {
        return 0;
    }

    packetsize = ntohl(header.response.bodylen) + (libcouchbase_uint32_t)sizeof(header);
    if (c->input.nbytes < packetsize) {
        return 0;
    }

    /* Is it already timed out? */
    nr = libcouchbase_ringbuffer_peek(&c->cmd_log, req.bytes, sizeof(req));
    if (nr < sizeof(req) || /* the command log doesn't know about it */
        (header.response.opaque < req.request.opaque &&
         header.response.opaque > 0)) { /* sasl comes with zero opaque */
        /* already processed. */
        libcouchbase_ringbuffer_consumed(&c->input, packetsize);
        return 1;
    }

    packet = c->input.read_head;
    /* we have everything! */

    if (!libcouchbase_ringbuffer_is_continous(&c->input, RINGBUFFER_READ,
                                              packetsize)) {
        /* The buffer isn't continous.. for now just copy it out and
        ** operate on the copy ;)
        */
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
    if (nr != sizeof(ct)) {
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
    case PROTOCOL_BINARY_RES: {
        int was_connected = c->connected;
        if (libcouchbase_server_purge_implicit_responses(c,
                                                         header.response.opaque, stop) != 0) {
            if (packet != c->input.read_head) {
                free(packet);
            }
            return -1;
        }


        assert(nr == sizeof(ct));
        if (c->instance->histogram) {
            libcouchbase_record_metrics(c->instance, stop - ct.start,
                                        header.response.opcode);
        }

        if (ntohs(header.response.status) != PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET) {
            c->instance->response_handler[header.response.opcode](c,
                                                                  ct.cookie,
                                                                  (void*)packet);
            /* keep command and cookie until we get complete STAT response */
            if(was_connected &&
               (header.response.opcode != PROTOCOL_BINARY_CMD_STAT || header.response.keylen == 0)) {
                nr = libcouchbase_ringbuffer_read(&c->cmd_log, req.bytes, sizeof(req));
                assert(nr == sizeof(req));
                libcouchbase_ringbuffer_consumed(&c->cmd_log, ntohl(req.request.bodylen));
                libcouchbase_ringbuffer_consumed(&c->output_cookies, sizeof(ct));
            }
        } else {
            libcouchbase_vbucket_t new_vb;
            char *body;
            libcouchbase_size_t nbody;
            /* re-schedule command with new vbucket id */
            nr = libcouchbase_ringbuffer_read(&c->cmd_log, req.bytes, sizeof(req));
            assert(nr == sizeof(req));
            new_vb = vbucket_found_incorrect_master(c->instance->vbucket_config,
                                                    ntohs(req.request.vbucket),
                                                    c->index);
            req.request.vbucket = new_vb;
            req.request.opaque = ++c->instance->seqno;
            nbody = ntohl(req.request.bodylen);
            body = malloc(nbody);
            if (body == NULL) {
                libcouchbase_error_handler(c->instance, LIBCOUCHBASE_ENOMEM, NULL);
                return -1;
            }
            nr = libcouchbase_ringbuffer_read(&c->cmd_log, body, nbody);
            assert(nr == nbody);
            nr = libcouchbase_ringbuffer_read(&c->output_cookies, &ct, sizeof(ct));
            assert(nr == sizeof(ct));
            /* Preserve the cookie and timestamp for the command. This means
             * that the library will retry the command until its time will
             * out and the client will get LIBCOUCHBASE_ETIMEDOUT error in
             * command callback */
            libcouchbase_server_retry_packet(c, &ct, &req, sizeof(req));
            libcouchbase_server_write_packet(c, body, nbody);
            libcouchbase_server_end_packet(c);
            free(body);
        }
        break;
    }

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
    /*
    ** Loop and try to parse the data... We don't want to lock up the
    ** event loop completely, so set a max number of packets to process
    ** before backing off..
    */
    libcouchbase_size_t processed = 0;
    /* @todo Make the backoff number tunable from the instance */
    const libcouchbase_size_t operations_per_call = 1000;
    int rv = 0;
    /*
    ** The timers isn't supposed to be _that_ accurate.. it's better
    ** to shave off system calls :)
    */
    hrtime_t stop = gethrtime();

    while (processed < operations_per_call) {
        switch ((rv = parse_single(c, stop))) {
        case -1:
            return -1;
        case 0:
            /* need more data */
            if ((rv = do_fill_input_buffer(c)) < 1) {
                /* error or would block ;) */
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
        libcouchbase_ssize_t nw;
        libcouchbase_ringbuffer_get_iov(&c->output, RINGBUFFER_READ, iov);
        nw = c->instance->io->sendv(c->instance->io, c->sock, iov, 2);
        if (nw == -1) {
            switch (c->instance->io->error) {
            case EINTR:
                /* retry */
                break;
            case EWOULDBLOCK:
                return 0;
            default:
                libcouchbase_failout_server(c, LIBCOUCHBASE_NETWORK_ERROR);
                return -1;
            }
        } else {
            libcouchbase_ringbuffer_consumed(&c->output, (libcouchbase_size_t)nw);
        }
    } while (c->output.nbytes > 0);

    return 0;
}

LIBCOUCHBASE_API
void libcouchbase_flush_buffers(libcouchbase_t instance, const void* cookie)
{
    libcouchbase_size_t ii;
    for (ii = 0; ii < instance->nservers; ++ii) {
        libcouchbase_server_t *c = instance->servers + ii;
        if (c->connected) {
            libcouchbase_server_event_handler(c->sock,
                                              LIBCOUCHBASE_READ_EVENT | LIBCOUCHBASE_WRITE_EVENT,
                                              c);
        }
    }
    (void)cookie;
}

void libcouchbase_server_event_handler(libcouchbase_socket_t sock, short which, void *arg) {
    libcouchbase_server_t *c = arg;
    (void)sock;

    if (which & LIBCOUCHBASE_READ_EVENT) {
        if (do_read_data(c) != 0) {
            /* TODO stash error message somewhere
             * "Failed to read from connection to \"%s:%s\"", c->hostname, c->port */
            libcouchbase_failout_server(c, LIBCOUCHBASE_NETWORK_ERROR);
            return;
        }
    }

    if (which & LIBCOUCHBASE_WRITE_EVENT) {
        if (c->connected) {
            hrtime_t now = gethrtime();
            hrtime_t tmo = c->instance->timeout.usec;
            tmo *= 1000;
            if (c->next_timeout != 0 && (now > (tmo + c->next_timeout))) {
                libcouchbase_purge_single_server(c,
                                                 &c->cmd_log,
                                                 &c->output_cookies,
                                                 tmo, now,
                                                 LIBCOUCHBASE_ETIMEDOUT);
            }
        }

        if (do_send_data(c) != 0) {
            /* TODO stash error message somewhere
             * "Failed to send to the connection to \"%s:%s\"", c->hostname, c->port */
            libcouchbase_failout_server(c, LIBCOUCHBASE_NETWORK_ERROR);
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

    libcouchbase_maybe_breakout(c->instance);

    /* Make it known that this was a success. */
    libcouchbase_error_handler(c->instance, LIBCOUCHBASE_SUCCESS, NULL);
}

void libcouchbase_maybe_breakout(libcouchbase_t instance)
{
    if (instance->wait) {
        int done = 1;
        libcouchbase_size_t ii;
        for (ii = 0; ii < instance->nservers; ++ii) {
            libcouchbase_server_t *c = instance->servers + ii;
            if (c->cmd_log.nbytes || c->output.nbytes || c->input.nbytes ||
                    c->pending.nbytes) {
                done = 0;
                break;
            }
        }

        if (done) {
            instance->wait = 0;
            instance->io->stop_event_loop(instance->io);
        }
    }
}
