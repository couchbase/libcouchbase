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

static int do_fill_input_buffer(lcb_server_t *c)
{
    struct lcb_iovec_st iov[2];
    lcb_ssize_t nr;

    if (!ringbuffer_ensure_capacity(&c->input, 8192)) {
        lcb_error_handler(c->instance, LCB_CLIENT_ENOMEM, NULL);
        return -1;
    }

    ringbuffer_get_iov(&c->input, RINGBUFFER_WRITE, iov);

    nr = c->instance->io->v.v0.recvv(c->instance->io, c->sock, iov, 2);
    if (nr == -1) {
        switch (c->instance->io->v.v0.error) {
        case EINTR:
            break;
        case EWOULDBLOCK:
            return 0;
        default:
            lcb_failout_server(c, LCB_NETWORK_ERROR);
            return -1;
        }
    } else if (nr == 0) {
        assert((iov[0].iov_len + iov[1].iov_len) != 0);
        /* TODO stash error message somewhere
         * "Connection closed... we should resend to other nodes or reconnect!!" */
        lcb_failout_server(c, LCB_NETWORK_ERROR);
        return -1;
    } else {
        ringbuffer_produced(&c->input, (lcb_size_t)nr);
    }

    return 1;
}

static int parse_single(lcb_server_t *c, hrtime_t stop)
{
    protocol_binary_request_header req;
    protocol_binary_response_header header;
    lcb_size_t nr;
    char *packet;
    lcb_size_t packetsize;
    struct lcb_command_data_st ct;

    if (ringbuffer_ensure_alignment(&c->input) != 0) {
        lcb_error_handler(c->instance, LCB_EINTERNAL,
                          NULL);
        return -1;
    }

    nr = ringbuffer_peek(&c->input, header.bytes, sizeof(header));
    if (nr < sizeof(header)) {
        return 0;
    }

    packetsize = ntohl(header.response.bodylen) + (lcb_uint32_t)sizeof(header);
    if (c->input.nbytes < packetsize) {
        return 0;
    }

    /* Is it already timed out? */
    nr = ringbuffer_peek(&c->cmd_log, req.bytes, sizeof(req));
    if (nr < sizeof(req) || /* the command log doesn't know about it */
            (header.response.opaque < req.request.opaque &&
             header.response.opaque > 0)) { /* sasl comes with zero opaque */
        /* already processed. */
        ringbuffer_consumed(&c->input, packetsize);
        return 1;
    }

    packet = c->input.read_head;
    /* we have everything! */

    if (!ringbuffer_is_continous(&c->input, RINGBUFFER_READ,
                                 packetsize)) {
        /* The buffer isn't continous.. for now just copy it out and
        ** operate on the copy ;)
        */
        if ((packet = malloc(packetsize)) == NULL) {
            lcb_error_handler(c->instance, LCB_CLIENT_ENOMEM, NULL);
            return -1;
        }
        nr = ringbuffer_read(&c->input, packet, packetsize);
        if (nr != packetsize) {
            lcb_error_handler(c->instance, LCB_EINTERNAL,
                              NULL);
            free(packet);
            return -1;
        }
    }

    nr = ringbuffer_peek(&c->output_cookies, &ct, sizeof(ct));
    if (nr != sizeof(ct)) {
        lcb_error_handler(c->instance, LCB_EINTERNAL,
                          NULL);
        if (packet != c->input.read_head) {
            free(packet);
        }
        return -1;
    }
    ct.vbucket = ntohs(req.request.vbucket);

    switch (header.response.magic) {
    case PROTOCOL_BINARY_REQ:
        c->instance->request_handler[header.response.opcode](c, &ct, (void *)packet);
        break;
    case PROTOCOL_BINARY_RES: {
        int was_connected = c->connected;
        if (lcb_server_purge_implicit_responses(c, header.response.opaque, stop) != 0) {
            if (packet != c->input.read_head) {
                free(packet);
            }
            return -1;
        }

        if (c->instance->histogram) {
            lcb_record_metrics(c->instance, stop - ct.start,
                               header.response.opcode);
        }

        if (ntohs(header.response.status) != PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET
                || header.response.opcode == CMD_GET_REPLICA) {
            c->instance->response_handler[header.response.opcode](c, &ct, (void *)packet);
            /* keep command and cookie until we get complete STAT response */
            if (was_connected &&
                    (header.response.opcode != PROTOCOL_BINARY_CMD_STAT || header.response.keylen == 0)) {
                nr = ringbuffer_read(&c->cmd_log, req.bytes, sizeof(req));
                assert(nr == sizeof(req));
                ringbuffer_consumed(&c->cmd_log, ntohl(req.request.bodylen));
                ringbuffer_consumed(&c->output_cookies, sizeof(ct));
            }
        } else {
            int idx;
            char *body;
            lcb_size_t nbody;
            lcb_server_t *new_srv;
            /* re-schedule command to new server */
            nr = ringbuffer_read(&c->cmd_log, req.bytes, sizeof(req));
            assert(nr == sizeof(req));
            idx = vbucket_found_incorrect_master(c->instance->vbucket_config,
                                                 ntohs(req.request.vbucket),
                                                 (int)c->index);
            assert((lcb_size_t)idx < c->instance->nservers);
            new_srv = c->instance->servers + idx;
            req.request.opaque = ++c->instance->seqno;
            nbody = ntohl(req.request.bodylen);
            body = malloc(nbody);
            if (body == NULL) {
                lcb_error_handler(c->instance, LCB_CLIENT_ENOMEM, NULL);
                return -1;
            }
            nr = ringbuffer_read(&c->cmd_log, body, nbody);
            assert(nr == nbody);
            nr = ringbuffer_read(&c->output_cookies, &ct, sizeof(ct));
            assert(nr == sizeof(ct));
            /* Preserve the cookie and reset timestamp for the command. This
             * means that the library will retry the command until it will
             * get code different from LCB_NOT_MY_VBUCKET */
            ct.start = gethrtime();
            lcb_server_retry_packet(new_srv, &ct, &req, sizeof(req));
            lcb_server_write_packet(new_srv, body, nbody);
            lcb_server_end_packet(new_srv);
            lcb_server_send_packets(new_srv);
            free(body);
        }
        break;
    }

    default:
        lcb_error_handler(c->instance,
                          LCB_PROTOCOL_ERROR,
                          NULL);
        if (packet != c->input.read_head) {
            free(packet);
        }
        return -1;
    }

    if (packet != c->input.read_head) {
        free(packet);
    } else {
        ringbuffer_consumed(&c->input, packetsize);
    }
    return 1;
}


static int do_read_data(lcb_server_t *c)
{
    /*
    ** Loop and try to parse the data... We don't want to lock up the
    ** event loop completely, so set a max number of packets to process
    ** before backing off..
    */
    lcb_size_t processed = 0;
    /* @todo Make the backoff number tunable from the instance */
    const lcb_size_t operations_per_call = 1000;
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

static int do_send_data(lcb_server_t *c)
{
    do {
        struct lcb_iovec_st iov[2];
        lcb_ssize_t nw;
        ringbuffer_get_iov(&c->output, RINGBUFFER_READ, iov);
        nw = c->instance->io->v.v0.sendv(c->instance->io, c->sock, iov, 2);
        if (nw == -1) {
            switch (c->instance->io->v.v0.error) {
            case EINTR:
                /* retry */
                break;
            case EWOULDBLOCK:
                return 0;
            default:
                lcb_failout_server(c, LCB_NETWORK_ERROR);
                return -1;
            }
        } else {
            ringbuffer_consumed(&c->output, (lcb_size_t)nw);
        }
    } while (c->output.nbytes > 0);

    return 0;
}

LIBCOUCHBASE_API
void lcb_flush_buffers(lcb_t instance, const void *cookie)
{
    lcb_size_t ii;
    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t *c = instance->servers + ii;
        if (c->connected) {
            lcb_server_event_handler(c->sock,
                                     LCB_READ_EVENT | LCB_WRITE_EVENT,
                                     c);
        }
    }
    (void)cookie;
}

void lcb_server_event_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_server_t *c = arg;
    (void)sock;

    lcb_update_server_timer(c);
    if (which & LCB_READ_EVENT) {
        if (do_read_data(c) != 0) {
            /* TODO stash error message somewhere
             * "Failed to read from connection to \"%s:%s\"", c->hostname, c->port */
            lcb_failout_server(c, LCB_NETWORK_ERROR);
            return;
        }
    }

    if (which & LCB_WRITE_EVENT) {
        if (do_send_data(c) != 0) {
            /* TODO stash error message somewhere
             * "Failed to send to the connection to \"%s:%s\"", c->hostname, c->port */
            lcb_failout_server(c, LCB_NETWORK_ERROR);
            return;
        }
    }

    if (c->output.nbytes == 0) {
        c->instance->io->v.v0.update_event(c->instance->io, c->sock,
                                           c->event, LCB_READ_EVENT,
                                           c, lcb_server_event_handler);
    } else {
        c->instance->io->v.v0.update_event(c->instance->io, c->sock,
                                           c->event, LCB_RW_EVENT,
                                           c, lcb_server_event_handler);
    }

    lcb_maybe_breakout(c->instance);

    /* Make it known that this was a success. */
    lcb_error_handler(c->instance, LCB_SUCCESS, NULL);
}

int lcb_has_data_in_buffers(lcb_t instance)
{
    lcb_size_t ii;

    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t *c = instance->servers + ii;
        if (c->cmd_log.nbytes || c->output.nbytes || c->input.nbytes ||
                c->pending.nbytes || hashset_num_items(c->http_requests)) {
            return 1;
        }
    }
    return 0;
}

void lcb_maybe_breakout(lcb_t instance)
{
    if (instance->wait) {
        if (!lcb_has_data_in_buffers(instance)
                && hashset_num_items(instance->timers) == 0) {
            instance->wait = 0;
            instance->io->v.v0.stop_event_loop(instance->io);
        }
    }
}
