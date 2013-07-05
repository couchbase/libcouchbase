/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2013 Couchbase, Inc.
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
 * This file contains the functions to operate on libembase_server objects
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

void lcb_failout_observe_request(lcb_server_t *server,
                                 struct lcb_command_data_st *command_data,
                                 const char *packet,
                                 lcb_size_t npacket,
                                 lcb_error_t err)
{
    lcb_t instance = server->instance;
    protocol_binary_request_header *req = (void *)packet;
    const char *ptr = packet + sizeof(req->bytes);
    const char *end = packet + npacket;
    lcb_observe_resp_t resp;

    memset(&resp, 0, sizeof(resp));
    resp.v.v0.status = LCB_OBSERVE_MAX;
    while (ptr < end) {
        lcb_uint16_t nkey;

        /* ignore vbucket */
        ptr += sizeof(lcb_uint16_t);
        memcpy(&nkey, ptr, sizeof(nkey));
        nkey = ntohs(nkey);

        ptr += sizeof(lcb_uint16_t);
        resp.v.v0.key = ptr;
        resp.v.v0.nkey = nkey;

        TRACE_OBSERVE_PROGRESS(req->request.opaque, ntohs(req->request.vbucket),
                               req->request.opcode, err, &resp);
        instance->callbacks.observe(instance, command_data->cookie,
                                    err, &resp);
        ptr += nkey;
    }
    if (lcb_lookup_server_with_command(instance, CMD_OBSERVE,
                                       req->request.opaque, server) < 0) {
        TRACE_OBSERVE_END(req->request.opaque, ntohs(req->request.vbucket),
                          req->request.opcode, err);
        resp.v.v0.key = NULL;
        resp.v.v0.nkey = 0;
        instance->callbacks.observe(instance, command_data->cookie, err, &resp);
    }
}


void lcb_purge_single_server(lcb_server_t *server,
                             lcb_error_t error)
{
    protocol_binary_request_header req;
    struct lcb_command_data_st ct;
    lcb_size_t nr;
    char *packet;
    lcb_size_t packetsize;
    char *keyptr;
    lcb_t root = server->instance;
    ringbuffer_t rest;
    ringbuffer_t *stream = &server->cmd_log;
    ringbuffer_t *cookies;
    ringbuffer_t *mirror = NULL; /* mirror buffer should be purged with main stream */
    lcb_connection_t conn = &server->connection;
    lcb_size_t send_size = ringbuffer_get_nbytes(conn->output);
    lcb_size_t stream_size = ringbuffer_get_nbytes(stream);
    hrtime_t now = gethrtime();
    int should_switch_to_backup_node = 0;

    if (server->connection_ready) {
        cookies = &server->output_cookies;
    } else {
        cookies = &server->pending_cookies;
        mirror = &server->pending;
    }

    lcb_assert(ringbuffer_initialize(&rest, 1024));

    do {
        int allocated = 0;
        lcb_uint32_t headersize;
        lcb_uint16_t nkey;
        union {
            lcb_get_resp_t get;
            lcb_store_resp_t store;
            lcb_remove_resp_t remove;
            lcb_touch_resp_t touch;
            lcb_unlock_resp_t unlock;
            lcb_arithmetic_resp_t arithmetic;
            lcb_observe_resp_t observe;
            lcb_server_stat_resp_t stats;
            lcb_server_version_resp_t versions;
            lcb_verbosity_resp_t verbosity;
            lcb_flush_resp_t flush;
        } resp;

        nr = ringbuffer_peek(cookies, &ct, sizeof(ct));
        if (nr != sizeof(ct)) {
            break;
        }
        nr = ringbuffer_peek(stream, req.bytes, sizeof(req));
        if (nr != sizeof(req)) {
            break;
        }
        packetsize = (lcb_uint32_t)sizeof(req) + ntohl(req.request.bodylen);
        if (stream->nbytes < packetsize) {
            break;
        }

        ringbuffer_consumed(cookies, sizeof(ct));

        lcb_assert(nr == sizeof(req));
        packet = stream->read_head;

        if (server->instance->histogram) {
            lcb_record_metrics(server->instance, now - ct.start,
                               req.request.opcode);
        }

        if (server->connection_ready &&
                stream_size > send_size && (stream_size - packetsize) < send_size) {
            /* Copy the rest of the current packet into the
               temporary stream */

            /* I do believe I have some IOV functions to do that? */
            lcb_size_t nbytes = packetsize - (stream_size - send_size);
            lcb_assert(ringbuffer_memcpy(&rest,
                                         conn->output,
                                         nbytes) == 0);
            ringbuffer_consumed(conn->output, nbytes);
            send_size -= nbytes;
        }
        stream_size -= packetsize;
        headersize = (lcb_uint32_t)sizeof(req) + req.request.extlen + htons(req.request.keylen);
        if (!ringbuffer_is_continous(stream, RINGBUFFER_READ, headersize)) {
            packet = malloc(headersize);
            if (packet == NULL) {
                lcb_error_handler(server->instance, LCB_CLIENT_ENOMEM, NULL);
                abort();
            }

            nr = ringbuffer_peek(stream, packet, headersize);
            if (nr != headersize) {
                lcb_error_handler(server->instance, LCB_EINTERNAL, NULL);
                free(packet);
                abort();
            }
            allocated = 1;
        }

        keyptr = packet + sizeof(req) + req.request.extlen;
        nkey = ntohs(req.request.keylen);

        /* It would have been awesome if we could have a generic error */
        /* handler we could call */
        switch (req.request.opcode) {
        case PROTOCOL_BINARY_CMD_NOOP:
            break;
        case PROTOCOL_BINARY_CMD_GAT:
        case PROTOCOL_BINARY_CMD_GATQ:
        case PROTOCOL_BINARY_CMD_GET:
        case PROTOCOL_BINARY_CMD_GETQ:
            setup_lcb_get_resp_t(&resp.get, keyptr, nkey, NULL, 0, 0, 0, 0);
            TRACE_GET_END(req.request.opaque, ntohs(req.request.vbucket),
                          req.request.opcode, error, &resp.get);
            root->callbacks.get(root, ct.cookie, error, &resp.get);
            break;
        case PROTOCOL_BINARY_CMD_FLUSH:
            setup_lcb_flush_resp_t(&resp.flush, server->authority);
            TRACE_FLUSH_PROGRESS(req.request.opaque, ntohs(req.request.vbucket),
                                 req.request.opcode, error, &resp.flush);
            root->callbacks.flush(root, ct.cookie, error, &resp.flush);
            if (lcb_lookup_server_with_command(root,
                                               PROTOCOL_BINARY_CMD_FLUSH,
                                               req.request.opaque,
                                               server) < 0) {
                setup_lcb_flush_resp_t(&resp.flush, NULL);
                TRACE_FLUSH_END(req.request.opaque, ntohs(req.request.vbucket),
                                req.request.opcode, error);
                root->callbacks.flush(root, ct.cookie, error, &resp.flush);
            }
            break;
        case PROTOCOL_BINARY_CMD_ADD:
            setup_lcb_store_resp_t(&resp.store, keyptr, nkey, 0);
            TRACE_STORE_END(req.request.opaque, ntohs(req.request.vbucket),
                            req.request.opcode, error, &resp.store);
            root->callbacks.store(root, ct.cookie, LCB_ADD, error, &resp.store);
            break;
        case PROTOCOL_BINARY_CMD_REPLACE:
            setup_lcb_store_resp_t(&resp.store, keyptr, nkey, 0);
            TRACE_STORE_END(req.request.opaque, ntohs(req.request.vbucket),
                            req.request.opcode, error, &resp.store);
            root->callbacks.store(root, ct.cookie, LCB_REPLACE, error,
                                  &resp.store);
            break;
        case PROTOCOL_BINARY_CMD_SET:
            setup_lcb_store_resp_t(&resp.store, keyptr, nkey, 0);
            TRACE_STORE_END(req.request.opaque, ntohs(req.request.vbucket),
                            req.request.opcode, error, &resp.store);
            root->callbacks.store(root, ct.cookie, LCB_SET, error, &resp.store);
            break;
        case PROTOCOL_BINARY_CMD_APPEND:
            setup_lcb_store_resp_t(&resp.store, keyptr, nkey, 0);
            TRACE_STORE_END(req.request.opaque, ntohs(req.request.vbucket),
                            req.request.opcode, error, &resp.store);
            root->callbacks.store(root, ct.cookie, LCB_APPEND, error,
                                  &resp.store);
            break;
        case PROTOCOL_BINARY_CMD_PREPEND:
            setup_lcb_store_resp_t(&resp.store, keyptr, nkey, 0);
            TRACE_STORE_END(req.request.opaque, ntohs(req.request.vbucket),
                            req.request.opcode, error, &resp.store);
            root->callbacks.store(root, ct.cookie, LCB_PREPEND, error,
                                  &resp.store);
            break;
        case PROTOCOL_BINARY_CMD_DELETE:
            setup_lcb_remove_resp_t(&resp.remove, keyptr, nkey, 0);
            TRACE_REMOVE_END(req.request.opaque, ntohs(req.request.vbucket),
                             req.request.opcode, error, &resp.remove);
            root->callbacks.remove(root, ct.cookie, error, &resp.remove);
            break;

        case PROTOCOL_BINARY_CMD_INCREMENT:
        case PROTOCOL_BINARY_CMD_DECREMENT:
            setup_lcb_arithmetic_resp_t(&resp.arithmetic, keyptr, nkey, 0, 0);
            TRACE_ARITHMETIC_END(req.request.opaque, ntohs(req.request.vbucket),
                                 req.request.opcode, error, &resp.arithmetic);
            root->callbacks.arithmetic(root, ct.cookie, error,
                                       &resp.arithmetic);
            break;
        case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS:
        case PROTOCOL_BINARY_CMD_SASL_AUTH:
        case PROTOCOL_BINARY_CMD_SASL_STEP:
            /* no need to notify user about these commands */
            break;

        case PROTOCOL_BINARY_CMD_TOUCH:
            setup_lcb_touch_resp_t(&resp.touch, keyptr, nkey, 0);
            TRACE_TOUCH_END(req.request.opaque, ntohs(req.request.vbucket),
                            req.request.opcode, error, &resp.touch);
            root->callbacks.touch(root, ct.cookie, error, &resp.touch);
            break;

        case PROTOCOL_BINARY_CMD_STAT:
            setup_lcb_server_stat_resp_t(&resp.stats, server->authority,
                                         NULL, 0, NULL, 0);
            TRACE_STATS_PROGRESS(req.request.opaque, ntohs(req.request.vbucket),
                                 req.request.opcode, error, &resp.stats);
            root->callbacks.stat(root, ct.cookie, error, &resp.stats);

            if (lcb_lookup_server_with_command(root,
                                               PROTOCOL_BINARY_CMD_STAT,
                                               req.request.opaque,
                                               server) < 0) {
                setup_lcb_server_stat_resp_t(&resp.stats,
                                             NULL, NULL, 0, NULL, 0);
                TRACE_STATS_END(req.request.opaque, ntohs(req.request.vbucket),
                                req.request.opcode, error);
                root->callbacks.stat(root, ct.cookie, error, &resp.stats);
            }
            break;

        case PROTOCOL_BINARY_CMD_VERBOSITY:
            setup_lcb_verbosity_resp_t(&resp.verbosity, server->authority);
            TRACE_VERBOSITY_END(req.request.opaque, ntohs(req.request.vbucket),
                                req.request.opcode, error, &resp.verbosity);
            root->callbacks.verbosity(root, ct.cookie, error, &resp.verbosity);

            if (lcb_lookup_server_with_command(root,
                                               PROTOCOL_BINARY_CMD_VERBOSITY,
                                               req.request.opaque,
                                               server) < 0) {
                setup_lcb_verbosity_resp_t(&resp.verbosity, NULL);
                TRACE_VERBOSITY_END(req.request.opaque, ntohs(req.request.vbucket),
                                    req.request.opcode, error, &resp.verbosity);
                root->callbacks.verbosity(root, ct.cookie, error, &resp.verbosity);
            }
            break;

        case PROTOCOL_BINARY_CMD_VERSION:
            setup_lcb_server_version_resp_t(&resp.versions, server->authority,
                                            NULL, 0);
            TRACE_VERSIONS_PROGRESS(req.request.opaque, ntohs(req.request.vbucket),
                                    req.request.opcode, error, &resp.versions);
            root->callbacks.version(root, ct.cookie, error, &resp.versions);
            if (lcb_lookup_server_with_command(root,
                                               PROTOCOL_BINARY_CMD_VERSION,
                                               req.request.opaque,
                                               server) < 0) {
                TRACE_VERSIONS_END(req.request.opaque, ntohs(req.request.vbucket),
                                   req.request.opcode, error);
                setup_lcb_server_version_resp_t(&resp.versions, NULL, NULL, 0);
                root->callbacks.version(root, ct.cookie, error, &resp.versions);
            }
            break;

        case CMD_OBSERVE:
            lcb_failout_observe_request(server, &ct, packet,
                                        sizeof(req.bytes) + ntohl(req.request.bodylen),
                                        error);
            break;

        default:
            abort();
        }

        if (allocated) {
            free(packet);
        }

        ringbuffer_consumed(stream, packetsize);
        if (mirror) {
            ringbuffer_consumed(mirror, packetsize);
        }
        if (server->is_config_node) {
            root->weird_things++;
            if (root->weird_things >= root->weird_things_threshold) {
                should_switch_to_backup_node = 1;
            }
        }
    } while (1); /* CONSTCOND */

    if (server->connection_ready) {
        /* Preserve the rest of the stream */
        lcb_size_t nbytes = ringbuffer_get_nbytes(stream);
        send_size = ringbuffer_get_nbytes(conn->output);

        if (send_size >= nbytes) {
            ringbuffer_consumed(conn->output, send_size - nbytes);
            lcb_assert(ringbuffer_memcpy(&rest, conn->output, nbytes) == 0);
        }
        ringbuffer_reset(conn->output);
        ringbuffer_append(&rest, conn->output);
    }

    ringbuffer_destruct(&rest);
    if (should_switch_to_backup_node) {
        lcb_switch_to_backup_node(root, LCB_NETWORK_ERROR,
                                  "Config connection considered stale. "
                                  "Reconnection forced");
    }
    lcb_maybe_breakout(server->instance);
}

lcb_error_t lcb_failout_server(lcb_server_t *server,
                               lcb_error_t error)
{
    lcb_purge_single_server(server, error);
    ringbuffer_reset(&server->cmd_log);
    ringbuffer_reset(&server->output_cookies);
    ringbuffer_reset(&server->pending);
    ringbuffer_reset(&server->pending_cookies);

    server->connection_ready = 0;
    lcb_connection_close(&server->connection);
    return error;
}

static void purge_http_request(lcb_server_t *server)
{
    lcb_size_t ii;
    lcb_http_request_t *htitems;
    lcb_size_t curix;
    lcb_size_t nitems = hashset_num_items(server->http_requests);
    htitems = malloc(nitems * sizeof(*htitems));

    for (curix = 0, ii = 0; ii < server->http_requests->capacity; ii++) {
        if (server->http_requests->items[ii] > 1) {
            htitems[curix] = (lcb_http_request_t)server->http_requests->items[ii];
            curix++;
        }
    }

    lcb_assert(curix);

    for (ii = 0; ii < curix; ii++) {
        lcb_http_request_finish(server->instance,
                                server,
                                htitems[ii],
                                LCB_ETMPFAIL);
    }

    free(htitems);
}

/**
 * Release all allocated resources for this server instance
 * @param server the server to destroy
 */
void lcb_server_destroy(lcb_server_t *server)
{
    /* Cancel all pending commands */
    if (server->cmd_log.nbytes) {
        lcb_server_purge_implicit_responses(server,
                                            server->instance->seqno,
                                            gethrtime(),
                                            1);
    }

    if (server->sasl_conn != NULL) {
        sasl_dispose(&server->sasl_conn);
        server->sasl_conn = NULL;
    }

    /* Delete the event structure itself */
    lcb_connection_cleanup(&server->connection);

    free(server->rest_api_server);
    free(server->couch_api_base);
    free(server->authority);
    ringbuffer_destruct(&server->output_cookies);
    ringbuffer_destruct(&server->cmd_log);
    ringbuffer_destruct(&server->pending);
    ringbuffer_destruct(&server->pending_cookies);

    if (hashset_num_items(server->http_requests)) {
        purge_http_request(server);
    }

    hashset_destroy(server->http_requests);
    memset(server, 0xff, sizeof(*server));
}


/**
 * Start the SASL auth for a given server.
 *
 * Neither the server or the client supports anything else than
 * plain SASL authentication, so lets just try it. If someone change
 * the list of supported SASL mechanisms they need to update the client
 * anyway.
 *
 * @param server the server object to auth agains
 */

void lcb_server_connected(lcb_server_t *server)
{
    lcb_connection_t conn = &server->connection;
    server->connection_ready = 1;

    if (server->pending.nbytes > 0) {
        /*
        ** @todo we might want to do this a bit more optimal later on..
        **       We're only using the pending ringbuffer while we're
        **       doing the SASL auth, so it shouldn't contain that
        **       much data..
        */
        ringbuffer_t copy = server->pending;
        ringbuffer_reset(&server->cmd_log);
        ringbuffer_reset(&server->output_cookies);
        ringbuffer_reset(conn->output);
        if (!ringbuffer_append(&server->pending, conn->output) ||
                !ringbuffer_append(&server->pending_cookies, &server->output_cookies) ||
                !ringbuffer_append(&copy, &server->cmd_log)) {

            lcb_error_handler(server->instance,
                              LCB_CLIENT_ENOMEM,
                              NULL);
        }

        ringbuffer_reset(&server->pending);
        ringbuffer_reset(&server->pending_cookies);
        assert(conn->output->nbytes);
        lcb_server_send_packets(server);
    }
}

void lcb_server_initialize(lcb_server_t *server, int servernum)
{
    /* Initialize all members */
    char *p;
    const char *n = vbucket_config_get_server(server->instance->vbucket_config,
                                              servernum);

    lcb_connection_init(&server->connection, server->instance);

    server->connection.data = server;

    server->index = servernum;
    server->authority = strdup(n);
    strcpy(server->connection.host, n);
    p = strchr(server->connection.host, ':');
    *p = '\0';
    strcpy(server->connection.port, p+1);

    server->is_config_node = vbucket_config_is_config_node(server->instance->vbucket_config,
                                                           servernum);
    n = vbucket_config_get_couch_api_base(server->instance->vbucket_config,
                                          servernum);
    server->couch_api_base = (n != NULL) ? strdup(n) : NULL;
    server->http_requests = hashset_create();
    n = vbucket_config_get_rest_api_server(server->instance->vbucket_config,
                                           servernum);
    server->rest_api_server = strdup(n);

    lcb_connection_getaddrinfo(&server->connection, 0);

    server->sasl_conn = NULL;
}

void lcb_server_send_packets(lcb_server_t *server)
{
    if (server->pending.nbytes > 0 || server->connection.output->nbytes > 0) {
        if (server->connection_ready) {
            lcb_sockrw_set_want(&server->connection, LCB_RW_EVENT, 0);
            if (!server->inside_handler) {
                lcb_sockrw_apply_want(&server->connection);
            }

        } else if (server->connection.state == LCB_CONNSTATE_UNINIT) {
            lcb_server_connect(server);
        }
    }
}

/*
 * Drop all packets with sequence number less than specified.
 *
 * The packets are considered as stale and the caller will receive
 * appropriate error code in the operation callback.
 *
 * Returns 0 on success
 */
int lcb_server_purge_implicit_responses(lcb_server_t *c,
                                        lcb_uint32_t seqno,
                                        hrtime_t end,
                                        int all)
{
    protocol_binary_request_header req;
    lcb_size_t nr =  ringbuffer_peek(&c->cmd_log, req.bytes, sizeof(req));
    /* There should at _LEAST_ be _ONE_ message in here if we're not
     * trying to purge _ALL_ of the messages in the queue
     */
    if (all && nr == 0) {
        return 0;
    }
    lcb_assert(nr == sizeof(req));
    while (req.request.opaque < seqno) {
        struct lcb_command_data_st ct;
        char *packet = c->cmd_log.read_head;
        lcb_size_t packetsize = ntohl(req.request.bodylen) + (lcb_uint32_t)sizeof(req);
        char *keyptr;
        union {
            lcb_get_resp_t get;
            lcb_store_resp_t store;
            lcb_remove_resp_t remove;
            lcb_touch_resp_t touch;
            lcb_unlock_resp_t unlock;
            lcb_arithmetic_resp_t arithmetic;
            lcb_observe_resp_t observe;
        } resp;
        nr = ringbuffer_read(&c->output_cookies, &ct, sizeof(ct));
        lcb_assert(nr == sizeof(ct));

        if (c->instance->histogram) {
            lcb_record_metrics(c->instance, end - ct.start, req.request.opcode);
        }

        if (!ringbuffer_is_continous(&c->cmd_log, RINGBUFFER_READ, packetsize)) {
            packet = malloc(packetsize);
            if (packet == NULL) {
                lcb_error_handler(c->instance, LCB_CLIENT_ENOMEM, NULL);
                return -1;
            }

            nr = ringbuffer_peek(&c->cmd_log, packet, packetsize);
            if (nr != packetsize) {
                lcb_error_handler(c->instance, LCB_EINTERNAL, NULL);
                free(packet);
                return -1;
            }
        }

        switch (req.request.opcode) {
        case PROTOCOL_BINARY_CMD_GATQ:
        case PROTOCOL_BINARY_CMD_GETQ:
            keyptr = packet + sizeof(req) + req.request.extlen;
            setup_lcb_get_resp_t(&resp.get, keyptr, ntohs(req.request.keylen),
                                 NULL, 0, 0, 0, 0);
            TRACE_GET_END(req.request.opaque, ntohs(req.request.vbucket),
                          req.request.opcode, LCB_KEY_ENOENT, &resp.get);
            c->instance->callbacks.get(c->instance, ct.cookie, LCB_KEY_ENOENT, &resp.get);
            break;
        case CMD_OBSERVE:
            lcb_failout_observe_request(c, &ct, packet,
                                        sizeof(req.bytes) + ntohl(req.request.bodylen),
                                        LCB_SERVER_BUG);
            break;
        case PROTOCOL_BINARY_CMD_NOOP:
            break;
        default: {
            char errinfo[128] = { '\0' };
            snprintf(errinfo, 128, "Unknown implicit send message op=%0x", req.request.opcode);
            lcb_error_handler(c->instance, LCB_EINTERNAL, errinfo);
            return -1;
        }
        }

        if (packet != c->cmd_log.read_head) {
            free(packet);
        }
        ringbuffer_consumed(&c->cmd_log, packetsize);
        nr =  ringbuffer_peek(&c->cmd_log, req.bytes, sizeof(req));
        /* The current message should also be there (unless we tried to
         * purge _all_ of them
         */
        if (all && nr == 0) {
            return 0;
        }
        lcb_assert(nr == sizeof(req));
    }

    return 0;
}
