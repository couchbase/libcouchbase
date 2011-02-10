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
 * This file contains the functions to tap the cluster
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

static void tap_vbucket_state_listener(libcouchbase_server_t *server)
{
    libcouchbase_t instance = server->instance;
    // Locate this index:
    size_t idx;
    for (idx = 0; idx < instance->nservers; ++idx) {
        if (server == instance->servers + idx) {
            break;
        }
    }
    assert(idx != instance->nservers);

    // Count the numbers of vbuckets for this server:
    uint16_t total = 0;
    for (int ii = 0; ii < instance->nvbuckets; ++ii) {
        if (instance->vb_server_map[ii] == idx) {
            ++total;
        }
    }

    size_t bodylen = (size_t)total * 2 + 6;
    protocol_binary_request_tap_connect req;
    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_TAP_CONNECT;
    req.message.header.request.extlen = 4;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = htonl((uint32_t)bodylen);
    req.message.body.flags = htonl(TAP_CONNECT_FLAG_LIST_VBUCKETS);

    libcouchbase_server_start_packet(server, req.bytes, sizeof(req.bytes));

    uint16_t val = htons(total);
    libcouchbase_server_write_packet(server, &val, sizeof(val));
    for (int ii = 0; ii < instance->nvbuckets; ++ii) {
        if (instance->vb_server_map[ii] == idx) {
            val = htons((uint16_t)ii);
            libcouchbase_server_write_packet(server, &val, sizeof(val));
        }
    }
    libcouchbase_server_end_packet(server);

    libcouchbase_server_send_packets(server);
}

LIBCOUCHBASE_API
void libcouchbase_tap_cluster(libcouchbase_t instance,
                              libcouchbase_tap_filter_t filter,
                              bool block)
{
    // connect to the upstream server.
    instance->vbucket_state_listener = tap_vbucket_state_listener;
    instance->tap.filter = filter;

    /* Start the event loop and dump everything */
    if (block) {
        event_base_loop(instance->ev_base, 0);
    }
}
