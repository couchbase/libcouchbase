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
 * This file contains the functions to tap the cluster
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

static void tap_vbucket_state_listener(libmembase_server_t *server)
{
    libmembase_t instance = server->instance;
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
    protocol_binary_request_tap_connect req = {
        .message = {
            .header.request = {
                .magic = PROTOCOL_BINARY_REQ,
                .opcode = PROTOCOL_BINARY_CMD_TAP_CONNECT,
                .extlen = 4,
                .datatype = PROTOCOL_BINARY_RAW_BYTES,
                .bodylen = htonl((uint32_t)bodylen)
            },
            .body = {
                .flags = htonl(TAP_CONNECT_FLAG_LIST_VBUCKETS)
            }
        }
    };

    libmembase_server_start_packet(server, req.bytes, sizeof(req.bytes));

    uint16_t val = htons(total);
    libmembase_server_write_packet(server, &val, sizeof(val));
    for (int ii = 0; ii < instance->nvbuckets; ++ii) {
        if (instance->vb_server_map[ii] == idx) {
            val = htons((uint16_t)ii);
            libmembase_server_write_packet(server, &val, sizeof(val));
        }
    }
    libmembase_server_end_packet(server);

    libmembase_server_send_packets(server);
}

LIBMEMBASE_API
void libmembase_tap_cluster(libmembase_t instance,
                            libmembase_tap_filter_t filter,
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
