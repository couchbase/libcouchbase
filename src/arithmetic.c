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
#include "internal.h"

/**
 * Spool an arithmetic request
 *
 * @author Trond Norbye
 * @todo add documentation
 */
LIBMEMBASE_API
libmembase_error_t libmembase_arithmetic(libmembase_t instance,
                                         const void *key, size_t nkey,
                                         int64_t delta, time_t exp,
                                         bool create, uint64_t initial)
{
    // we need a vbucket config before we can start getting data..
    libmembase_ensure_vbucket_config(instance);
    assert(instance->vbucket_config);

    uint16_t vb;
    vb = (uint16_t)vbucket_get_vbucket_by_key(instance->vbucket_config,
                                              key, nkey);
    libmembase_server_t *server;
    server = instance->servers + instance->vb_server_map[vb];
    protocol_binary_request_incr req = {
        .message = {
            .header.request = {
                .magic = PROTOCOL_BINARY_REQ,
                .opcode = PROTOCOL_BINARY_CMD_INCREMENT,
                .keylen = ntohs((uint16_t)nkey),
                .extlen = 20,
                .datatype = PROTOCOL_BINARY_RAW_BYTES,
                .vbucket = ntohs(vb),
                .bodylen = ntohl((uint32_t)(nkey + 20)),
                .opaque = ++instance->seqno
            },
            .body = {
                .delta = ntohll((uint64_t)(delta)),
                .initial = ntohll(initial),
                .expiration = ntohl((uint32_t)exp)
            }
        }
    };

    if (delta < 0) {
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_DECREMENT;
        req.message.body.delta = ntohll((uint64_t)(delta * -1));
    }

    if (create) {
        memset(&req.message.body.expiration, 0xff,
               sizeof(req.message.body.expiration));
    }

    libmembase_server_start_packet(server, req.bytes, sizeof(req.bytes));
    libmembase_server_write_packet(server, key, nkey);
    libmembase_server_end_packet(server);
    libmembase_server_send_packets(server);

    return LIBMEMBASE_SUCCESS;
}
