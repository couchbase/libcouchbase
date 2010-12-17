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
 * libmembase_mget use the GETQ command followed by a NOOP command to avoid
 * transferring not-found responses. All of the not-found callbacks are
 * generated implicit by receiving a successful get or the NOOP.
 *
 * @author Trond Norbye
 * @todo improve the error handling
 */
LIBMEMBASE_API
libmembase_error_t libmembase_mget(libmembase_t instance,
                                   size_t num_keys,
                                   const void * const *keys,
                                   const size_t *nkey)
{
    // we need a vbucket config before we can start getting data..
    libmembase_ensure_vbucket_config(instance);
    assert(instance->vbucket_config);

    for (size_t ii = 0; ii < num_keys; ++ii) {
        uint16_t vb;
        vb = (uint16_t)vbucket_get_vbucket_by_key(instance->vbucket_config,
                                                  keys[ii], nkey[ii]);
        libmembase_server_t *server;
        server = instance->servers + instance->vb_server_map[vb];
        protocol_binary_request_get req = {
            .message.header.request = {
                .magic = PROTOCOL_BINARY_REQ,
                .opcode = PROTOCOL_BINARY_CMD_GETQ,
                .keylen = ntohs((uint16_t)nkey[ii]),
                .datatype = PROTOCOL_BINARY_RAW_BYTES,
                .vbucket = ntohs(vb),
                .bodylen = ntohl((uint32_t)(nkey[ii])),
                .opaque = ++instance->seqno
            }
        };
        grow_buffer(&server->output, sizeof(req.bytes) + nkey[ii]);
        memcpy(server->output.data + server->output.avail,
               &req, sizeof(req.bytes));
        server->output.avail += sizeof(req.bytes);
        memcpy(server->output.data + server->output.avail,
               keys[ii], nkey[ii]);
        server->output.avail += nkey[ii];
    }

    for (size_t ii = 0; ii < instance->nservers; ++ii) {
        libmembase_server_t *server = instance->servers + ii;
        if (server->output.avail > 0) {
            protocol_binary_request_noop req = {
                .message.header.request = {
                    .magic = PROTOCOL_BINARY_REQ,
                    .opcode = PROTOCOL_BINARY_CMD_NOOP,
                    .datatype = PROTOCOL_BINARY_RAW_BYTES,
                    .opaque = ++instance->seqno
                }
            };
            grow_buffer(&server->output, sizeof(req.bytes));
            memcpy(server->output.data + server->output.avail,
                   &req, sizeof(req.bytes));
            server->output.avail += sizeof(req.bytes);
            libmembase_server_event_handler(0, EV_WRITE, server);
        }
    }

    return LIBMEMBASE_SUCCESS;
}
