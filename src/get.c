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

#include "internal.h"

/**
 * libcouchbase_mget use the GETQ command followed by a NOOP command to avoid
 * transferring not-found responses. All of the not-found callbacks are
 * generated implicit by receiving a successful get or the NOOP.
 *
 * @author Trond Norbye
 * @todo improve the error handling
 */
LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_mget(libcouchbase_t instance,
                                       size_t num_keys,
                                       const void * const *keys,
                                       const size_t *nkey)
{
    return libcouchbase_mget_by_key(instance, NULL, 0, num_keys, keys, nkey);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_mget_by_key(libcouchbase_t instance,
                                              const void *hashkey,
                                              size_t nhashkey,
                                              size_t num_keys,
                                              const void * const *keys,
                                              const size_t *nkey)
{
    // we need a vbucket config before we can start getting data..
    libcouchbase_ensure_vbucket_config(instance);
    assert(instance->vbucket_config);

    uint16_t vb;
    libcouchbase_server_t *server;

    if (nhashkey != 0) {
        vb = (uint16_t)vbucket_get_vbucket_by_key(instance->vbucket_config,
                                                  hashkey, nhashkey);
        server = instance->servers + instance->vb_server_map[vb];
    }

    for (size_t ii = 0; ii < num_keys; ++ii) {
        if (nhashkey == 0) {
            vb = (uint16_t)vbucket_get_vbucket_by_key(instance->vbucket_config,
                                                      keys[ii], nkey[ii]);
            server = instance->servers + instance->vb_server_map[vb];
        }

        protocol_binary_request_get req;
        memset(&req, 0, sizeof(req));
        req.message.header.request.magic = PROTOCOL_BINARY_REQ;
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GETQ;
        req.message.header.request.keylen = ntohs((uint16_t)nkey[ii]);
        req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        req.message.header.request.vbucket = ntohs(vb);
        req.message.header.request.bodylen = ntohl((uint32_t)(nkey[ii]));
        req.message.header.request.opaque = ++instance->seqno;

        libcouchbase_server_start_packet(server, req.bytes, sizeof(req.bytes));
        libcouchbase_server_write_packet(server, keys[ii], nkey[ii]);
        libcouchbase_server_end_packet(server);
    }

    protocol_binary_request_noop noop;
    memset(&noop, 0, sizeof(noop));
    noop.message.header.request.magic = PROTOCOL_BINARY_REQ;
    noop.message.header.request.opcode = PROTOCOL_BINARY_CMD_NOOP;
    noop.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;

    if (nhashkey == 0) {
        // We don't know which server we sent the data to, so examine
        // where to send the noop
        for (size_t ii = 0; ii < instance->nservers; ++ii) {
            server = instance->servers + ii;
            if (server->output.avail > 0 || server->pending.avail > 0) {
                noop.message.header.request.opaque = ++instance->seqno;
                libcouchbase_server_complete_packet(server, noop.bytes,
                                                    sizeof(noop.bytes));
                libcouchbase_server_send_packets(server);
            }
        }
    } else {
        noop.message.header.request.opaque = ++instance->seqno;
        libcouchbase_server_complete_packet(server, noop.bytes,
                                            sizeof(noop.bytes));
        libcouchbase_server_send_packets(server);
    }

    return LIBCOUCHBASE_SUCCESS;
}
