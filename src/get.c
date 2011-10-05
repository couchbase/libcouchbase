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

static libcouchbase_error_t libcouchbase_single_get(libcouchbase_t instance,
                                                    const void *command_cookie,
                                                    const void *hashkey,
                                                    size_t nhashkey,
                                                    const void *key,
                                                    const size_t nkey,
                                                    const time_t *exp);

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
                                       const void *command_cookie,
                                       size_t num_keys,
                                       const void * const *keys,
                                       const size_t *nkey,
                                       const time_t *exp)
{
    return libcouchbase_mget_by_key(instance, command_cookie, NULL, 0, num_keys,
                                    keys, nkey, exp);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_mget_by_key(libcouchbase_t instance,
                                              const void *command_cookie,
                                              const void *hashkey,
                                              size_t nhashkey,
                                              size_t num_keys,
                                              const void * const *keys,
                                              const size_t *nkey,
                                              const time_t *exp)
{
    uint16_t vb = 0;
    libcouchbase_server_t *server = NULL;
    protocol_binary_request_noop noop;
    size_t ii;

    // we need a vbucket config before we can start getting data..
    if (instance->vbucket_config == NULL) {
        return LIBCOUCHBASE_ETMPFAIL;
    }

    if (num_keys == 1) {
        return libcouchbase_single_get(instance, command_cookie, hashkey,
                                       nhashkey, keys[0], nkey[0], exp);
    }

    if (nhashkey != 0) {
        vb = (uint16_t)vbucket_get_vbucket_by_key(instance->vbucket_config,
                                                  hashkey, nhashkey);
        server = instance->servers + instance->vb_server_map[vb];
    }

    for (ii = 0; ii < num_keys; ++ii) {
        protocol_binary_request_gat req;
        if (nhashkey == 0) {
            vb = (uint16_t)vbucket_get_vbucket_by_key(instance->vbucket_config,
                                                      keys[ii], nkey[ii]);
            server = instance->servers + instance->vb_server_map[vb];
        }

        memset(&req, 0, sizeof(req));
        req.message.header.request.magic = PROTOCOL_BINARY_REQ;
        req.message.header.request.keylen = ntohs((uint16_t)nkey[ii]);
        req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        req.message.header.request.vbucket = ntohs(vb);
        req.message.header.request.bodylen = ntohl((uint32_t)(nkey[ii]));
        req.message.header.request.opaque = ++instance->seqno;

        if (!exp) {
            req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GETQ;
            libcouchbase_server_start_packet(server, command_cookie, req.bytes,
                                             sizeof(req.bytes) - 4);
        } else {
            req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GATQ;
            req.message.header.request.extlen = 4;
            req.message.body.expiration = ntohl((uint32_t)exp[ii]);
            req.message.header.request.bodylen = ntohl((uint32_t)(nkey[ii]) + 4);
            libcouchbase_server_start_packet(server, command_cookie, req.bytes,
                                             sizeof(req.bytes));
        }
        libcouchbase_server_write_packet(server, keys[ii], nkey[ii]);
        libcouchbase_server_end_packet(server);
    }

    memset(&noop, 0, sizeof(noop));
    noop.message.header.request.magic = PROTOCOL_BINARY_REQ;
    noop.message.header.request.opcode = PROTOCOL_BINARY_CMD_NOOP;
    noop.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;

    if (nhashkey == 0) {
        // We don't know which server we sent the data to, so examine
        // where to send the noop
        for (ii = 0; ii < instance->nservers; ++ii) {
            server = instance->servers + ii;
            if (server->output.nbytes > 0 || server->pending.nbytes > 0) {
                noop.message.header.request.opaque = ++instance->seqno;
                libcouchbase_server_complete_packet(server, command_cookie,
                                                    noop.bytes,
                                                    sizeof(noop.bytes));
                libcouchbase_server_send_packets(server);
            }
        }
    } else {
        noop.message.header.request.opaque = ++instance->seqno;
        libcouchbase_server_complete_packet(server, command_cookie, noop.bytes,
                                            sizeof(noop.bytes));
        libcouchbase_server_send_packets(server);
    }

    return LIBCOUCHBASE_SUCCESS;
}

static libcouchbase_error_t libcouchbase_single_get(libcouchbase_t instance,
                                                    const void *command_cookie,
                                                    const void *hashkey,
                                                    size_t nhashkey,
                                                    const void * key,
                                                    const size_t nkey,
                                                    const time_t *exp)
{
    uint16_t vb = 0;
    libcouchbase_server_t *server;
    protocol_binary_request_gat req;

    if (nhashkey != 0) {
        vb = (uint16_t)vbucket_get_vbucket_by_key(instance->vbucket_config,
                                                  hashkey, nhashkey);
    } else {
        vb = (uint16_t)vbucket_get_vbucket_by_key(instance->vbucket_config,
                                                  key, nkey);
    }
    server = instance->servers + instance->vb_server_map[vb];

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.keylen = ntohs((uint16_t)nkey);
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.vbucket = ntohs(vb);
    req.message.header.request.bodylen = ntohl((uint32_t)(nkey));
    req.message.header.request.opaque = ++instance->seqno;

    if (!exp) {
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GET;
        libcouchbase_server_start_packet(server, command_cookie, req.bytes,
                                         sizeof(req.bytes) - 4);
    } else {
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GAT;
        req.message.header.request.extlen = 4;
        req.message.body.expiration = ntohl((uint32_t)exp[0]);
        req.message.header.request.bodylen = ntohl((uint32_t)(nkey) + 4);
        libcouchbase_server_start_packet(server, command_cookie, req.bytes,
                                         sizeof(req.bytes));
    }
    libcouchbase_server_write_packet(server, key, nkey);
    libcouchbase_server_end_packet(server);
    libcouchbase_server_send_packets(server);

    return LIBCOUCHBASE_SUCCESS;
}
