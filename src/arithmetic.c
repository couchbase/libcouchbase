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
#include "internal.h"

/**
 * Spool an arithmetic request
 *
 * @author Trond Norbye
 * @todo add documentation
 */
LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_arithmetic(libcouchbase_t instance,
                                             const void *command_cookie,
                                             const void *key, libcouchbase_size_t nkey,
                                             int64_t delta, libcouchbase_time_t exp,
                                             int create, libcouchbase_uint64_t initial)
{
    return libcouchbase_arithmetic_by_key(instance, command_cookie, NULL, 0, key,
                                          nkey, delta, exp, create, initial);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_arithmetic_by_key(libcouchbase_t instance,
                                                    const void *command_cookie,
                                                    const void *hashkey,
                                                    libcouchbase_size_t nhashkey,
                                                    const void *key, libcouchbase_size_t nkey,
                                                    int64_t delta, libcouchbase_time_t exp,
                                                    int create, libcouchbase_uint64_t initial)
{
    libcouchbase_server_t *server;
    protocol_binary_request_incr req;
    int vb, idx;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
    }

    if (nhashkey == 0) {
        nhashkey = nkey;
        hashkey = key;
    }
    (void)vbucket_map(instance->vbucket_config, hashkey, nhashkey, &vb, &idx);
    if (idx < 0 || (libcouchbase_size_t)idx > instance->nservers) {
        /* the config says that there is no server yet at that position (-1) */
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NETWORK_ERROR);
    }
    server = instance->servers + (libcouchbase_size_t)idx;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_INCREMENT;
    req.message.header.request.keylen = ntohs((libcouchbase_uint16_t)nkey);
    req.message.header.request.extlen = 20;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.vbucket = ntohs((libcouchbase_uint16_t)vb);
    req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)(nkey + 20));
    req.message.header.request.opaque = ++instance->seqno;
    req.message.body.delta = ntohll((libcouchbase_uint64_t)(delta));
    req.message.body.initial = ntohll(initial);
    req.message.body.expiration = ntohl((libcouchbase_uint32_t)exp);

    if (delta < 0) {
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_DECREMENT;
        req.message.body.delta = ntohll((libcouchbase_uint64_t)(delta * -1));
    }

    if (!create) {
        memset(&req.message.body.expiration, 0xff,
               sizeof(req.message.body.expiration));
    }

    libcouchbase_server_start_packet(server, command_cookie, req.bytes, sizeof(req.bytes));
    libcouchbase_server_write_packet(server, key, nkey);
    libcouchbase_server_end_packet(server);
    libcouchbase_server_send_packets(server);

    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}
