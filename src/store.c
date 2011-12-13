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
 * Spool a store request
 *
 * @author Trond Norbye
 * @todo add documentation
 * @todo fix the expiration so that it works relative/absolute etc..
 * @todo we might want to wait to write the data to the sockets if the
 *       user want to run a batch of store requests?
 */
LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_store(libcouchbase_t instance,
                                        const void *command_cookie,
                                        libcouchbase_storage_t operation,
                                        const void *key, size_t nkey,
                                        const void *bytes, size_t nbytes,
                                        uint32_t flags, time_t exp,
                                        uint64_t cas)
{
    return libcouchbase_store_by_key(instance, command_cookie, operation, NULL, 0,
                                     key, nkey, bytes, nbytes, flags, exp, cas);
}

libcouchbase_error_t libcouchbase_store_by_key(libcouchbase_t instance,
                                               const void *command_cookie,
                                               libcouchbase_storage_t operation,
                                               const void *hashkey,
                                               size_t nhashkey,
                                               const void *key, size_t nkey,
                                               const void *bytes, size_t nbytes,
                                               uint32_t flags, time_t exp,
                                               uint64_t cas)
{
    uint16_t vb;
    libcouchbase_server_t *server;
    protocol_binary_request_set req;
    size_t headersize;
    size_t bodylen;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return LIBCOUCHBASE_ETMPFAIL;
    }

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
    req.message.header.request.extlen = 8;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.vbucket = ntohs(vb);
    req.message.header.request.opaque = ++instance->seqno;
    req.message.header.request.cas = cas;
    req.message.body.flags = htonl(flags);
    req.message.body.expiration = htonl((uint32_t)exp);

    headersize = sizeof(req.bytes);
    switch (operation) {
    case LIBCOUCHBASE_ADD:
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_ADD;
        break;
    case LIBCOUCHBASE_REPLACE:
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_REPLACE;
        break;
    case LIBCOUCHBASE_SET:
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SET;
        break;
    case LIBCOUCHBASE_APPEND:
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_APPEND;
        req.message.header.request.extlen = 0;
        headersize -= 8;
        break;
    case LIBCOUCHBASE_PREPEND:
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_PREPEND;
        req.message.header.request.extlen = 0;
        headersize -= 8;
        break;
    default:
        /* We were given an unknown storage operation. */
        return libcouchbase_error_handler(instance, LIBCOUCHBASE_EINVAL,
                                          "Invalid value passed as storage operation");
    }

    /* Make it known that this was a success. */
    libcouchbase_error_handler(instance, LIBCOUCHBASE_SUCCESS, NULL);

    bodylen = nkey + nbytes + req.message.header.request.extlen;
    req.message.header.request.bodylen = htonl((uint32_t)bodylen);

    libcouchbase_server_start_packet(server, command_cookie, &req, headersize);
    libcouchbase_server_write_packet(server, key, nkey);
    libcouchbase_server_write_packet(server, bytes, nbytes);
    libcouchbase_server_end_packet(server);
    libcouchbase_server_send_packets(server);

    return LIBCOUCHBASE_SUCCESS;
}
