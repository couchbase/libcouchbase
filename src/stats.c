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
 * libcouchbase_stat use the STATS command
 *
 * @author Sergey Avseyev
 */
LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_server_stats(libcouchbase_t instance,
                                               const void* command_cookie,
                                               const void* arg,
                                               libcouchbase_size_t narg)
{
    libcouchbase_server_t *server;
    protocol_binary_request_stats req;
    libcouchbase_size_t ii;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
    }

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic= PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode= PROTOCOL_BINARY_CMD_STAT;
    req.message.header.request.datatype= PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.keylen = ntohs((libcouchbase_uint16_t)narg);
    req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)narg);
    req.message.header.request.opaque = ++instance->seqno;

    for (ii = 0; ii < instance->nservers; ++ii) {
        server = instance->servers + ii;
        libcouchbase_server_start_packet(server, command_cookie,
                                         req.bytes, sizeof(req.bytes));
        libcouchbase_server_write_packet(server, arg, narg);
        libcouchbase_server_end_packet(server);
        libcouchbase_server_send_packets(server);
    }
    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}
