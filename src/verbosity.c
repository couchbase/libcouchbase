/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_set_verbosity(libcouchbase_t instance,
                                                const void *command_cookie,
                                                const char *server,
                                                libcouchbase_verbosity_level_t level)
{
    libcouchbase_server_t *srv;
    protocol_binary_request_verbosity req;
    libcouchbase_size_t ii;
    uint32_t lvl;
    int found = 0;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
    }

    switch (level) {
    case LIBCOUCHBASE_VERBOSITY_DETAIL:
        lvl = 3;
        break;
    case LIBCOUCHBASE_VERBOSITY_DEBUG:
        lvl = 2;
        break;
    case LIBCOUCHBASE_VERBOSITY_INFO:
        lvl = 1;
        break;
    case LIBCOUCHBASE_VERBOSITY_WARNING:
    default:
        lvl = 0;
    }

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_VERBOSITY;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.opaque = ++instance->seqno;
    req.message.header.request.extlen = 4;
    req.message.header.request.bodylen = htonl(4);
    req.message.body.level = htonl(lvl);

    for (ii = 0; ii < instance->nservers; ++ii) {
        srv = instance->servers + ii;

        if (server && strncmp(server, srv->authority, strlen(server)) != 0) {
            continue;
        }

        libcouchbase_server_start_packet(srv, command_cookie, req.bytes,
                                         sizeof(req.bytes));
        libcouchbase_server_end_packet(srv);
        libcouchbase_server_send_packets(srv);
        found = 1;
    }

    if (server && found ==0) {
        return libcouchbase_synchandler_return(instance,
                                               LIBCOUCHBASE_UNKNOWN_HOST);
    }

    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}
