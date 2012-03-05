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
libcouchbase_error_t libcouchbase_flush(libcouchbase_t instance,
                                        const void *command_cookie)
{
    libcouchbase_server_t *server;
    protocol_binary_request_no_extras flush;
    libcouchbase_size_t ii;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
    }

    memset(&flush, 0, sizeof(flush));
    flush.message.header.request.magic = PROTOCOL_BINARY_REQ;
    flush.message.header.request.opcode = PROTOCOL_BINARY_CMD_FLUSH;
    flush.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    flush.message.header.request.opaque = ++instance->seqno;

    for (ii = 0; ii < instance->nservers; ++ii) {
        server = instance->servers + ii;
        libcouchbase_server_complete_packet(server, command_cookie,
                                            flush.bytes,
                                            sizeof(flush.bytes));
        libcouchbase_server_send_packets(server);
    }

    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}
