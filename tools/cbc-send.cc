/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012 Couchbase, Inc.
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

#include "config.h"

#include <string>
#include <list>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <libcouchbase/couchbase.h>
#include <memcached/protocol_binary.h>
#include "tools/cbc-util.h"

using namespace std;

extern "C" {
    static void cbc_tap_mutation_callback(libcouchbase_t,
                                          const void *,
                                          const void *key,
                                          libcouchbase_size_t nkey,
                                          const void *data,
                                          libcouchbase_size_t nbytes,
                                          libcouchbase_uint32_t flags,
                                          libcouchbase_time_t exp,
                                          libcouchbase_cas_t cas,
                                          libcouchbase_vbucket_t vbucket,
                                          const void *,
                                          libcouchbase_size_t)
    {
        protocol_binary_request_set req;
        memset(&req, 0, sizeof(req));
        req.message.header.request.magic = PROTOCOL_BINARY_REQ;
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SET;
        req.message.header.request.keylen = ntohs((libcouchbase_vbucket_t)nkey);
        req.message.header.request.extlen = 8;
        req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        req.message.header.request.cas = cas;
        req.message.header.request.vbucket = htons(vbucket);
        req.message.body.flags = flags;
        req.message.body.expiration = htonl((libcouchbase_uint32_t)exp);
        libcouchbase_uint32_t bodylen = (libcouchbase_uint32_t)(nkey + nbytes + 8 + nbytes);
        req.message.header.request.bodylen = htonl((libcouchbase_uint32_t)bodylen);
        sendIt(req.bytes, sizeof(req.bytes));
        sendIt((const uint8_t*)key, nkey);
        sendIt((const uint8_t*)data, nbytes);
    }

    static void cbc_tap_deletion_callback(libcouchbase_t,
                                          const void *,
                                          const void *key,
                                          libcouchbase_size_t nkey,
                                          libcouchbase_cas_t cas,
                                          libcouchbase_vbucket_t vbucket,
                                          const void *,
                                          libcouchbase_size_t)
    {
        protocol_binary_request_delete req;

        memset(&req, 0, sizeof(req));
        req.message.header.request.magic = PROTOCOL_BINARY_REQ;
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_DELETE;
        req.message.header.request.keylen = ntohs((libcouchbase_vbucket_t)nkey);
        req.message.header.request.extlen = 0;
        req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        req.message.header.request.cas = cas;
        req.message.header.request.vbucket = htons(vbucket);
        req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)nkey);
        sendIt(req.bytes, sizeof(req.bytes));
        sendIt((const uint8_t*)key, nkey);
    }

    static void cbc_tap_flush_callback(libcouchbase_t,
                                       const void *,
                                       const void *,
                                       libcouchbase_size_t)
    {
        protocol_binary_request_flush req;
        memset(req.bytes, 0, sizeof(req.bytes));
        req.message.header.request.magic = PROTOCOL_BINARY_REQ;
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_FLUSH;
        req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        sendIt(req.bytes, sizeof(req.bytes));
    }

    static void cbc_tap_opaque_callback(libcouchbase_t, const void *,
                                        const void *, libcouchbase_size_t)
    {
        // We don't have an alternative for this. Just swallow the message
    }

    static void cbc_tap_vbucket_set_callback(libcouchbase_t,
                                             const void *,
                                             libcouchbase_vbucket_t vbucket,
                                             libcouchbase_vbucket_state_t state,
                                             const void *,
                                             libcouchbase_size_t)
    {
        protocol_binary_request_set_vbucket req;
        memset(req.bytes, 0, sizeof(req.bytes));
        req.message.header.request.magic = PROTOCOL_BINARY_REQ;
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SET_VBUCKET;
        req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        req.message.header.request.vbucket = htons(vbucket);
        state = (libcouchbase_vbucket_state_t)ntohl((libcouchbase_vbucket_state_t)state);
        memcpy(&req.message.body.state, &state, sizeof(state));
        sendIt(req.bytes, sizeof(req.bytes));
    }
}

bool send(libcouchbase_t instance, list<string> &keys)
{
    if (!keys.empty()) {
        cerr << "Ignoring arguments." << endl;
    }

    setBinaryIO();

    (void)libcouchbase_set_tap_mutation_callback(instance,
                                                 cbc_tap_mutation_callback);
    (void)libcouchbase_set_tap_deletion_callback(instance,
                                                 cbc_tap_deletion_callback);
    (void)libcouchbase_set_tap_flush_callback(instance,
                                              cbc_tap_flush_callback);
    (void)libcouchbase_set_tap_opaque_callback(instance,
                                               cbc_tap_opaque_callback);
    (void)libcouchbase_set_tap_vbucket_set_callback(instance,
                                                    cbc_tap_vbucket_set_callback);

    // @todo refactor this shit! tap cluster should work just as the other
    //       commands!
    libcouchbase_tap_cluster(instance, NULL, NULL, 1);

    return true;
}
