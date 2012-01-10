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

#include <iostream>
#include <sstream>
#include <ctype.h>
#include <getopt.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <cerrno>
#include <libcouchbase/couchbase.h>
#include <memcached/protocol_binary.h>

#include "configuration.h"
#include "commandlineparser.h"
#include "tools/cbc-util.h"

using namespace std;


extern "C" {
    // libcouchbase use a C linkage!
    static void storage_callback(libcouchbase_t instance,
                                 const void *,
                                 libcouchbase_storage_t,
                                 libcouchbase_error_t error,
                                 const void *key, size_t nkey,
                                 uint64_t)
    {
        if (error != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to store \"";
            cerr.write(static_cast<const char*>(key), nkey);
            cerr << "\":" << endl
                      << libcouchbase_strerror(instance, error) << endl;

            void *cookie = const_cast<void*>(libcouchbase_get_cookie(instance));
            bool *e = static_cast<bool*>(cookie);
            *e = true;
        }
    }

    static void remove_callback(libcouchbase_t instance,
                                const void *,
                                libcouchbase_error_t error,
                                const void *key, size_t nkey)
    {
        if (error != LIBCOUCHBASE_SUCCESS) {
            cerr << "Failed to remove \"";
            cerr.write(static_cast<const char*>(key), nkey);
            cerr << "\":" << endl
                      << libcouchbase_strerror(instance, error) << endl;
            void *cookie = const_cast<void*>(libcouchbase_get_cookie(instance));
            bool *err = static_cast<bool*>(cookie);
            *err = true;
        }
    }
}

typedef bool (*packetHandler)(libcouchbase_t instance,
                              protocol_binary_request_header &header);

static bool setHandler(libcouchbase_t instance,
                       protocol_binary_request_header &header)
{
    bool ret = true;
    uint32_t bodylen = ntohl(header.request.bodylen);
    uint16_t keylen = ntohl(header.request.keylen);

    if (bodylen <= 0 || keylen <= 0) {
        cerr << "Protocol error for the set command" << endl;
        exit(1);
    }

    uint8_t *data = new uint8_t[bodylen];
    ret = readIt(data, bodylen);

    libcouchbase_error_t err;
    uint32_t flags;
    uint32_t exptime;

    memcpy(&flags, data, sizeof(flags));
    memcpy(&exptime, data + sizeof(flags), sizeof(exptime));
    exptime = ntohl(exptime);

    err = libcouchbase_store(instance,
                             NULL,
                             LIBCOUCHBASE_SET,
                             (const void*)(data + header.request.extlen),
                             keylen,
                             (const void*)(data + header.request.extlen + keylen),
                             bodylen - header.request.extlen - keylen,
                             flags, exptime, 0);

    delete []data;
    if (err != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to remove entry:" << endl
             << libcouchbase_strerror(instance, err) << endl;
        return false;
    }

    // we should probably batch these ;)
    libcouchbase_wait(instance);
    // @todo add test for the error-cookie

    return true;
}

static bool deleteHandler(libcouchbase_t instance,
                          protocol_binary_request_header &header)
{
    bool ret = true;
    uint32_t bodylen = ntohl(header.request.bodylen);
    uint16_t keylen = ntohl(header.request.keylen);

    if (bodylen <= 0 || keylen <= 0) {
        cerr << "Protocol error for the delete command" << endl;
        exit(1);
    }

    uint8_t *data = new uint8_t[bodylen];
    ret = readIt(data, bodylen);

    libcouchbase_error_t err;
    err = libcouchbase_remove(instance, NULL,
                              (const void*)(data + header.request.extlen),
                              keylen, 0);
    delete []data;

    if (err != LIBCOUCHBASE_SUCCESS) {
        cerr << "Failed to remove entry:" << endl
             << libcouchbase_strerror(instance, err) << endl;
        return false;
    }

    // we should probably batch these ;)
    libcouchbase_wait(instance);
    // @todo add test for the error-cookie

    return true;
}

static bool unknownHandler(libcouchbase_t,
                           protocol_binary_request_header &header)
{
    bool ret = true;
    uint32_t bodylen = ntohl(header.request.bodylen);
    if (bodylen > 0) {
        uint8_t *data = new uint8_t[bodylen];
        ret = readIt(data, bodylen);
        delete []data;
        cout << "Skipping unknown command" << endl;
    }

    return ret;
}

static bool processNextPacket(libcouchbase_t instance)
{
    protocol_binary_request_header header;
    if (!readIt(header.bytes, sizeof(header.bytes))) {
        return false;
    }

    if (header.request.magic != PROTOCOL_BINARY_REQ) {
        cerr << "Unknown data received" << endl;
        exit(1);
    }

    packetHandler handler;
    switch (header.request.opcode) {
    case PROTOCOL_BINARY_CMD_SET:
        handler = setHandler;
        break;
    case PROTOCOL_BINARY_CMD_DELETE:
        handler = deleteHandler;
        break;
    default:
        handler = unknownHandler;
    }

    return handler(instance, header);
}

bool receive(libcouchbase_t instance, list<string> &keys)
{
    if (!keys.empty()) {
        cerr << "Ignoring arguments." << endl;
    }

#ifdef WIN32
    // Windows defaults to text mode, but we're going to read
    // binary data...
    _setmode(_fileno(stdin), _O_BINARY);
#endif

    // override the handlers..
    (void)libcouchbase_set_remove_callback(instance, remove_callback);
    (void)libcouchbase_set_storage_callback(instance, storage_callback);

    while (feof(stdin) == 0) {
        if (!processNextPacket(instance)) {
            // error should already be printed
            return false;
        }
    }

    return true;
}
