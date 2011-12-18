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
// Include config.h to get the definition of hrtime_t for
// platforms without it...
#include "config.h"
#undef NDEBUG
#include <assert.h>

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <event.h>
#include <libcouchbase/couchbase.h>

#include "server.h"

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t err,
                           const char *errinfo)
{
    (void)instance;
    fprintf(stderr, "Error %s", libcouchbase_strerror(instance, err));
    if (errinfo) {
        fprintf(stderr, ": %s", errinfo);
    }
    fprintf(stderr, "\n");
    abort();
    exit(EXIT_FAILURE);
}

static void storage_callback(libcouchbase_t instance,
                             const void *cookie,
                             libcouchbase_storage_t operation,
                             libcouchbase_error_t error,
                             const void *key, size_t nkey,
                             uint64_t cas)
{
    (void)instance; (void)operation; (void)cas; (void)cookie;
    assert(nkey == 5);
    assert(memcmp(key, "flags", 5) == 0);
    assert(error == LIBCOUCHBASE_SUCCESS);
}

static void get_callback(libcouchbase_t instance,
                         const void *cookie,
                         libcouchbase_error_t error,
                         const void *key, size_t nkey,
                         const void *bytes, size_t nbytes,
                         uint32_t flags, uint64_t cas)
{
    (void)instance; (void)cookie; (void)cas;
    assert(nkey == 5);
    assert(memcmp(key, "flags", 5) == 0);
    assert(error == LIBCOUCHBASE_SUCCESS);
    assert(nbytes == 1);
    assert(memcmp(bytes, "x", 1) == 0);
    assert(flags == 0xdeadbeef);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char * keys[1];
    size_t nkeys[1];
    struct event_base *evbase;
    const void *mock;
    const char *http;
    struct libcouchbase_io_opt_st *io;
    libcouchbase_t instance;

    evbase = event_base_new();
    if (evbase == NULL) {
        fprintf(stderr, "Failed to create event base\n");
        return 1;
    }

    mock = start_mock_server(NULL);
    if (mock == NULL) {
        fprintf(stderr, "Failed to start mock server\n");
        return 1;
    }
    http = get_mock_http_server(mock);

    io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_LIBEVENT, evbase, NULL);
    if (io == NULL) {
        fprintf(stderr, "Failed to create IO instance\n");
        return 1;
    }
    instance = libcouchbase_create(http, "Administrator",
                                   "password", NULL, io);

    if (instance == NULL) {
        fprintf(stderr, "Failed to create libcouchbase instance\n");
        event_base_free(evbase);
        return 1;
    }

    (void)libcouchbase_set_error_callback(instance, error_callback);
    (void)libcouchbase_set_get_callback(instance, get_callback);
    (void)libcouchbase_set_storage_callback(instance, storage_callback);

    if (libcouchbase_connect(instance) != LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr, "Failed to connect libcouchbase instance to server\n");
        event_base_free(evbase);
        return 1;
    }

    // Wait for the connect to compelete
    libcouchbase_wait(instance);

    keys[0] = "flags";
    nkeys[0] = 5;

    assert(libcouchbase_store(instance, NULL, LIBCOUCHBASE_SET, keys[0], nkeys[0],
                              "x", 1, 0xdeadbeef, 0, 0) == LIBCOUCHBASE_SUCCESS);
    // Wait for it to be persisted
    libcouchbase_wait(instance);

    assert(libcouchbase_mget(instance, NULL, 1, (const void*const*)keys,
                             nkeys, NULL) == LIBCOUCHBASE_SUCCESS);

    // Wait for it to be received
    libcouchbase_wait(instance);

    shutdown_mock_server(mock);

    return 0;
}
