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

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <event.h>
#include <libcouchbase/couchbase.h>

#include "server.h"

libcouchbase_uint64_t val = 0;

static void storage_callback(libcouchbase_t instance,
                             const void *cookie,
                             libcouchbase_storage_t operation,
                             libcouchbase_error_t error,
                             const void *key, libcouchbase_size_t nkey,
                             libcouchbase_cas_t cas)
{
    (void)instance; (void)operation; (void)cas; (void)cookie;
    assert(nkey == 7);
    assert(memcmp(key, "counter", 7) == 0);
    assert(error == LIBCOUCHBASE_SUCCESS);
}

static void initialize_counter(const char *host, const char *user,
                               const char *passwd, const char *bucket)
{
    libcouchbase_t instance;
    struct libcouchbase_io_opt_st *io;
    struct event_base *evbase = event_base_new();
    if (evbase == NULL) {
        fprintf(stderr, "Failed to create event base\n");
        exit(1);
    }

    io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_LIBEVENT, evbase, NULL);
    if (io == NULL) {
        fprintf(stderr, "Failed to create IO instance\n");
        exit(1);
    }
    instance = libcouchbase_create(host, user, passwd, bucket, io);
    if (instance == NULL) {
        fprintf(stderr, "Failed to create libcouchbase instance\n");
        event_base_free(evbase);
        exit(1);
    }

    if (libcouchbase_connect(instance) != LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr, "Failed to connect libcouchbase instance to server\n");
        event_base_free(evbase);
        exit(1);
    }

    /* Wait for the connect to compelete */
    libcouchbase_wait(instance);

    (void)libcouchbase_set_storage_callback(instance, storage_callback);

    libcouchbase_store(instance, NULL, LIBCOUCHBASE_SET, "counter", 7,
                       "0", 1, 0, 0, 0);
    libcouchbase_wait(instance);
    libcouchbase_destroy(instance);
    event_base_free(evbase);
}

static void arithmetic_callback(libcouchbase_t instance,
                                const void *cookie,
                                libcouchbase_error_t error,
                                const void *key, libcouchbase_size_t nkey,
                                libcouchbase_uint64_t value, libcouchbase_cas_t cas)
{
    assert(nkey == 7);
    assert(memcmp(key, "counter", 7) == 0);
    assert(error == LIBCOUCHBASE_SUCCESS);
    assert(value == (val + 1));
    val = value;
    (void)cas;
    (void)instance;
    (void)cookie;
}

static void do_run_arithmetic(const char *host, const char *user,
                              const char *passwd, const char *bucket)
{
    int ii;
    libcouchbase_t instance;
    struct libcouchbase_io_opt_st *io;
    struct event_base *evbase = event_base_new();
    if (evbase == NULL) {
        fprintf(stderr, "Failed to create event base\n");
        exit(1);
    }

    io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_LIBEVENT, evbase, NULL);
    if (io == NULL) {
        fprintf(stderr, "Failed to create IO instance\n");
        exit(1);
    }
    instance = libcouchbase_create(host, user, passwd, bucket, io);
    if (instance == NULL) {
        fprintf(stderr, "Failed to create libcouchbase instance\n");
        event_base_free(evbase);
        exit(1);
    }

    if (libcouchbase_connect(instance) != LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr, "Failed to connect libcouchbase instance to server\n");
        event_base_free(evbase);
        exit(1);
    }

    /* Wait for the connect to compelete */
    libcouchbase_wait(instance);

    (void)libcouchbase_set_arithmetic_callback(instance,
                                               arithmetic_callback);

    for (ii = 0; ii < 10; ++ii) {
        libcouchbase_arithmetic(instance, NULL, "counter", 7, 1, 0, 1, 0);
        libcouchbase_wait(instance);
    }

    libcouchbase_destroy(instance);
    event_base_free(evbase);
}

int main(int argc, char **argv)
{
    const void *mock;
    const char *http;
    int ii;

    (void)argc; (void)argv;

    mock = start_mock_server(NULL);
    if (mock == NULL) {
        fprintf(stderr, "Failed to start mock server\n");
        return 1;
    }

    http = get_mock_http_server(mock);
    initialize_counter(http, "Administrator", "password", NULL);

    for (ii = 0; ii < 10; ++ii) {
        do_run_arithmetic(http, "Administrator", "password", NULL);
    }

    shutdown_mock_server(mock);
    return 0;
}
