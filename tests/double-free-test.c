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

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

#include "libcouchbase/couchbase.h"
#include "server.h"
#include "test.h"

libcouchbase_t session = NULL;
const void *mock = NULL;
struct libcouchbase_io_opt_st *io = NULL;

struct rvbuf
{
    libcouchbase_error_t error;
    libcouchbase_cas_t cas1;
    libcouchbase_cas_t cas2;
};

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t err,
                           const char *errinfo)
{
    err_exit("Error %s: %s", libcouchbase_strerror(instance, err), errinfo);
}

static void setup(char **argv)
{
    const char *endpoint;

    assert(session == NULL);
    assert(mock == NULL);
    assert(io == NULL);

    io = get_test_io_opts();
    if (io == NULL) {
        err_exit("Failed to create IO session");
    }

    mock = start_mock_server(argv);
    if (mock == NULL) {
        err_exit("Failed to start mock server");
    }

    endpoint = get_mock_http_server(mock);
    session = libcouchbase_create(endpoint, "Administrator", "password", NULL, io);
    if (session == NULL) {
        err_exit("Failed to create libcouchbase session");
    }

    (void)libcouchbase_set_error_callback(session, error_callback);

    if (libcouchbase_connect(session) != LIBCOUCHBASE_SUCCESS) {
        err_exit("Failed to connect to server");
    }
    libcouchbase_wait(session);
}

static void teardown(void)
{
    libcouchbase_destroy(session);
    session = NULL;
    io = NULL;
    shutdown_mock_server(mock);
    mock = NULL;
}

static void store_callback1(libcouchbase_t instance,
                            const void *cookie,
                            libcouchbase_storage_t operation,
                            libcouchbase_error_t error,
                            const void *key, libcouchbase_size_t nkey,
                            libcouchbase_cas_t cas)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    assert(io);
    io->stop_event_loop(io);
    (void)instance;
    (void)operation;
    (void)cas;
    (void)key;
    (void)nkey;
}

static void store_callback2(libcouchbase_t instance,
                            const void *cookie,
                            libcouchbase_storage_t operation,
                            libcouchbase_error_t error,
                            const void *key, libcouchbase_size_t nkey,
                            libcouchbase_cas_t cas)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    rv->cas2 = cas;
    assert(io);
    io->stop_event_loop(io);
    (void)instance;
    (void)operation;
    (void)key;
    (void)nkey;
}

static void get_callback(libcouchbase_t instance,
                         const void *cookie,
                         libcouchbase_error_t error,
                         const void *key, libcouchbase_size_t nkey,
                         const void *bytes, libcouchbase_size_t nbytes,
                         libcouchbase_uint32_t flags, libcouchbase_cas_t cas)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    const char *val = "{\"bar\"=>1, \"baz\"=>2}";
    libcouchbase_size_t nval = strlen(val);
    libcouchbase_error_t err;

    rv->error = error;
    rv->cas1 = cas;
    err = libcouchbase_store(session, rv, LIBCOUCHBASE_SET, key, nkey, val, nval, 0, 0, cas);
    assert(err == LIBCOUCHBASE_SUCCESS);

    (void)instance;
    (void)bytes;
    (void)nbytes;
    (void)flags;
}

static void reproduce_double_free_error(void)
{
    libcouchbase_error_t err;
    struct rvbuf rv;
    const char *key = "test_compare_and_swap_async_", *val = "{\"bar\" => 1}";
    libcouchbase_size_t nkey = strlen(key), nval = strlen(val);

    /* prefill the bucket */
    (void)libcouchbase_set_storage_callback(session, store_callback1);
    err = libcouchbase_store(session, &rv, LIBCOUCHBASE_SET, key, nkey, val, nval, 0, 0, 0);
    assert(err == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);

    /* run exercise
     *
     * 1. get the value and its cas
     * 2. atomic set new value using old cas
     */
    (void)libcouchbase_set_storage_callback(session, store_callback2);
    (void)libcouchbase_set_get_callback(session, get_callback);
    err = libcouchbase_mget(session, &rv, 1, (const void * const *)&key, &nkey, NULL);
    assert(err == LIBCOUCHBASE_SUCCESS);
    rv.cas1 = rv.cas2 = 0;
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);
    assert(rv.cas1 > 0);
    assert(rv.cas2 > 0);
    assert(rv.cas1 != rv.cas2);
}

int main(int argc, char **argv)
{
    const char *args[] = {"--nodes", "5", NULL};

    if (getenv("LIBCOUCHBASE_VERBOSE_TESTS") == NULL) {
        freopen("/dev/null", "w", stdout);
    }

    setup((char **)args);

    reproduce_double_free_error();

    teardown();

    (void)argc; (void)argv;
    return EXIT_SUCCESS;
}
