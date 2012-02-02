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

#include "internal.h" /* to look at the internals to check if sasl ok */
#include "server.h"
#include "test.h"

libcouchbase_t session = NULL;
const void *mock = NULL;
struct libcouchbase_io_opt_st *io = NULL;
libcouchbase_error_t global_error = -1;

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t err,
                           const char *errinfo)
{
    err_exit("Error %s: %s", libcouchbase_strerror(instance, err), errinfo);
}

static void error_callback2(libcouchbase_t instance,
                            libcouchbase_error_t err,
                            const char *errinfo)
{
    global_error = err;
    (void)instance;
    (void)errinfo;
}

static void setup(char **argv, const char *username, const char *password,
                  const char *bucket)
{
    const char *endpoint;

    assert(session == NULL);
    assert(mock == NULL);
    assert(io == NULL);

    io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT, NULL, NULL);
    if (io == NULL) {
        err_exit("Failed to create IO session");
    }

    mock = start_mock_server(argv);
    if (mock == NULL) {
        err_exit("Failed to start mock server");
    }

    endpoint = get_mock_http_server(mock);
    session = libcouchbase_create(endpoint, username, password, bucket, io);
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

struct rvbuf
{
    libcouchbase_error_t error;
    libcouchbase_storage_t operation;
    const char *key;
    libcouchbase_size_t nkey;
    const char *bytes;
    libcouchbase_size_t nbytes;
    libcouchbase_cas_t cas;
    libcouchbase_uint32_t flags;
    int32_t counter;
    libcouchbase_uint32_t errors;
};

static void store_callback(libcouchbase_t instance,
                           const void *cookie,
                           libcouchbase_storage_t operation,
                           libcouchbase_error_t error,
                           const void *key, libcouchbase_size_t nkey,
                           libcouchbase_cas_t cas)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    rv->operation = operation;
    rv->key = key;
    rv->nkey = nkey;
    rv->cas = cas;
    assert(io);
    io->stop_event_loop(io);
    (void)instance;
}

static void mstore_callback(libcouchbase_t instance,
                            const void *cookie,
                            libcouchbase_storage_t operation,
                            libcouchbase_error_t error,
                            const void *key, libcouchbase_size_t nkey,
                            libcouchbase_cas_t cas)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->errors |= error;
    rv->operation = operation;
    rv->key = key;
    rv->nkey = nkey;
    rv->cas = cas;
    rv->counter--;
    if (rv->counter <= 0) {
        assert(io);
        io->stop_event_loop(io);
    }
    (void)instance;
}

static void get_callback(libcouchbase_t instance,
                         const void *cookie,
                         libcouchbase_error_t error,
                         const void *key, libcouchbase_size_t nkey,
                         const void *bytes, libcouchbase_size_t nbytes,
                         libcouchbase_uint32_t flags, libcouchbase_cas_t cas)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    rv->bytes = bytes;
    rv->nbytes = nbytes;
    rv->key = key;
    rv->nkey = nkey;
    rv->cas = cas;
    rv->flags = flags;
    assert(io);
    io->stop_event_loop(io);
    (void)instance;
}

static void test_set1(void)
{
    libcouchbase_error_t err;
    struct rvbuf rv;
    const char *key = "foo", *val = "bar";
    libcouchbase_size_t nkey = strlen(key), nval = strlen(val);

    (void)libcouchbase_set_storage_callback(session, store_callback);
    err = libcouchbase_store(session, &rv, LIBCOUCHBASE_SET, key, nkey, val, nval, 0, 0, 0);
    assert(err == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);
    assert(rv.operation == LIBCOUCHBASE_SET);
    assert(memcmp(rv.key, "foo", 3) == 0);
}

static void test_set2(void)
{
    libcouchbase_error_t err;
    struct rvbuf rv;
    const char *key = "foo", *val = "bar";
    libcouchbase_size_t ii, nkey = strlen(key), nval = strlen(val);

    (void)libcouchbase_set_storage_callback(session, mstore_callback);
    rv.errors = 0;
    rv.counter = 0;
    for (ii = 0; ii < 10; ++ii, ++rv.counter) {
        err = libcouchbase_store(session, &rv, LIBCOUCHBASE_SET, key, nkey, val, nval, 0, 0, 0);
        assert(err == LIBCOUCHBASE_SUCCESS);
    }
    io->run_event_loop(io);
    assert(rv.errors == 0);
}

static void test_get1(void)
{
    libcouchbase_error_t err;
    struct rvbuf rv;
    const char *key = "foo", *val = "bar";
    libcouchbase_size_t nkey = strlen(key), nval = strlen(val);

    (void)libcouchbase_set_storage_callback(session, store_callback);
    (void)libcouchbase_set_get_callback(session, get_callback);

    err = libcouchbase_store(session, &rv, LIBCOUCHBASE_SET, key, nkey, val, nval, 0, 0, 0);
    assert(err == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);

    memset(&rv, 0, sizeof(rv));
    err = libcouchbase_mget(session, &rv, 1, (const void * const *)&key, &nkey, NULL);
    assert(err == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);
    assert(rv.nbytes == nval);
    assert(memcmp(rv.bytes, "bar", 3) == 0);
}

static libcouchbase_error_t test_connect(char **argv, const char *username,
                                         const char *password,
                                         const char *bucket)
{
    const char *endpoint;
    libcouchbase_error_t rc;

    assert(session == NULL);
    assert(mock == NULL);
    assert(io == NULL);

    io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT, NULL, NULL);
    if (io == NULL) {
        err_exit("Failed to create IO session");
    }

    mock = start_mock_server(argv);
    if (mock == NULL) {
        err_exit("Failed to start mock server");
    }

    endpoint = get_mock_http_server(mock);
    session = libcouchbase_create(endpoint, username, password, bucket, io);
    if (session == NULL) {
        err_exit("Failed to create libcouchbase session");
    }

    (void)libcouchbase_set_error_callback(session, error_callback2);

    if (libcouchbase_connect(session) != LIBCOUCHBASE_SUCCESS) {
        err_exit("Failed to connect to server");
    }
    libcouchbase_wait(session);
    rc = global_error;

    libcouchbase_destroy(session);
    session = NULL;
    io = NULL;
    shutdown_mock_server(mock);
    mock = NULL;

    return rc;
}

RESPONSE_HANDLER old_sasl_auth_response_handler;
libcouchbase_error_t sasl_auth_rc;

static void sasl_auth_response_handler(libcouchbase_server_t *server,
                                       const void *command_cookie,
                                       protocol_binary_response_header *res)
{
    sasl_auth_rc = ntohs(res->response.status);
    old_sasl_auth_response_handler(server, command_cookie, res);
}

static void test_set3(void)
{
    libcouchbase_error_t err;
    struct rvbuf rv;
    const char *key = "foo", *val = "bar";
    libcouchbase_size_t nkey = strlen(key), nval = strlen(val);

    old_sasl_auth_response_handler = session->response_handler[PROTOCOL_BINARY_CMD_SASL_AUTH];
    session->response_handler[PROTOCOL_BINARY_CMD_SASL_AUTH] = sasl_auth_response_handler;
    sasl_auth_rc = -1;

    (void)libcouchbase_set_storage_callback(session, store_callback);
    err = libcouchbase_store(session, &rv, LIBCOUCHBASE_SET, key, nkey, val, nval, 0, 0, 0);
    assert(err == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);
    assert(rv.operation == LIBCOUCHBASE_SET);
    assert(memcmp(rv.key, "foo", 3) == 0);
    assert(sasl_auth_rc == LIBCOUCHBASE_SUCCESS);
    session->response_handler[PROTOCOL_BINARY_CMD_SASL_AUTH] = old_sasl_auth_response_handler;
}

int main(int argc, char **argv)
{
    const char *args[] = {"--nodes", "5", "--buckets=default::memcache", NULL};

    if (getenv("LIBCOUCHBASE_VERBOSE_TESTS") == NULL) {
        freopen("/dev/null", "w", stdout);
    }

    setup((char **)args, "Administrator", "password", "default");
    test_set1();
    test_set2();
    test_get1();
    teardown();

    args[2] = NULL;
    setup((char **)args, "Administrator", "password", "default");
    test_set1();
    test_set2();
    test_get1();
    teardown();

    assert(test_connect((char **)args, "Administrator", "password", "missing") == LIBCOUCHBASE_BUCKET_ENOENT);

    args[2] = "--buckets=protected:secret";
    assert(test_connect((char **)args, "protected", "incorrect", "protected") == LIBCOUCHBASE_AUTH_ERROR);
    setup((char **)args, "protected", "secret", "protected");
    test_set3();
    teardown();

    (void)argc; (void)argv;
    return EXIT_SUCCESS;
}
