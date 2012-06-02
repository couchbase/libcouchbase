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
int total_node_count = -1;


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

    io = get_test_io_opts();
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

struct rvbuf {
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
    rv->counter--;
    if (rv->counter <= 0) {
        assert(io);
        io->stop_event_loop(io);
    }
    (void)instance;
}

static void touch_callback(libcouchbase_t instance,
                           const void *cookie,
                           libcouchbase_error_t error,
                           const void *key, libcouchbase_size_t nkey)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    assert(error == LIBCOUCHBASE_SUCCESS);
    rv->key = key;
    rv->nkey = nkey;
    rv->counter--;
    if (rv->counter <= 0) {
        assert(io);
        io->stop_event_loop(io);
    }
    (void)instance;
}

static void version_callback(libcouchbase_t instance,
                             const void *cookie,
                             const char *server_endpoint,
                             libcouchbase_error_t error,
                             const char *vstring,
                             libcouchbase_size_t nvstring)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    char *str;

    assert(error == LIBCOUCHBASE_SUCCESS);

    if (server_endpoint == NULL) {
        assert(rv->counter == 0);
        io->stop_event_loop(io);
        return;
    }

    rv->counter--;

    /*copy the key to an allocated buffer and ensure the key read from vstring
     * will not segfault
     */
    str = malloc(nvstring);
    memcpy(str, vstring, nvstring);
    free(str);

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

static void test_get2(void)
{
    libcouchbase_error_t err;
    struct rvbuf rv;
    char *key = "fooX", *val = "bar";
    libcouchbase_size_t nkey = strlen(key), nval = strlen(val);
    char **keys;
    libcouchbase_size_t *nkeys, ii;

    (void)libcouchbase_set_storage_callback(session, store_callback);
    (void)libcouchbase_set_get_callback(session, get_callback);

    keys = malloc(26 * sizeof(char *));
    nkeys = malloc(26 * sizeof(libcouchbase_size_t));
    if (keys == NULL || nkeys == NULL) {
        err_exit("Failed to allocate memory for keys");
    }
    for (ii = 0; ii < 26; ii++) {
        nkeys[ii] = nkey;
        keys[ii] = strdup(key);
        if (keys[ii] == NULL) {
            err_exit("Failed to allocate memory for key");
        }
        keys[ii][3] = (char)ii + 'a';
        err = libcouchbase_store(session, &rv, LIBCOUCHBASE_SET, keys[ii], nkeys[ii], val, nval, 0, 0, 0);
        assert(err == LIBCOUCHBASE_SUCCESS);
        io->run_event_loop(io);
        assert(rv.error == LIBCOUCHBASE_SUCCESS);
        memset(&rv, 0, sizeof(rv));
    }

    rv.counter = 26;
    err = libcouchbase_mget(session, &rv, 26, (const void * const *)keys, nkeys, NULL);
    assert(err == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);
    assert(rv.nbytes == nval);
    assert(memcmp(rv.bytes, "bar", 3) == 0);
    for (ii = 0; ii < 26; ii++) {
        free(keys[ii]);
    }
    free(keys);
    free(nkeys);
}

static void test_touch1(void)
{
    libcouchbase_error_t err;
    struct rvbuf rv;
    char *key = "fooX", *val = "bar";
    libcouchbase_size_t nkey = strlen(key), nval = strlen(val);
    char **keys;
    libcouchbase_size_t *nkeys, ii;
    libcouchbase_time_t *ttls;

    (void)libcouchbase_set_storage_callback(session, store_callback);
    (void)libcouchbase_set_touch_callback(session, touch_callback);

    keys = malloc(26 * sizeof(char *));
    nkeys = malloc(26 * sizeof(libcouchbase_size_t));
    ttls = malloc(26 * sizeof(libcouchbase_time_t));
    if (keys == NULL || nkeys == NULL || ttls == NULL) {
        err_exit("Failed to allocate memory for keys");
    }
    for (ii = 0; ii < 26; ii++) {
        nkeys[ii] = nkey;
        keys[ii] = strdup(key);
        ttls[ii] = 1;
        if (keys[ii] == NULL) {
            err_exit("Failed to allocate memory for key");
        }
        keys[ii][3] = (char)ii + 'a';
        err = libcouchbase_store(session, &rv, LIBCOUCHBASE_SET, keys[ii], nkeys[ii], val, nval, 0, 0, 0);
        assert(err == LIBCOUCHBASE_SUCCESS);
        io->run_event_loop(io);
        assert(rv.error == LIBCOUCHBASE_SUCCESS);
        memset(&rv, 0, sizeof(rv));
    }

    rv.counter = 26;
    err = libcouchbase_mtouch(session, &rv, 26, (const void * const *)keys, nkeys, ttls);
    assert(err == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);
    for (ii = 0; ii < 26; ii++) {
        free(keys[ii]);
    }
    free(keys);
    free(ttls);
    free(nkeys);
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

    io = get_test_io_opts();
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

static void test_version1(void)
{
    libcouchbase_error_t err;
    struct rvbuf rv;

    (void)libcouchbase_set_version_callback(session, version_callback);
    err = libcouchbase_server_versions(session, &rv);

    assert(err == LIBCOUCHBASE_SUCCESS);

    rv.counter = total_node_count;

    io->run_event_loop(io);

    /* Ensure all version responses have been received */
    assert(rv.counter == 0);
}

static void test_spurious_saslerr(void)
{
    const char *key = "KEY";
    int iterations = 50;
    struct rvbuf rvs[50];
    int i;
    libcouchbase_error_t err;
    libcouchbase_set_storage_callback(session, mstore_callback);

    memset(rvs, 0, sizeof(rvs));

    for (i = 0; i < iterations; i++) {
        rvs[i].counter = 999; /*don't trigger a stop_event_loop*/
        err = libcouchbase_store(session, rvs + i, LIBCOUCHBASE_SET, key, 3, key, 3, 0, 0, 0);
        if (err != LIBCOUCHBASE_SUCCESS) {
            err_exit("Store operation failed");
        }
    }
    libcouchbase_wait(session);

    for (i = 0; i < iterations; i++) {
        char *errinfo = NULL;
        if (rvs[i].errors != LIBCOUCHBASE_SUCCESS) {
            errinfo = "Did not get success response";
        } else if (rvs[i].nkey != 3) {
            errinfo = "Did not get expected key length";
        } else if (memcmp(rvs[i].key, key, 3) != 0) {
            errinfo = "Weird key size";
        }
        if (errinfo) {
            err_exit("%s", errinfo);
        }
    }
}

/* libcouchbase_wait() blocks forever if there is nothing queued */
static void test_issue_59(void)
{
    libcouchbase_wait(session);
    libcouchbase_wait(session);
    libcouchbase_wait(session);
    libcouchbase_wait(session);
    libcouchbase_wait(session);
}

int main(int argc, char **argv)
{
    char str_node_count[16];
    const char *args[] = {"--nodes", "",
                          "--buckets=default::memcache", NULL
                         };

    if (getenv("LIBCOUCHBASE_VERBOSE_TESTS") == NULL) {
        freopen("/dev/null", "w", stdout);
    }

    total_node_count = 5;
    snprintf(str_node_count, 16, "%d", total_node_count);
    args[1] = str_node_count;

    setup((char **)args, "Administrator", "password", "default");
    test_set1();
    test_set2();
    test_get1();
    test_get2();
    test_version1();
    test_issue_59();
    teardown();

    args[2] = NULL;
    setup((char **)args, "Administrator", "password", "default");
    test_set1();
    test_set2();
    test_get1();
    test_get2();
    test_touch1();
    test_version1();
    teardown();

    assert(test_connect((char **)args, "Administrator", "password", "missing") == LIBCOUCHBASE_BUCKET_ENOENT);

    args[2] = "--buckets=protected:secret";
    assert(test_connect((char **)args, "protected", "incorrect", "protected") == LIBCOUCHBASE_AUTH_ERROR);
    setup((char **)args, "protected", "secret", "protected");
    test_set3();
    test_spurious_saslerr();
    teardown();

    (void)argc;
    (void)argv;
    return EXIT_SUCCESS;
}
