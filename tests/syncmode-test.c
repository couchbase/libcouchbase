/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

#include "libcouchbase/couchbase.h"
#include "tests/server.h"
#include "tests/test.h"

libcouchbase_t session = NULL;
const void *mock = NULL;

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t err,
                           const char *errinfo)
{
    err_exit("Error %s: %s", libcouchbase_strerror(instance, err), errinfo);
}

static void store_callback(libcouchbase_t instance,
                           const void *cookie,
                           libcouchbase_storage_t operation,
                           libcouchbase_error_t error,
                           const void *key, libcouchbase_size_t nkey,
                           libcouchbase_cas_t cas)
{
    int *status = (int *)cookie;
    *status = error;
    (void)instance;
    (void)operation;
    (void)key;
    (void)nkey;
    (void)cas;
}

static void setup(char **argv)
{
    const char *endpoint;

    assert(session == NULL);
    assert(mock == NULL);

    mock = start_mock_server(argv);
    if (mock == NULL) {
        err_exit("Failed to start mock server");
    }

    endpoint = get_mock_http_server(mock);
    session = libcouchbase_create(endpoint, "Administrator", "password",
                                  NULL, NULL);
    if (session == NULL) {
        err_exit("Failed to create libcouchbase session");
    }

    if (libcouchbase_behavior_get_syncmode(session) != LIBCOUCHBASE_ASYNCHRONOUS) {
        err_exit("The defaul sync mode should be async");
    }

    (void)libcouchbase_set_error_callback(session, error_callback);
    if (libcouchbase_connect(session) != LIBCOUCHBASE_SUCCESS) {
        err_exit("Failed to connect to server");
    }
    libcouchbase_wait(session);

    libcouchbase_behavior_set_syncmode(session, LIBCOUCHBASE_SYNCHRONOUS);
    if (libcouchbase_behavior_get_syncmode(session) != LIBCOUCHBASE_SYNCHRONOUS) {
        err_exit("set/get of syncmode doesn't work!");
    }

    libcouchbase_set_storage_callback(session, store_callback);
}

static void teardown(void)
{
    libcouchbase_destroy(session);
    session = NULL;
    shutdown_mock_server(mock);
    mock = NULL;
}

int main(void)
{
    libcouchbase_error_t ret;
    int error = 0xffff;
    const char *args[] = {"--nodes", "5", "--buckets=default::memcache", NULL};

    if (getenv("LIBCOUCHBASE_VERBOSE_TESTS") == NULL) {
        freopen("/dev/null", "w", stdout);
    }

    setup((char **)args);

    ret = libcouchbase_store(session, &error, LIBCOUCHBASE_SET,
                             "key", 3, NULL, 0, 0, 0, 0);
    if (ret != LIBCOUCHBASE_SUCCESS) {
        err_exit("failed to store key");
    }

    if (error == 0xffff) {
        err_exit("libcouchbase_store didn't wait for the callback");
    }
    error = 0xffff;

    ret = libcouchbase_store(session, &error, LIBCOUCHBASE_ADD,
                             "key", 3, NULL, 0, 0, 0, 0);
    if (ret != LIBCOUCHBASE_KEY_EEXISTS || error != LIBCOUCHBASE_KEY_EEXISTS) {
        err_exit("Expected the callback to set key eexists");
    }

    teardown();
    return 0;
}
