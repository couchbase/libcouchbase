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

uint64_t val = 0;

static void storage_callback(libcouchbase_t instance,
                             libcouchbase_error_t error,
                             const void *key, size_t nkey,
                             uint64_t cas)
{
    (void)instance; (void)cas;
    assert(nkey == 7);
    assert(memcmp(key, "counter", 7) == 0);
    assert(error == LIBCOUCHBASE_SUCCESS);
}

static void initialize_counter(const char *host, const char *user,
                               const char *passwd, const char *bucket)
{
    struct event_base *evbase = event_base_new();
    if (evbase == NULL) {
        fprintf(stderr, "Failed to create event base\n");
        exit(1);
    }

    libcouchbase_t instance = libcouchbase_create(host, user, passwd, bucket,
                                                  evbase);
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

    (void)libcouchbase_set_storage_callback(instance, storage_callback);

    libcouchbase_store(instance, LIBCOUCHBASE_SET, "counter", 7,
                       "0", 1, 0, 0, 0);
    libcouchbase_execute(instance);
    libcouchbase_destroy(instance);
    event_base_free(evbase);
}

static void arithmetic_callback(libcouchbase_t instance,
                                libcouchbase_error_t error,
                                const void *key, size_t nkey,
                                uint64_t value, uint64_t cas)
{
    assert(nkey == 7);
    assert(memcmp(key, "counter", 7) == 0);
    assert(error == LIBCOUCHBASE_SUCCESS);
    assert(value == (val + 1));
    val = value;
    (void)cas;
    (void)instance;
}

static void do_run_arithmetic(const char *host, const char *user,
                              const char *passwd, const char *bucket)
{
    struct event_base *evbase = event_base_new();
    if (evbase == NULL) {
        fprintf(stderr, "Failed to create event base\n");
        exit(1);
    }

    libcouchbase_t instance = libcouchbase_create(host, user, passwd, bucket,
                                                  evbase);
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

    (void)libcouchbase_set_arithmetic_callback(instance,
                                               arithmetic_callback);

    for (int ii = 0; ii < 10; ++ii) {
        libcouchbase_arithmetic(instance, "counter", 7, 1, 0, true, 0);
        libcouchbase_execute(instance);
    }

    libcouchbase_destroy(instance);
    event_base_free(evbase);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *host = getenv("LIBCOUCHBASE_CLUSTER");
    if (host == NULL) {
        fprintf(stdout, "Skipping test.. \n"
                "set LIBCOUCHBASE_CLUSTER to the location of your cluster\n"
                "    LIBCOUCHBASE_USER if you want to auth as a user\n"
                "    LIBCOUCHBASE_PASSWD for the auth passwd\n"
                "    LIBCOUCHBASE_BUCKET to use a given bucket\n");
        return 0;
    }

    const char *user = getenv("LIBCOUCHBASE_USER");
    const char *passwd = getenv("LIBCOUCHBASE_PASSWD");
    const char *bucket = getenv("LIBCOUCHBASE_BUCKET");

    initialize_counter(host, user, passwd, bucket);

    for (int ii = 0; ii < 10; ++ii) {
        do_run_arithmetic(host, user, passwd, bucket);
    }

    return 0;
}
