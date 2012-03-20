/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011, 2012 Couchbase, Inc.
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
#include <libcouchbase/couchbase.h>

#include "server.h"

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t err,
                           const char *errinfo)
{
    (void)instance;
    if (err == LIBCOUCHBASE_ETIMEDOUT) {
        return;
    }
    fprintf(stderr, "Error %s", libcouchbase_strerror(instance, err));
    if (errinfo) {
        fprintf(stderr, ": %s", errinfo);
    }
    fprintf(stderr, "\n");
    abort();
    exit(EXIT_FAILURE);
}

int seqno = 0;
int stats_done = 0;

static void storage_callback(libcouchbase_t instance,
                             const void *cookie,
                             libcouchbase_storage_t operation,
                             libcouchbase_error_t error,
                             const void *key, libcouchbase_size_t nkey,
                             libcouchbase_cas_t cas)
{
    libcouchbase_io_opt_t *io = (libcouchbase_io_opt_t *)cookie;

    assert(error == LIBCOUCHBASE_SUCCESS);
    seqno--;
    if (stats_done && seqno == 0) {
        io->stop_event_loop(io);
    }
    (void)instance;
    (void)operation;
    (void)key;
    (void)nkey;
    (void)cas;
}

static void stat_callback(libcouchbase_t instance,
                          const void *cookie,
                          const char *server_endpoint,
                          libcouchbase_error_t error,
                          const void *key,
                          libcouchbase_size_t nkey,
                          const void *bytes,
                          libcouchbase_size_t nbytes)
{
    libcouchbase_error_t err;
    libcouchbase_io_opt_t *io = (libcouchbase_io_opt_t *)cookie;
    char *statkey;
    libcouchbase_size_t nstatkey;

    assert(error == LIBCOUCHBASE_SUCCESS);
    if (server_endpoint != NULL) {
        nstatkey = strlen(server_endpoint) + nkey + 2;
        statkey = malloc(nstatkey);
        snprintf(statkey, nstatkey, "%s-%s", server_endpoint, (const char*)key);
        err = libcouchbase_store(instance, io, LIBCOUCHBASE_SET,
                                 statkey, nstatkey,
                                 bytes, nbytes, 0, 0, 0);
        assert(err == LIBCOUCHBASE_SUCCESS);
        seqno++;
        free(statkey);
    } else {
        stats_done = 1;
    }
}

int main(int argc, char **argv)
{
    const void *mock;
    const char *http;
    struct libcouchbase_io_opt_st *io;
    libcouchbase_t instance;

    mock = start_mock_server(NULL);
    if (mock == NULL) {
        fprintf(stderr, "Failed to start mock server\n");
        return 1;
    }
    http = get_mock_http_server(mock);

    io = get_test_io_opts();
    if (io == NULL) {
        fprintf(stderr, "Failed to create IO instance\n");
        return 1;
    }
    instance = libcouchbase_create(http, "Administrator", "password", NULL, io);
    if (instance == NULL) {
        fprintf(stderr, "Failed to create libcouchbase instance\n");
        return 1;
    }

    (void)libcouchbase_set_error_callback(instance, error_callback);
    (void)libcouchbase_set_stat_callback(instance, stat_callback);
    (void)libcouchbase_set_storage_callback(instance, storage_callback);

    if (libcouchbase_connect(instance) != LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr, "Failed to connect libcouchbase instance to server\n");
        libcouchbase_destroy(instance);
        return 1;
    }
    libcouchbase_wait(instance);

    assert(libcouchbase_server_stats(instance, io, NULL, 0) == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);

    shutdown_mock_server(mock);

    (void)argc; (void)argv;
    return 0;
}
