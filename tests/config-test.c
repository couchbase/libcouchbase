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

#include "internal.h" /* libcouchbase_t definition */


#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <event.h>

#include "server.h"
#include "test.h"

int config_cnt;
int store_cnt;

static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t err,
                           const char *errinfo)
{
    (void)instance;
    err_exit("Error %s: %s", libcouchbase_strerror(instance, err), errinfo);
}

static void vbucket_state_callback(libcouchbase_server_t *server)
{
    config_cnt++;
    server->instance->io->stop_event_loop(server->instance->io);
}

struct rvbuf
{
    libcouchbase_error_t error;
    const char *bytes;
    libcouchbase_size_t nbytes;
};

static void storage_callback(libcouchbase_t instance,
                             const void *cookie,
                             libcouchbase_storage_t operation,
                             libcouchbase_error_t error,
                             const void *key, libcouchbase_size_t nkey,
                             libcouchbase_cas_t cas)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    store_cnt++;
    instance->io->stop_event_loop(instance->io);

    (void)operation;
    (void)key;
    (void)nkey;
    (void)cas;
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
    instance->io->stop_event_loop(instance->io);

    (void)key;
    (void)nkey;
    (void)cas;
    (void)flags;
}

static void smoke_test(void)
{
    struct libcouchbase_io_opt_st *io;
    const void *mock;
    const char *endpoint;
    const char *argv[] = {"--nodes", "20", NULL};
    libcouchbase_t instance;

    mock = start_mock_server((char **)argv);
    if (mock == NULL) {
        err_exit("Failed to start mock server");
    }

    io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT, NULL, NULL);
    if (io == NULL) {
        err_exit("Failed to create IO instance");
    }

    endpoint = get_mock_http_server(mock);
    instance = libcouchbase_create(endpoint, "Administrator", "password", NULL, io);
    if (instance == NULL) {
        err_exit("Failed to create libcouchbase instance");
    }

    (void)libcouchbase_set_error_callback(instance, error_callback);
    instance->vbucket_state_listener = vbucket_state_callback;

    if (libcouchbase_connect(instance) != LIBCOUCHBASE_SUCCESS) {
        err_exit("Failed to connect libcouchbase instance to server");
    }
    config_cnt = 0;
    io->run_event_loop(io);
    assert(config_cnt == 20);

    config_cnt = 0;
    failover_node(mock, 0, NULL);
    io->run_event_loop(io);
    assert(config_cnt == 19);

    config_cnt = 0;
    respawn_node(mock, 0, NULL);
    io->run_event_loop(io);
    assert(config_cnt == 20);

    libcouchbase_destroy(instance);
    shutdown_mock_server(mock);
}

static void buffer_relocation_test(void)
{
    struct libcouchbase_io_opt_st *io;
    const void *mock;
    const char *endpoint;
    const char *argv[] = {"--nodes", "2", NULL};
    libcouchbase_t instance;
    libcouchbase_error_t err;
    struct rvbuf rv;
    const char *key = "foo", *val = "bar";
    libcouchbase_size_t nkey = strlen(key), nval = strlen(val);
    int vb, idx;

    mock = start_mock_server((char **)argv);
    if (mock == NULL) {
        err_exit("Failed to start mock server");
    }

    io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT, NULL, NULL);
    if (io == NULL) {
        err_exit("Failed to create IO instance");
    }

    endpoint = get_mock_http_server(mock);
    instance = libcouchbase_create(endpoint, "Administrator", "password", NULL, io);
    if (instance == NULL) {
        err_exit("Failed to create libcouchbase instance");
    }

    (void)libcouchbase_set_error_callback(instance, error_callback);
    (void)libcouchbase_set_storage_callback(instance, storage_callback);
    (void)libcouchbase_set_get_callback(instance, get_callback);
    instance->vbucket_state_listener = vbucket_state_callback;

    if (libcouchbase_connect(instance) != LIBCOUCHBASE_SUCCESS) {
        err_exit("Failed to connect libcouchbase instance to server");
    }
    io->run_event_loop(io);

    /* schedule SET operation */
    err = libcouchbase_store(instance, &rv, LIBCOUCHBASE_SET,
                            key, nkey, val, nval, 0, 0, 0);
    assert(err == LIBCOUCHBASE_SUCCESS);

    /* determine what server should receive that operation */
    vb = vbucket_get_vbucket_by_key(instance->vbucket_config, key, nkey);
    idx = instance->vb_server_map[vb];

    /* switch off that server */
    failover_node(mock, idx, NULL);

    /* execute event loop to reconfigure client and execute operation */
    config_cnt = 0;
    store_cnt = 0;
    /* it should never return LIBCOUCHBASE_NOT_MY_VBUCKET */
    while (config_cnt == 0 || store_cnt == 0) {
        memset(&rv, 0, sizeof(rv));
        io->run_event_loop(io);
        assert(err != LIBCOUCHBASE_NOT_MY_VBUCKET);
    }

    /* check that value was actually set */
    memset(&rv, 0, sizeof(rv));
    err = libcouchbase_mget(instance, &rv, 1, (const void * const *)&key, &nkey, NULL);
    assert(err == LIBCOUCHBASE_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LIBCOUCHBASE_SUCCESS);
    assert(memcmp(rv.bytes, "bar", 3) == 0);

    libcouchbase_destroy(instance);
    shutdown_mock_server(mock);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    if (getenv("LIBCOUCHBASE_VERBOSE_TESTS") == NULL) {
        freopen("/dev/null", "w", stdout);
    }

    smoke_test();
    buffer_relocation_test();

    return EXIT_SUCCESS;
}
