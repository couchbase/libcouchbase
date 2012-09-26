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

#include "internal.h" /* lcb_t definition */


#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

#include "server.h"
#include "test.h"
#include "testutil.h"

int config_cnt;
int store_cnt;

static void error_callback(lcb_t instance,
                           lcb_error_t err,
                           const char *errinfo)
{
    (void)instance;
    err_exit("Error %s: %s", lcb_strerror(instance, err), errinfo);
}

static void vbucket_state_callback(lcb_server_t *server)
{
    config_cnt++;
    server->instance->io->stop_event_loop(server->instance->io);
}

struct rvbuf {
    lcb_error_t error;
    const char *bytes;
    lcb_size_t nbytes;
};

static void store_callback(lcb_t instance,
                           const void *cookie,
                           lcb_storage_t operation,
                           lcb_error_t error,
                           const lcb_store_resp_t *resp)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    store_cnt++;
    instance->io->stop_event_loop(instance->io);

    (void)operation;
    (void)resp;
}


static void get_callback(lcb_t instance,
                         const void *cookie,
                         lcb_error_t error,
                         const lcb_get_resp_t *resp)
{
    struct rvbuf *rv = (struct rvbuf *)cookie;
    rv->error = error;
    rv->bytes = malloc(resp->v.v0.nbytes);
    memcpy((void *)rv->bytes, resp->v.v0.bytes, resp->v.v0.nbytes);
    rv->nbytes = resp->v.v0.nbytes;
    instance->io->stop_event_loop(instance->io);

    (void)resp;
}

static void smoke_test(void)
{
    lcb_io_opt_t io;
    const void *mock;
    const char *endpoint;
    const char *argv[] = {"--nodes", "20", NULL};
    lcb_t instance;
    struct lcb_create_st options;

    if (is_using_real_cluster()) {
        fprintf(stderr, "Skipping \"%s\" while testing towards real cluster\n",
                __func__);
        return;
    }

    mock = start_test_server((char **)argv);
    if (mock == NULL) {
        err_exit("Failed to start mock server");
    }

    if (lcb_create_io_ops(&io, NULL) != LCB_SUCCESS) {
        fprintf(stderr, "Failed to create IO instance\n");
        exit(1);
    }

    endpoint = get_mock_http_server(mock);
    memset(&options, 0, sizeof(options));
    options.v.v0.host = endpoint;
    options.v.v0.user = "Administrator";
    options.v.v0.passwd = "password";
    options.v.v0.io = io;

    if (lcb_create(&instance, &options) != LCB_SUCCESS) {
        err_exit("Failed to create libcouchbase instance");
    }

    (void)lcb_set_error_callback(instance, error_callback);
    instance->vbucket_state_listener = vbucket_state_callback;

    if (lcb_connect(instance) != LCB_SUCCESS) {
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

    lcb_destroy(instance);
    shutdown_mock_server(mock);
}

static void buffer_relocation_test(void)
{
    lcb_io_opt_t io;
    const void *mock;
    const char *endpoint;
    const char *argv[] = {"--nodes", "2", NULL};
    lcb_t instance;
    lcb_error_t err;
    struct rvbuf rv;
    const char *key = "foo", *val = "bar";
    lcb_size_t nkey = strlen(key), nval = strlen(val);
    int vb, idx;
    lcb_store_cmd_t storecmd;
    const lcb_store_cmd_t *storecmds[] = { &storecmd };
    lcb_get_cmd_t getcmd;
    const lcb_get_cmd_t *getcmds[] = { &getcmd };
    struct lcb_create_st options;

    if (is_using_real_cluster()) {
        fprintf(stderr, "Skipping \"%s\" while testing towards real cluster\n",
                __func__);
        return;
    }

    mock = start_test_server((char **)argv);
    if (mock == NULL) {
        err_exit("Failed to start mock server");
    }

    if (lcb_create_io_ops(&io, NULL) != LCB_SUCCESS) {
        fprintf(stderr, "Failed to create IO instance\n");
        exit(1);
    }

    endpoint = get_mock_http_server(mock);
    memset(&options, 0, sizeof(options));
    options.v.v0.host = endpoint;
    options.v.v0.user = "Administrator";
    options.v.v0.passwd = "password";
    options.v.v0.io = io;

    if (lcb_create(&instance, &options) != LCB_SUCCESS) {
        err_exit("Failed to create libcouchbase instance");
    }

    (void)lcb_set_error_callback(instance, error_callback);
    (void)lcb_set_store_callback(instance, store_callback);
    (void)lcb_set_get_callback(instance, get_callback);
    instance->vbucket_state_listener = vbucket_state_callback;

    if (lcb_connect(instance) != LCB_SUCCESS) {
        err_exit("Failed to connect libcouchbase instance to server");
    }
    io->run_event_loop(io);

    /* schedule SET operation */

    memset(&storecmd, 0, sizeof(storecmd));
    storecmd.v.v0.key = key;
    storecmd.v.v0.nkey = nkey;
    storecmd.v.v0.bytes = val;
    storecmd.v.v0.nbytes = nval;
    storecmd.v.v0.operation = LCB_SET;
    err = lcb_store(instance, &rv, 1, storecmds);
    assert(err == LCB_SUCCESS);

    /* determine what server should receive that operation */
    vb = vbucket_get_vbucket_by_key(instance->vbucket_config, key, nkey);
    idx = instance->vb_server_map[vb];

    /* switch off that server */
    failover_node(mock, idx, NULL);

    /* execute event loop to reconfigure client and execute operation */
    config_cnt = 0;
    store_cnt = 0;
    /* it should never return LCB_NOT_MY_VBUCKET */
    while (config_cnt == 0 || store_cnt == 0) {
        memset(&rv, 0, sizeof(rv));
        io->run_event_loop(io);
        assert(err != LCB_NOT_MY_VBUCKET);
    }

    /* check that value was actually set */
    memset(&rv, 0, sizeof(rv));
    memset(&getcmd, 0, sizeof(getcmd));
    getcmd.v.v0.key = key;
    getcmd.v.v0.nkey = nkey;
    err = lcb_get(instance, &rv, 1, getcmds);
    assert(err == LCB_SUCCESS);
    io->run_event_loop(io);
    assert(rv.error == LCB_SUCCESS);
    assert(memcmp(rv.bytes, "bar", 3) == 0);
    free((void *)rv.bytes);
    lcb_destroy(instance);
    shutdown_mock_server(mock);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    setup_test_timeout_handler();

    if (getenv("LIBCOUCHBASE_VERBOSE_TESTS") == NULL) {
        freopen("/dev/null", "w", stdout);
    }

    smoke_test();
    buffer_relocation_test();

    return EXIT_SUCCESS;
}
