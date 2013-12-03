/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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

#include "internal.h"

static void config_v0_handler(lcb_socket_t sock, short which, void *arg);
static void config_v1_read_handler(lcb_sockdata_t *sockptr, lcb_ssize_t nr);
static void config_v1_write_handler(lcb_sockdata_t *sockptr, lcb_io_writebuf_t *wbuf, int status);
static void config_v1_error_handler(lcb_sockdata_t *sockptr);
static lcb_error_t start_connection(lcb_t instance);
static lcb_error_t handle_vbstream_read(lcb_t instance);
static void connect_done_handler(lcb_connection_t conn, lcb_error_t err);
static void v1_error_common(lcb_t instance);
static void dummy_error_callback(lcb_t instance, lcb_error_t err, const char *msg);

static lcb_error_t http_setup(lcb_t instance);
static void http_cleanup(lcb_t instance);
static lcb_error_t http_connect(lcb_t instance);

static void reset_stream_state(lcb_t instance)
{
    free(instance->bootstrap.via.http.stream.input.data);
    free(instance->bootstrap.via.http.stream.chunk.data);
    free(instance->bootstrap.via.http.stream.header);
    memset(&instance->bootstrap.via.http.stream, 0, sizeof(instance->bootstrap.via.http.stream));
    lcb_assert(LCB_SUCCESS == lcb_connection_reset_buffers(&instance->bootstrap.via.http.connection));
}

/**
 * Common function to handle parsing the event loop for both v0 and v1 io
 * implementations.
 */
static lcb_error_t handle_vbstream_read(lcb_t instance)
{
    lcb_error_t err;
    int can_retry = 0;
    int old_gen = instance->config.generation;
    lcb_connection_t conn = &instance->bootstrap.via.http.connection;

    err = lcb_parse_vbucket_stream(instance);
    if (err == LCB_SUCCESS) {
        if (instance->type == LCB_TYPE_BUCKET) {
            lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
            lcb_sockrw_apply_want(conn);
        }
        if (old_gen != instance->config.generation || instance->type == LCB_TYPE_CLUSTER) {
            lcb_connection_cancel_timer(conn);
            conn->timeout.usec = 0;
            lcb_maybe_breakout(instance);
        }
        return LCB_SUCCESS;

    } else if (err != LCB_BUSY) {
        /**
         * XXX: We only want to retry on some errors. Things which signify an
         * obvious user error should be left out here; we only care about
         * actual "network" errors
         */

        switch (err) {
        case LCB_ENOMEM:
        case LCB_AUTH_ERROR:
        case LCB_PROTOCOL_ERROR:
        case LCB_BUCKET_ENOENT:
            can_retry = 0;
            break;
        default:
            can_retry = 1;
        }

        if (instance->bootstrap.via.http.bummer &&
                (err == LCB_BUCKET_ENOENT || err == LCB_AUTH_ERROR)) {
            can_retry = 1;
        }

        if (can_retry) {
            const char *msg = "Failed to get configuration";
            lcb_bootstrap_error(instance, err, msg, LCB_CONFERR_NO_BREAKOUT);
            return err;
        } else {
            lcb_maybe_breakout(instance);
            return lcb_error_handler(instance, err, "");
        }
    }

    lcb_assert(err == LCB_BUSY);
    lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
    lcb_sockrw_apply_want(conn);

    if (old_gen != instance->config.generation) {
        lcb_connection_cancel_timer(conn);
        conn->timeout.usec = 0;
        lcb_maybe_breakout(instance);
    }

    return LCB_BUSY;
}

static void dummy_error_callback(lcb_t instance, lcb_error_t err,
                                 const char *msg)
{
    (void)instance;
    (void)err;
    (void)msg;
}

static void timeout_handler(lcb_connection_t conn, lcb_error_t err)
{
    lcb_t instance = (lcb_t)conn->data;
    const char *msg = "Configuration update timed out";
    lcb_assert(instance->config.state != LCB_CONFSTATE_CONFIGURED);

    if (instance->config.state == LCB_CONFSTATE_UNINIT) {
        /**
         * If lcb_connect was called explicitly then it means there are no
         * pending operations and we should just break out because we have
         * no valid configuration.
         */
        lcb_error_handler(instance, LCB_CONNECT_ERROR,
                          "Could not connect to server within allotted time");
        lcb_maybe_breakout(instance);
        return;
    }

    lcb_bootstrap_error(instance, err, msg, 0);
}

static void connect_done_handler(lcb_connection_t conn, lcb_error_t err)
{
    lcb_t instance = conn->instance;

    if (err == LCB_SUCCESS) {
        /**
         * Print the URI to the ringbuffer
         */
        ringbuffer_strcat(conn->output, instance->bootstrap.via.http.uri);
        lcb_assert(conn->output->nbytes > 0);

        lcb_sockrw_set_want(conn, LCB_RW_EVENT, 0);
        lcb_sockrw_apply_want(conn);
        lcb_connection_activate_timer(conn);
        return;
    }

    if (err == LCB_ETIMEDOUT) {
        timeout_handler(conn, err);
    } else {
        lcb_bootstrap_error(instance, err, "Couldn't connect", 0);
    }
}

static lcb_error_t start_connection(lcb_t instance)
{
    lcb_error_t rc;
    char *ptr;
    lcb_connection_result_t connres;
    lcb_connection_t conn = &instance->bootstrap.via.http.connection;

    /**
     * First, close the connection, if there's an open socket from a previous
     * one.
     */
    lcb_connection_close(conn);
    reset_stream_state(instance);

    conn->on_connect_complete = connect_done_handler;
    conn->evinfo.handler = config_v0_handler;
    conn->completion.read = config_v1_read_handler;
    conn->completion.write = config_v1_write_handler;
    conn->completion.error = config_v1_error_handler;
    conn->on_timeout = lcb_bootstrap_timeout_handler;
    conn->timeout.usec = instance->config.bootstrap_timeout;
    rc = lcb_init_next_host(instance, 8091);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    instance->last_error = LCB_SUCCESS;

    /* We need to fix the host part... */
    ptr = strstr(instance->bootstrap.via.http.uri, LCB_LAST_HTTP_HEADER);
    lcb_assert(ptr);
    ptr += strlen(LCB_LAST_HTTP_HEADER);
    sprintf(ptr, "Host: %s:%s\r\n\r\n", conn->host, conn->port);
    connres = lcb_connection_start(conn, 1);
    if (connres == LCB_CONN_ERROR) {
        lcb_connection_close(conn);
        return lcb_error_handler(instance, LCB_CONNECT_ERROR,
                                 "Couldn't schedule connection");
    }

    if (instance->config.syncmode == LCB_SYNCHRONOUS) {
        lcb_wait(instance);
    }

    return instance->last_error;
}

/**
 * Callback from libevent when we read from the REST socket
 * @param sock the readable socket
 * @param which what kind of events we may do
 * @param arg pointer to the libcouchbase instance
 */
static void config_v0_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_t instance = arg;
    lcb_connection_t conn = &instance->bootstrap.via.http.connection;
    lcb_sockrw_status_t status;

    lcb_assert(sock != INVALID_SOCKET);
    if ((which & LCB_WRITE_EVENT) == LCB_WRITE_EVENT) {

        status = lcb_sockrw_v0_write(conn, conn->output);
        if (status != LCB_SOCKRW_WROTE && status != LCB_SOCKRW_WOULDBLOCK) {
            lcb_bootstrap_error(instance, LCB_NETWORK_ERROR,
                                "Problem with sending data. "
                                "Failed to send data to REST server", 0);
            return;
        }

        if (lcb_sockrw_flushed(conn)) {
            lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
        }

    }

    if ((which & LCB_READ_EVENT) == 0) {
        return;
    }

    status = lcb_sockrw_v0_slurp(conn, conn->input);
    if (status != LCB_SOCKRW_READ && status != LCB_SOCKRW_WOULDBLOCK) {
        lcb_bootstrap_error(instance, LCB_NETWORK_ERROR,
                            "Problem with reading data. "
                            "Failed to send read data from REST server", 0);
        return;
    }

    handle_vbstream_read(instance);
    (void)sock;
}

static void v1_error_common(lcb_t instance)
{
    lcb_bootstrap_error(instance, LCB_NETWORK_ERROR,
                        "Problem with sending data", 0);
}

static void config_v1_read_handler(lcb_sockdata_t *sockptr, lcb_ssize_t nr)
{
    lcb_t instance;
    lcb_connection_t conn = sockptr->lcbconn;

    if (!lcb_sockrw_v1_cb_common(sockptr, NULL, (void **)&instance)) {
        return;
    }
    lcb_sockrw_v1_onread_common(sockptr, &conn->input, nr);
    if (nr < 1) {
        v1_error_common(instance);
        return;
    }

    lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
    /* automatically does apply_want */
    handle_vbstream_read(instance);
}

static void config_v1_write_handler(lcb_sockdata_t *sockptr,
                                    lcb_io_writebuf_t *wbuf,
                                    int status)
{
    lcb_t instance;
    lcb_connection_t conn = sockptr->lcbconn;

    if (!lcb_sockrw_v1_cb_common(sockptr, wbuf, (void **)&instance)) {
        return;
    }
    lcb_sockrw_v1_onwrite_common(sockptr, wbuf, &conn->output);
    if (status) {
        v1_error_common(instance);
    }

    lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
    lcb_sockrw_apply_want(conn);
}

static void config_v1_error_handler(lcb_sockdata_t *sockptr)
{
    lcb_t instance;
    if (!lcb_sockrw_v1_cb_common(sockptr, NULL, (void **)&instance)) {
        return;
    }

    v1_error_common(instance);
}

static lcb_error_t http_setup(lcb_t instance)
{
    char buffer[1024];
    lcb_ssize_t offset = 0;
    lcb_error_t err;
    lcb_connection_t conn = &instance->bootstrap.via.http.connection;

    instance->bootstrap.via.http.weird_things_threshold = LCB_DEFAULT_CONFIG_ERRORS_THRESHOLD;
    instance->bootstrap.via.http.bummer = 0;
    switch (instance->type) {
    case LCB_TYPE_BUCKET:
        offset = snprintf(buffer, sizeof(buffer),
                          "GET /pools/default/bucketsStreaming/%s HTTP/1.1\r\n",
                          instance->bucket);
        break;
    case LCB_TYPE_CLUSTER:
        offset = snprintf(buffer, sizeof(buffer), "GET /pools/ HTTP/1.1\r\n");
        break;
    default:
        return LCB_EINVAL;
    }

    err = lcb_connection_init(conn, instance);
    if (err != LCB_SUCCESS) {
        return err;
    }
    conn->data = instance;

    if (instance->password) {
        char cred[256];
        char base64[256];
        snprintf(cred, sizeof(cred), "%s:%s", instance->username, instance->password);
        if (lcb_base64_encode(cred, base64, sizeof(base64)) == -1) {
            lcb_destroy(instance);
            return LCB_EINTERNAL;
        }
        offset += snprintf(buffer + offset, sizeof(buffer) - (lcb_size_t)offset,
                           "Authorization: Basic %s\r\n", base64);
    }

    offset += snprintf(buffer + offset, sizeof(buffer) - (lcb_size_t)offset,
                       "%s", LCB_LAST_HTTP_HEADER);

    /* Add space for: Host: \r\n\r\n" */
    instance->bootstrap.via.http.uri = malloc(strlen(buffer) + strlen(instance->config.backup_nodes[0]) + 80);
    if (instance->bootstrap.via.http.uri == NULL) {
        lcb_destroy(instance);
        return LCB_CLIENT_ENOMEM;
    }
    strcpy(instance->bootstrap.via.http.uri, buffer);

    return LCB_SUCCESS;
}

static lcb_error_t http_connect(lcb_t instance)
{
    lcb_error_t ret;
    lcb_error_callback old_cb;
    lcb_connection_t conn = &instance->bootstrap.via.http.connection;

    if (instance->compat.type == LCB_MEMCACHED_CLUSTER ||
        (instance->compat.type == LCB_CACHED_CONFIG &&
         instance->config.handle != NULL &&
         instance->compat.value.cached.updating == 0)) {
        return LCB_SUCCESS;
    }
    switch (conn->state) {
    case LCB_CONNSTATE_CONNECTED:
        return LCB_SUCCESS;
    case LCB_CONNSTATE_INPROGRESS:
        return LCB_BUSY;
    default:
        old_cb = instance->callbacks.error;
        instance->callbacks.error = dummy_error_callback;
        ret = start_connection(instance);
        instance->callbacks.error = old_cb;
        return ret;
    }
}

void http_cleanup(lcb_t instance)
{
    reset_stream_state(instance);
    free(instance->bootstrap.via.http.uri);
    lcb_connection_cleanup(&instance->bootstrap.via.http.connection);
}

void lcb_bootstrap_use_http(lcb_t instance)
{
    instance->bootstrap.type = LCB_CONFIG_TRANSPORT_HTTP;
    instance->bootstrap.connection = &instance->bootstrap.via.http.connection;
    instance->bootstrap.setup = http_setup;
    instance->bootstrap.cleanup = http_cleanup;
    instance->bootstrap.connect = http_connect;
    /* initialize connection to allow early lcb_destroy() from lcb_create() */
    instance->bootstrap.via.http.connection.sockfd = INVALID_SOCKET;
    instance->bootstrap.via.http.connection.instance = instance;
}
