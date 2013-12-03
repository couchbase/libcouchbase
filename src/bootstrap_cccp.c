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

static void config_callback(lcb_server_t *server, lcb_error_t error, const char *json);

static lcb_error_t cccp_setup(lcb_t instance);
static void cccp_cleanup(lcb_t instance);
static lcb_error_t cccp_connect(lcb_t instance);

void lcb_bootstrap_use_cccp(lcb_t instance)
{
    instance->bootstrap.type = LCB_CONFIG_TRANSPORT_CCCP;
    instance->bootstrap.connection = &instance->bootstrap.via.cccp.server.connection;
    instance->bootstrap.setup = cccp_setup;
    instance->bootstrap.cleanup = cccp_cleanup;
    instance->bootstrap.connect = cccp_connect;
}

static lcb_error_t cccp_setup(lcb_t instance)
{
    lcb_error_t rc;
    lcb_server_t *serv = &instance->bootstrap.via.cccp.server;

    instance->bootstrap.via.cccp.next_config = NULL;
    /* TODO check if connected server sockets can be re-used */

    rc = lcb_setup_sasl(instance);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    memset(serv, 0, sizeof(*serv));
    serv->index = -1;
    serv->instance = instance;
    rc = lcb_connection_init(&serv->connection, instance);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    serv->connection.data = serv;
    instance->callbacks.cluster_config = config_callback;
    return LCB_SUCCESS;
}

static void cccp_cleanup(lcb_t instance)
{
    lcb_server_destroy(&instance->bootstrap.via.cccp.server);
}

static lcb_error_t cccp_connect(lcb_t instance)
{
    lcb_error_t rc;
    lcb_connection_result_t connrc;
    protocol_binary_request_set_cluster_config req;
    lcb_server_t *server = &instance->bootstrap.via.cccp.server;
    lcb_connection_t conn = &server->connection;

    rc = lcb_init_next_host(instance, 11210);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    conn->on_connect_complete = lcb_server_connect_handler;
    conn->on_timeout = lcb_bootstrap_timeout_handler;
    conn->evinfo.handler = lcb_server_v0_event_handler;
    conn->completion.read = lcb_server_v1_read_handler;
    conn->completion.write = lcb_server_v1_write_handler;
    conn->completion.error = lcb_server_v1_error_handler;
    conn->timeout.usec = instance->config.bootstrap_timeout;
    if (lcb_connection_reset_buffers(conn) != LCB_SUCCESS) {
        return LCB_CLIENT_ENOMEM;
    }
    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = CMD_GET_CLUSTER_CONFIG;
    req.message.header.request.opaque = ++instance->seqno;
    lcb_server_complete_packet(server, NULL, req.bytes, sizeof(req.bytes));
    instance->last_error = LCB_SUCCESS;
    connrc = lcb_connection_start(conn, LCB_CONNSTART_NOCB | LCB_CONNSTART_ASYNCERR);
    if (connrc == LCB_CONN_ERROR) {
        return LCB_NETWORK_ERROR;
    }
    if (instance->config.syncmode == LCB_SYNCHRONOUS) {
        lcb_wait(instance);
    }

    return instance->last_error;
}

static void config_callback(lcb_server_t *server, lcb_error_t error, const char *json)
{
    VBUCKET_CONFIG_HANDLE config;
    lcb_t instance = server->instance;

    server->connection.timeout.usec = 0;
    lcb_connection_cancel_timer(&server->connection);
    if (error != LCB_SUCCESS) {
        lcb_error_handler(instance, error, "Failed to receive configration");
        return;
    }
    config = vbucket_config_create();
    if (config == NULL) {
        lcb_error_handler(instance, LCB_CLIENT_ENOMEM, "Failed to allocate memory for configuration");
        return;
    }
    if (vbucket_config_parse2(config, LIBVBUCKET_SOURCE_MEMORY, json, server->connection.host)) {
        vbucket_config_destroy(config);
        lcb_error_handler(instance, LCB_PROTOCOL_ERROR, vbucket_get_error_message(config));
        return;
    }
    lcb_update_vbconfig(instance, config);
}
