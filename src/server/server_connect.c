/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2013 Couchbase, Inc.
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

/**
 * This file contains connection handlers for the server connection
 * @author Mark Nunberg
 * @todo add more documentation
 */

#include "internal.h"

struct nameinfo_common {
    char remote[NI_MAXHOST + NI_MAXSERV + 2];
    char local[NI_MAXHOST + NI_MAXSERV + 2];
};

static int saddr_to_string(struct sockaddr *saddr, int len,
                           char *buf, lcb_size_t nbuf)
{
    char h[NI_MAXHOST + 1];
    char p[NI_MAXSERV + 1];
    int rv;

    rv = getnameinfo(saddr, len, h, sizeof(h), p, sizeof(p),
                     NI_NUMERICHOST|NI_NUMERICSERV);
    if (rv < 0) {
        return 0;
    }

    if (snprintf(buf, nbuf, "%s;%s", h, p) < 0) {
        return 0;
    }

    return 1;
}

static int get_nameinfo(lcb_connection_t conn,
                        struct nameinfo_common *nistrs)
{
    struct sockaddr_storage sa_local;
    struct sockaddr_storage sa_remote;
    int n_salocal, n_saremote;
    struct lcb_nameinfo_st ni;
    int rv;

    n_salocal = sizeof(sa_local);
    n_saremote = sizeof(sa_remote);

    ni.local.name = (struct sockaddr *)&sa_local;
    ni.local.len = &n_salocal;

    ni.remote.name = (struct sockaddr *)&sa_remote;
    ni.remote.len = &n_saremote;

    if (conn->instance->io->version == 1) {
        rv = conn->instance->io->v.v1.get_nameinfo(conn->instance->io,
                                                   conn->sockptr,
                                                   &ni);

        if (ni.local.len == 0 || ni.remote.len == 0 || rv < 0) {
            return 0;
        }

    } else {
        socklen_t sl_tmp = sizeof(sa_local);

        rv = getsockname(conn->sockfd, ni.local.name, &sl_tmp);
        n_salocal = sl_tmp;
        if (rv < 0) {
            return 0;
        }
        rv = getpeername(conn->sockfd, ni.remote.name, &sl_tmp);
        n_saremote = sl_tmp;
        if (rv < 0) {
            return 0;
        }
    }

    if (!saddr_to_string(ni.remote.name, *ni.remote.len,
                         nistrs->remote, sizeof(nistrs->remote))) {
        return 0;
    }

    if (!saddr_to_string(ni.local.name, *ni.local.len,
                         nistrs->local, sizeof(nistrs->local))) {
        return 0;
    }
    return 1;
}

static void start_sasl_auth_server(lcb_server_t *server)
{
    /* There is no point of calling sasl_list_mechs on the server
     * because we know that the server will reply with "PLAIN"
     * it means it's just an extra ping-pong to the server
     * adding latency.. Let's do the SASL_AUTH immediately
     */
    const char *data;
    const char *chosenmech;
    char *mechlist;
    unsigned int len;
    protocol_binary_request_no_extras req;
    lcb_size_t keylen;
    lcb_size_t bodysize;
    lcb_connection_t conn = &server->connection;

    mechlist = strdup("PLAIN");
    if (mechlist == NULL) {
        lcb_error_handler(server->instance, LCB_CLIENT_ENOMEM, NULL);
        return;
    }
    if (sasl_client_start(server->sasl_conn, mechlist,
                          NULL, &data, &len, &chosenmech) != SASL_OK) {
        free(mechlist);
        lcb_error_handler(server->instance, LCB_AUTH_ERROR,
                          "Unable to start sasl client");
        return;
    }
    free(mechlist);

    keylen = strlen(chosenmech);
    bodysize = keylen + len;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SASL_AUTH;
    req.message.header.request.keylen = ntohs((lcb_uint16_t)keylen);
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = ntohl((lcb_uint32_t)(bodysize));

    lcb_server_buffer_start_packet(server, NULL, conn->output,
                                   &server->output_cookies,
                                   req.bytes, sizeof(req.bytes));
    lcb_server_buffer_write_packet(server, conn->output,
                                   chosenmech, keylen);
    lcb_server_buffer_write_packet(server, conn->output, data, len);
    lcb_server_buffer_end_packet(server, conn->output);
    lcb_sockrw_set_want(&server->connection, LCB_WRITE_EVENT, 0);
}


static void connection_error(lcb_server_t *server, lcb_error_t err)
{
    lcb_failout_server(server, err);
    if (server->instance->compat.type == LCB_CACHED_CONFIG) {
        /* Try to update the cache :S */
        lcb_schedule_config_cache_refresh(server->instance);
        return;
    }

}

static void socket_connected(lcb_connection_t conn, lcb_error_t err)
{
    lcb_server_t *server = (lcb_server_t*)conn->data;
    struct nameinfo_common nistrs;
    int sasl_in_progress;

    if (err != LCB_SUCCESS) {
        connection_error(server, err);
        return;
    }

    sasl_in_progress = (server->sasl_conn != NULL);
    if (!get_nameinfo(conn, &nistrs)) {
        /** This normally shouldn't happen! */
        connection_error(server, LCB_NETWORK_ERROR);
    }

    if (!sasl_in_progress) {
        assert(sasl_client_new("couchbase", conn->host,
                               nistrs.local, nistrs.remote,
                               server->instance->sasl.callbacks, 0,
                               &server->sasl_conn) == SASL_OK);
    }

    if (vbucket_config_get_user(server->instance->vbucket_config) == NULL) {
        /* No SASL AUTH needed */
        lcb_server_connected(server);
    } else {
        if (!sasl_in_progress) {
            start_sasl_auth_server(server);
        }
    }

    lcb_connection_cancel_timer(conn);
    lcb_sockrw_apply_want(conn);
}

static void server_timeout_handler(lcb_connection_t conn, lcb_error_t err)
{
    lcb_server_t *server = (lcb_server_t*)conn->data;
    lcb_purge_single_server(server, err);
    lcb_maybe_breakout(server->instance);
}

/**
 * Schedule a connection to the server
 */
void lcb_server_connect(lcb_server_t *server)
{
    lcb_connection_t conn = &server->connection;
    conn->on_connect_complete = socket_connected;
    conn->on_timeout = server_timeout_handler;
    conn->evinfo.handler = lcb_server_v0_event_handler;
    conn->completion.read = lcb_server_v1_read_handler;
    conn->completion.write = lcb_server_v1_write_handler;
    conn->completion.error = lcb_server_v1_error_handler;
    conn->timeout.usec = server->instance->timeout.usec;

    lcb_connection_start(conn, LCB_CONNSTART_NOCB|LCB_CONNSTART_ASYNCERR);
}
