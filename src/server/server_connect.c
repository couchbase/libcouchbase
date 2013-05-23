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

/**
 * Get the name of the local endpoint
 * @param sock The socket to query the name for
 * @param buffer The destination buffer
 * @param buffz The size of the output buffer
 * @return 1 if success, 0 otherwise
 */
static int get_local_address(lcb_socket_t sock,
                             char *buffer,
                             lcb_size_t bufsz)
{
    char h[NI_MAXHOST];
    char p[NI_MAXSERV];
    struct sockaddr_storage saddr;
    socklen_t salen = sizeof(saddr);

    if ((getsockname(sock, (struct sockaddr *)&saddr, &salen) < 0) ||
            (getnameinfo((struct sockaddr *)&saddr, salen, h, sizeof(h),
                         p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV) < 0) ||
            (snprintf(buffer, bufsz, "%s;%s", h, p) < 0)) {
        return 0;
    }

    return 1;
}

/**
 * Get the name of the remote enpoint
 * @param sock The socket to query the name for
 * @param buffer The destination buffer
 * @param buffz The size of the output buffer
 * @return 1 if success, 0 otherwise
 */
static int get_remote_address(lcb_socket_t sock,
                              char *buffer,
                              lcb_size_t bufsz)
{
    char h[NI_MAXHOST];
    char p[NI_MAXSERV];
    struct sockaddr_storage saddr;
    socklen_t salen = sizeof(saddr);

    if ((getpeername(sock, (struct sockaddr *)&saddr, &salen) < 0) ||
            (getnameinfo((struct sockaddr *)&saddr, salen, h, sizeof(h),
                         p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV) < 0) ||
            (snprintf(buffer, bufsz, "%s;%s", h, p) < 0)) {
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

    lcb_server_io_start(server, LCB_WRITE_EVENT);
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

    if (err != LCB_SUCCESS) {
        connection_error(server, err);
    }

    char local[NI_MAXHOST + NI_MAXSERV + 2];
    char remote[NI_MAXHOST + NI_MAXSERV + 2];
    int sasl_in_progress = (server->sasl_conn != NULL);

    get_local_address(conn->sockfd, local, sizeof(local));
    get_remote_address(conn->sockfd, remote, sizeof(remote));

    if (!sasl_in_progress) {
        assert(sasl_client_new("couchbase", conn->host, local, remote,
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

    (void)err;
}

/**
 * Schedule a connection to the server
 */
void lcb_server_connect(lcb_server_t *server)
{
    lcb_connection_t conn = &server->connection;
    conn->on_connect_complete = socket_connected;
    lcb_connection_start(conn, 1, 0);
}

/**
 * Request an IO operation on the server
 */
void lcb_server_io_start(lcb_server_t *server, short flags)
{
    lcb_io_opt_t io = server->instance->io;
    io->v.v0.update_event(io,
                          server->connection.sockfd,
                          server->connection.event,
                          flags,
                          server,
                          lcb_server_event_handler);
}
