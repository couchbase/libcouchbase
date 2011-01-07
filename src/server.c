/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Membase, Inc.
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
 * This file contains the functions to operate on libembase_server objects
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

/**
 * Release all allocated resources for this server instance
 * @param server the server to destroy
 */
void libmembase_server_destroy(libmembase_server_t *server)
{
    if (server->sasl_conn != NULL) {
        sasl_dispose(&server->sasl_conn);
    }

    if (server->ev_flags != 0) {
        if (event_del(&server->ev_event) == -1) {
            abort();
        }
    }

    if (server->sock != INVALID_SOCKET) {
        EVUTIL_CLOSESOCKET(server->sock);
    }

    if (server->root_ai != NULL) {
        freeaddrinfo(server->root_ai);
    }

    free(server->hostname);
    free(server->output.data);
    free(server->cmd_log.data);
    free(server->pending.data);
    free(server->input.data);
    memset(server, 0xff, sizeof(*server));
}


/**
 * Get the name of the local endpoint
 * @param sock The socket to query the name for
 * @param buffer The destination buffer
 * @param buffz The size of the output buffer
 * @return true if success, false otherwise
 */
static bool get_local_address(evutil_socket_t sock,
                              char *buffer,
                              size_t bufsz)
{
    char h[NI_MAXHOST];
    char p[NI_MAXSERV];
    struct sockaddr_storage saddr;
    socklen_t salen = sizeof(saddr);

    if ((getsockname(sock, (struct sockaddr *)&saddr, &salen) < 0) ||
        (getnameinfo((struct sockaddr *)&saddr, salen, h, sizeof(h),
                     p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV) < 0) ||
        (snprintf(buffer, bufsz, "%s;%s", h, p) < 0))
    {
        return false;
    }

    return true;
}

/**
 * Get the name of the remote enpoint
 * @param sock The socket to query the name for
 * @param buffer The destination buffer
 * @param buffz The size of the output buffer
 * @return true if success, false otherwise
 */
static bool get_remote_address(evutil_socket_t sock,
                               char *buffer,
                               size_t bufsz)
{
    char h[NI_MAXHOST];
    char p[NI_MAXSERV];
    struct sockaddr_storage saddr;
    socklen_t salen = sizeof(saddr);

    if ((getpeername(sock, (struct sockaddr *)&saddr, &salen) < 0) ||
        (getnameinfo((struct sockaddr *)&saddr, salen, h, sizeof(h),
                     p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV) < 0) ||
        (snprintf(buffer, bufsz, "%s;%s", h, p) < 0))
    {
        return false;
    }

    return true;
}

/**
 * Start the SASL auth for a given server by sending the SASL_LIST_MECHS
 * packet to the server.
 * @param server the server object to auth agains
 */
static void start_sasl_auth_server(libmembase_server_t *server)
{
    protocol_binary_request_no_extras req = {
        .message.header.request = {
            .magic = PROTOCOL_BINARY_REQ,
            .opcode = PROTOCOL_BINARY_CMD_SASL_LIST_MECHS,
            .datatype = PROTOCOL_BINARY_RAW_BYTES
        }
    };
    libmembase_server_buffer_complete_packet(server, &server->output,
                                             req.bytes, sizeof(req.bytes));
    // send the data and add it to libevent..
    libmembase_server_event_handler(0, EV_WRITE, server);
}

void libmembase_server_connected(libmembase_server_t *server)
{
    server->connected = true;

    // move all pending data!
    if (server->pending.avail > 0) {
        grow_buffer(&server->output, server->pending.avail);
        memcpy(server->output.data + server->output.avail,
               server->pending.data, server->pending.avail);
        server->output.avail += server->pending.avail;
        server->pending.avail = 0;
        // Send the pending data!
        libmembase_server_event_handler(0, EV_WRITE, server);
    }
}

static void socket_connected(libmembase_server_t *server)
{
    char local[NI_MAXHOST + NI_MAXSERV + 2];
    char remote[NI_MAXHOST + NI_MAXSERV + 2];

    get_local_address(server->sock, local, sizeof(local));
    get_remote_address(server->sock, remote, sizeof(remote));

    assert(sasl_client_new("membase", server->hostname, local, remote,
                           server->instance->sasl.callbacks, 0,
                           &server->sasl_conn) == SASL_OK);

    if (vbucket_config_get_user(server->instance->vbucket_config) == NULL) {
        // No SASL AUTH needed
        libmembase_server_connected(server);
    } else {
        start_sasl_auth_server(server);
    }

    // Set the correct event handler
    libmembase_server_update_event(server, EV_READ,
                                   libmembase_server_event_handler);
}

static bool server_connect(libmembase_server_t *server);
static void try_next_server_connect(libmembase_server_t *server);


static void server_connect_handler(evutil_socket_t sock, short which, void *arg)
{
    libmembase_server_t *server = arg;
    if (!server_connect(server)) {
        try_next_server_connect(server);
    }
}

static bool server_connect(libmembase_server_t *server) {
    bool retry;
    do {
        retry = false;
        if (connect(server->sock, server->curr_ai->ai_addr,
                    server->curr_ai->ai_addrlen) == 0) {
            // connected
            socket_connected(server);
            return true;
        } else {
            switch (errno) {
            case EINTR:
                retry = true;
                break;
            case EISCONN:
                socket_connected(server);
                return true;
            case EINPROGRESS: /* First call to connect */
                libmembase_server_update_event(server,
                                               EV_WRITE,
                                               server_connect_handler);
                return true;
            case EALREADY: /* Subsequent calls to connect */
                return true;

            default:
                fprintf(stderr, "connect fail: %s\n",
                        strerror(errno));
                EVUTIL_CLOSESOCKET(server->sock);
                return false;
            }
        }
    } while (retry);
    // not reached
    return false;
}

static void try_next_server_connect(libmembase_server_t *server) {
    while (server->curr_ai != NULL) {
        server->sock = socket(server->curr_ai->ai_family,
                              server->curr_ai->ai_socktype,
                              server->curr_ai->ai_protocol);
        if (server->sock != -1) {
            if (evutil_make_socket_nonblocking(server->sock) != 0) {
                EVUTIL_CLOSESOCKET(server->sock);
                server->curr_ai = server->curr_ai->ai_next;
                continue;
            }

            if (server_connect(server)) {
                return ;
            }
        }
        server->curr_ai = server->curr_ai->ai_next;
    }

    // @todo notify the lib if we failed to connect to all ports..
}


void libmembase_server_initialize(libmembase_server_t *server, int servernum)
{
    /* Initialize all members */
    server->current_packet = (size_t)-1;
    const char *n = vbucket_config_get_server(server->instance->vbucket_config,
                                              servernum);
    server->hostname = strdup(n);
    char *p = strchr(server->hostname, ':');
    *p = '\0';
    server->port = p + 1;

    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,
        .ai_socktype = SOCK_STREAM,
        .ai_family = AF_UNSPEC
    };

    int error = getaddrinfo(server->hostname, server->port,
                            &hints, &server->root_ai);
    server->curr_ai = server->root_ai;
    if (error == 0) {
        try_next_server_connect(server);
    } else {
        server->sock = -1;
        server->root_ai = NULL;
    }
}

void libmembase_server_send_packets(libmembase_server_t *server)
{
    if (server->connected) {
        libmembase_server_update_event(server, EV_READ|EV_WRITE,
                                       libmembase_server_event_handler);
    }
}
