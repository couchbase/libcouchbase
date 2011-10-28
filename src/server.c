/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc.
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
void libcouchbase_server_destroy(libcouchbase_server_t *server)
{
    /* Cancel all pending commands */
    if (server->cmd_log.nbytes) {
        libcouchbase_server_purge_implicit_responses(server,
                                                     server->instance->seqno,
                                                     gethrtime());
    }

    if (server->sasl_conn != NULL) {
        sasl_dispose(&server->sasl_conn);
    }

    // Delete the event structure itself
    server->instance->io->destroy_event(server->instance->io,
                                        server->event);

    if (server->sock != INVALID_SOCKET) {
        server->instance->io->close(server->instance->io, server->sock);
    }

    if (server->root_ai != NULL) {
        freeaddrinfo(server->root_ai);
    }

    free(server->couch_api_base);
    free(server->hostname);
    free(server->authority);
    libcouchbase_ringbuffer_destruct(&server->output);
    libcouchbase_ringbuffer_destruct(&server->cmd_log);
    libcouchbase_ringbuffer_destruct(&server->pending);
    libcouchbase_ringbuffer_destruct(&server->input);
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
static void start_sasl_auth_server(libcouchbase_server_t *server)
{
    protocol_binary_request_no_extras req;
    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SASL_LIST_MECHS;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;

    libcouchbase_server_buffer_complete_packet(server, NULL, &server->output,
                                               &server->output_cookies,
                                               req.bytes, sizeof(req.bytes));
    // send the data and add it to libevent..
    libcouchbase_server_event_handler(server->sock, LIBCOUCHBASE_WRITE_EVENT,
                                      server);
}

void libcouchbase_server_connected(libcouchbase_server_t *server)
{
    server->connected = true;

    if (server->pending.nbytes > 0) {
        // @todo we might want to do this a bit more optimal later on..
        //       We're only using the pending ringbuffer while we're
        //       doing the SASL auth, so it shouldn't contain that
        //       much data..
        if (!libcouchbase_ringbuffer_append(&server->pending, &server->output) ||
            !libcouchbase_ringbuffer_append(&server->pending_cookies, &server->output_cookies)) {
            libcouchbase_error_handler(server->instance,
                                       LIBCOUCHBASE_ENOMEM,
                                       NULL);
        }

        // Send the pending data!
        libcouchbase_server_event_handler(server->sock,
                                          LIBCOUCHBASE_WRITE_EVENT, server);

    }
}

static void socket_connected(libcouchbase_server_t *server)
{
    char local[NI_MAXHOST + NI_MAXSERV + 2];
    char remote[NI_MAXHOST + NI_MAXSERV + 2];

    get_local_address(server->sock, local, sizeof(local));
    get_remote_address(server->sock, remote, sizeof(remote));

    assert(sasl_client_new("couchbase", server->hostname, local, remote,
                           server->instance->sasl.callbacks, 0,
                           &server->sasl_conn) == SASL_OK);

    if (vbucket_config_get_user(server->instance->vbucket_config) == NULL) {
        // No SASL AUTH needed
        libcouchbase_server_connected(server);
    } else {
        start_sasl_auth_server(server);
    }

    // Set the correct event handler
    server->instance->io->update_event(server->instance->io, server->sock,
                                       server->event, LIBCOUCHBASE_READ_EVENT,
                                       server, libcouchbase_server_event_handler);
}

static bool server_connect(libcouchbase_server_t *server);


static void server_connect_handler(evutil_socket_t sock, short which, void *arg)
{
    libcouchbase_server_t *server = arg;
    (void)sock;
    (void)which;

    server_connect(server);
}

static bool server_connect(libcouchbase_server_t *server) {
    bool retry;
    do {
        if (server->sock == INVALID_SOCKET) {
            // Try to get a socket..
            while (server->curr_ai != NULL) {
                server->sock = server->instance->io->socket(server->instance->io,
                                                            server->curr_ai->ai_family,
                                                            server->curr_ai->ai_socktype,
                                                            server->curr_ai->ai_protocol);
                if (server->sock != INVALID_SOCKET) {
                    break;
                }
                server->curr_ai = server->curr_ai->ai_next;
            }
        }

        if (server->curr_ai == NULL) {
            return false;
        }

        retry = false;
        if (server->instance->io->connect(server->instance->io,
                                          server->sock,
                                          server->curr_ai->ai_addr,
                                          (int)server->curr_ai->ai_addrlen) == 0) {
            // connected
            socket_connected(server);
            return true;
        } else {
            switch (server->instance->io->error) {
            case EINTR:
                retry = true;
                break;
            case EISCONN:
                socket_connected(server);
                return true;
            case EWOULDBLOCK:
            case EINPROGRESS: /* First call to connect */
                server->instance->io->update_event(server->instance->io,
                                                   server->sock,
                                                   server->event,
                                                   LIBCOUCHBASE_WRITE_EVENT,
                                                   server,
                                                   server_connect_handler);
                return true;
            case EALREADY: /* Subsequent calls to connect */
                return true;

            default:
                if (errno == ECONNREFUSED) {
                    retry = true;
                    server->curr_ai = server->curr_ai->ai_next;
                } else {
                    fprintf(stderr, "Connection failed: %s", strerror(server->instance->io->error));
                    // TODO: Is there a better error for this?
                    libcouchbase_error_handler(server->instance,
                                               LIBCOUCHBASE_NETWORK_ERROR,
                                               "Connection failed");
                    return false;
                }

                server->instance->io->delete_event(server->instance->io,
                                                   server->sock,
                                                   server->event);
                server->instance->io->close(server->instance->io, server->sock);
                server->sock = INVALID_SOCKET;
            }
        }
    } while (retry);
    // not reached
    return false;
}

void libcouchbase_server_initialize(libcouchbase_server_t *server, int servernum)
{
    /* Initialize all members */
    char *p;
    int error;
    struct addrinfo hints;
    const char *n = vbucket_config_get_server(server->instance->vbucket_config,
                                              servernum);
    server->authority = strdup(n);
    server->hostname = strdup(n);
    p = strchr(server->hostname, ':');
    *p = '\0';
    server->port = p + 1;

    n = vbucket_config_get_couch_api_base(server->instance->vbucket_config,
                                          servernum);
    server->couch_api_base = (n != NULL) ? strdup(n) : NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    server->event = server->instance->io->create_event(server->instance->io);
    error = getaddrinfo(server->hostname, server->port,
                        &hints, &server->root_ai);
    server->curr_ai = server->root_ai;
    if (error == 0) {
        server->sock = INVALID_SOCKET;
        server_connect(server);
    } else {
        server->sock = INVALID_SOCKET;
        server->root_ai = NULL;
    }
}

void libcouchbase_server_send_packets(libcouchbase_server_t *server)
{
    if (server->connected) {
        server->instance->io->update_event(server->instance->io,
                                           server->sock,
                                           server->event,
                                           LIBCOUCHBASE_RW_EVENT,
                                           server,
                                           libcouchbase_server_event_handler);
    }
}

int libcouchbase_server_purge_implicit_responses(libcouchbase_server_t *c,
                                                 uint32_t seqno,
                                                 hrtime_t end)
{
    protocol_binary_request_header req;
    size_t nr =  libcouchbase_ringbuffer_peek(&c->cmd_log, req.bytes,
                                              sizeof(req));
    // There should at _LEAST_ be _ONE_ message in here!
    assert(nr == sizeof(req));
    while (req.request.opaque < seqno) {
        struct libcouchbase_command_data_st ct;
        char *packet = c->cmd_log.read_head;
        uint32_t packetsize = ntohl(req.request.bodylen) + (uint32_t)sizeof(req);
        char *keyptr;

        nr = libcouchbase_ringbuffer_read(&c->output_cookies, &ct, sizeof(ct));
        assert(nr == sizeof(ct));

        switch (req.request.opcode) {
        case PROTOCOL_BINARY_CMD_GATQ:
        case PROTOCOL_BINARY_CMD_GETQ:
            if (ct.start != 0 && c->instance->histogram) {
                libcouchbase_record_metrics(c->instance, end - ct.start,
                                            req.request.opcode);
            }


            if (!libcouchbase_ringbuffer_is_continous(&c->cmd_log,
                                                      RINGBUFFER_READ,
                                                      packetsize)) {
                packet = malloc(packetsize);
                if (packet == NULL) {
                    libcouchbase_error_handler(c->instance, LIBCOUCHBASE_ENOMEM, NULL);
                    return -1;
                }

                nr = libcouchbase_ringbuffer_peek(&c->cmd_log, packet, packetsize);
                if (nr != packetsize) {
                    libcouchbase_error_handler(c->instance, LIBCOUCHBASE_EINTERNAL,
                                               NULL);
                    free(packet);
                    return -1;
                }
            }

            keyptr = packet + sizeof(req) + req.request.extlen;
            c->instance->callbacks.get(c->instance, ct.cookie,
                                       LIBCOUCHBASE_KEY_ENOENT,
                                       keyptr, ntohs(req.request.keylen),
                                       NULL, 0, 0, 0);
            if (packet != c->cmd_log.read_head) {
                free(packet);
            }
            break;
        default:
            libcouchbase_error_handler(c->instance,
                                       LIBCOUCHBASE_EINTERNAL,
                                       "Received an implicit msg I don't support");
            return -1;
        }

        libcouchbase_ringbuffer_consumed(&c->cmd_log, packetsize);
        nr =  libcouchbase_ringbuffer_peek(&c->cmd_log, req.bytes,
                                           sizeof(req));
        // The current message should also be there...
        assert(nr == sizeof(req));
    }

    return 0;
}
