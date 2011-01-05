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
 * This file contains the functions to create / destroy the libmembase instance
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"

LIBMEMBASE_API
libmembase_t libmembase_create(const char *host,
                               const char *user,
                               const char *passwd,
                               const char *bucket,
                               struct event_base *base)
{
    assert(sasl_client_init(NULL) == SASL_OK);

    libmembase_t ret = calloc(1, sizeof(*ret));

    if (ret == NULL) {
        return NULL;
    }
    libmembase_initialize_packet_handlers(ret);

    ret->host = strdup(host);
    char *p = strchr(host, ':');
    if (p == NULL) {
        ret->port = "8091";
    } else {
        *p = '\0';
        ret->port = p + 1;
    }

    ret->user = strdup(user);
    ret->passwd = strdup(passwd);
    ret->bucket = strdup(bucket);

    if (ret->host == NULL || ret->user == NULL || ret->passwd == NULL ||
        ret->bucket == NULL) {
        libmembase_destroy(ret);
        return NULL;
    }

    ret->sock = -1;
    ret->ev_base = base;

    return ret;
}

/**
 * Release all allocated resources for this server instance
 * @param server the server to destroy
 */
static void libmembase_destroy_server(libmembase_server_t *server)
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

    if (server->ai != NULL) {
        freeaddrinfo(server->ai);
    }

    free(server->output.data);
    free(server->cmd_log.data);
    free(server->input.data);
    memset(server, 0xff, sizeof(*server));
}

LIBMEMBASE_API
void libmembase_destroy(libmembase_t instance)
{
    free(instance->host);
    free(instance->user);
    free(instance->passwd);
    free(instance->bucket);

    if (instance->sock != INVALID_SOCKET) {
        EVUTIL_CLOSESOCKET(instance->sock);
    }

    if (instance->ai != NULL) {
        freeaddrinfo(instance->ai);
    }

    if (instance->vbucket_config != NULL) {
        vbucket_config_destroy(instance->vbucket_config);
    }

    for (size_t ii = 0; ii < instance->nservers; ++ii) {
        libmembase_destroy_server(instance->servers + ii);
    }
    free(instance->servers);

    memset(instance, 0xff, sizeof(*instance));
    free(instance);
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
    libmembase_server_complete_packet(server, req.bytes, sizeof(req.bytes));
    // send the data and add it to libevent..
    libmembase_server_event_handler(0, EV_WRITE, server);
}

/**
 * Callback functions called from libsasl to get the username to use for
 * authentication.
 *
 * @param context ponter to the libmembase_t instance running the sasl bits
 * @param id the piece of information libsasl wants
 * @param result where to store the result (OUT)
 * @param len The length of the data returned (OUT)
 * @return SASL_OK if succes
 */
static int sasl_get_username(void *context, int id, const char **result,
                             unsigned int *len)
{
    if (!context || !result || (id != SASL_CB_USER && id != SASL_CB_AUTHNAME)) {
        return SASL_BADPARAM;
    }

    libmembase_t instance = context;
    *result = instance->sasl.name;
    if (len) {
        *len = (unsigned int)strlen(*result);
    }

    return SASL_OK;
}

/**
 * Callback functions called from libsasl to get the password to use for
 * authentication.
 *
 * @param context ponter to the libmembase_t instance running the sasl bits
 * @param id the piece of information libsasl wants
 * @param psecret where to store the result (OUT)
 * @return SASL_OK if succes
 */
static int sasl_get_password(sasl_conn_t *conn, void *context, int id,
                        sasl_secret_t **psecret)
{
    if (!conn || ! psecret || id != SASL_CB_PASS) {
        return SASL_BADPARAM;
    }

    libmembase_t instance = context;
    *psecret = &instance->sasl.password.secret;
    return SASL_OK;
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
 * Update the list of servers and connect to the new ones
 * @param instance the instance to update the serverlist for.
 *
 * @todo use non-blocking connects and timeouts
 * @todo try to reshuffle all pending operations!
 * @todo use the diff functionality to avoid reshuffle all of the pending ops
 */
static void libmembase_update_serverlist(libmembase_t instance)
{
    if (instance->vbucket_config != NULL) {
        vbucket_config_destroy(instance->vbucket_config);
    }

    instance->vbucket_config = vbucket_config_parse_string(instance->vbucket_stream.input.data);
    if (instance->vbucket_config == NULL) {
        // ERROR SYNTAX ERROR
        fprintf(stdout, "Syntax Error [%s]\n", instance->vbucket_stream.input.data);
        return;
    }

    // @todo we shouldn't kill all of them, but fix that later on (remember
    // to cancel all ongoing crap etc..
    libmembase_server_t *servers = instance->servers;
    for (size_t ii = 0; ii < instance->nservers; ++ii) {
        libmembase_destroy_server(instance->servers + ii);
    }
    free(instance->servers);
    instance->servers = NULL;
    instance->nservers = 0;

    uint16_t max = (uint16_t)vbucket_config_get_num_vbuckets(instance->vbucket_config);
    size_t num = (size_t)vbucket_config_get_num_servers(instance->vbucket_config);
    instance->nservers = num;
    servers = calloc(num, sizeof(libmembase_server_t));

    instance->sasl.name = vbucket_config_get_user(instance->vbucket_config);
    memset(instance->sasl.password.buffer, 0,
           sizeof(instance->sasl.password.buffer));
    const char *passwd = vbucket_config_get_password(instance->vbucket_config);
    if (passwd) {
        instance->sasl.password.secret.len = strlen(passwd);
        strcpy((char*)instance->sasl.password.secret.data, passwd);
    }

    sasl_callback_t sasl_callbacks[4] = {
        { SASL_CB_USER, (int(*)(void))&sasl_get_username, instance },
        { SASL_CB_AUTHNAME, (int(*)(void))&sasl_get_username, instance },
        { SASL_CB_PASS, (int(*)(void))&sasl_get_password, instance },
        { SASL_CB_LIST_END, NULL, NULL }
    };
    memcpy(instance->sasl.callbacks, sasl_callbacks, sizeof(sasl_callbacks));

    for (size_t ii = 0; ii < num; ++ii) {
        servers[ii].instance = instance;
        servers[ii].current_packet = (size_t)-1;

        struct addrinfo hints = {
            .ai_flags = AI_PASSIVE,
            .ai_socktype = SOCK_STREAM,
            .ai_family = AF_UNSPEC
        };

        char *h;
        h = strdup(vbucket_config_get_server(instance->vbucket_config, (int)ii));
        char *p = strchr(h, ':');
        *p = '\0';
        ++p;

        int error = getaddrinfo(h, p, &hints, &servers[ii].ai);
        if (error == 0) {
            /* @todo make the connects non-blocking */
            struct addrinfo *ai = servers[ii].ai;
            while (ai != NULL) {
                servers[ii].sock = socket(ai->ai_family,
                                          ai->ai_socktype,
                                          ai->ai_protocol);
                if (servers[ii].sock != -1) {
                    if (connect(servers[ii].sock, ai->ai_addr,
                                ai->ai_addrlen) != -1 &&
                        evutil_make_socket_nonblocking(servers[ii].sock) == 0) {

                        char local[NI_MAXHOST + NI_MAXSERV + 2];
                        char remote[NI_MAXHOST + NI_MAXSERV + 2];

                        get_local_address(servers[ii].sock, local,
                                          sizeof(local));

                        get_remote_address(servers[ii].sock, remote,
                                           sizeof(remote));

                        int ret = sasl_client_new("membase", h,
                                                  local, remote,
                                                  instance->sasl.callbacks, 0,
                                                  &servers[ii].sasl_conn);
                        assert(ret == SASL_OK);
                        break;
                    }
                    EVUTIL_CLOSESOCKET(servers[ii].sock);
                    servers[ii].sock = -1;
                }
                ai = ai->ai_next;
            }
        } else {
            servers[ii].sock = -1;
            servers[ii].ai = NULL;
        }
    }

    /*
     * Run through all of the vbuckets and build a map of what they need.
     * It would have been nice if I could query libvbucket for the number
     * of vbuckets a server got, but there isn't at the moment..
     */
    instance->nvbuckets = max;
    free(instance->vb_server_map);
    instance->vb_server_map = calloc(max, sizeof(uint16_t));
    for (int ii = 0; ii < max; ++ii) {
        int idx = vbucket_get_master(instance->vbucket_config, ii);
        instance->vb_server_map[ii] = (uint16_t)idx;
    }

    instance->servers = servers;

    if (vbucket_config_get_user(instance->vbucket_config) == NULL) {
        if (instance->vbucket_state_listener != NULL) {
            for (size_t ii = 0; ii < instance->nservers; ++ii) {
                // fire notifications!
                instance->vbucket_state_listener(instance->servers + ii);
            }
        }
    } else {
        for (size_t ii = 0; ii < instance->nservers; ++ii) {
            start_sasl_auth_server(instance->servers + ii);
        }
    }
}

/**
 * Try to parse the piece of data we've got available to see if we got all
 * the data for this "chunk"
 * @param instance the instance containing the data
 * @return true if we got all the data we need, false otherwise
 */
static bool parse_chunk(libmembase_t instance)
{
    buffer_t *buffer = &instance->vbucket_stream.input;

    if (instance->vbucket_stream.chunk_size == (size_t)-1) {
        char *ptr = strstr(buffer->data, "\r\n");
        if (ptr == NULL) {
            // We need more data!
            return false;
        }
        ptr += 2;

        long val = strtol(buffer->data, NULL, 16);
        val += 2;
        instance->vbucket_stream.chunk_size = (size_t)val;
        buffer->avail -= (size_t)(ptr - buffer->data);
        memmove(buffer->data, ptr, buffer->avail);
        buffer->data[buffer->avail] = '\0';
    }

    if (buffer->avail < instance->vbucket_stream.chunk_size) {
        // need more data!
        return false;
    }

    // I've got everything, but there is a trailing \r\n I don't want..
    buffer->data[instance->vbucket_stream.chunk_size - 2] = '\0';
    return true;
}

/**
 * Try to parse the headers in the input chunk.
 *
 * @param instance the instance containing the data
 * @return 0 success, 1 we need more data, -1 incorrect response
 */
static int parse_header(libmembase_t instance)
{
    buffer_t *buffer = &instance->vbucket_stream.input;
    char *ptr = strstr(buffer->data, "\r\n\r\n");

    if (ptr != NULL) {
        *ptr = '\0';
        ptr += 4;
    } else if ((ptr = strstr(buffer->data, "\n\n")) != NULL) {
        *ptr = '\0';
        ptr += 2;
    } else {
        /* We need more data! */
        return 1;
    }

    /* parse the headers I care about... */
    if (memcmp(buffer->data, "HTTP/1.1 200 OK", strlen("HTTP/1.1 200 OK")) != 0) {
        /* incorrect response */
        return -1;
    }

    if (strstr(buffer->data, "Transfer-Encoding: chunked") == NULL) {
        fprintf(stderr, "Unsupported format\n");
        return -1;
    }

    instance->vbucket_stream.header = strdup(buffer->data);
    // realign remaining data..
    buffer->avail -= (size_t)(ptr - buffer->data);
    memmove(buffer->data, ptr, buffer->avail);
    buffer->data[buffer->avail] = '\0';
    instance->vbucket_stream.chunk_size = (size_t)-1;

    return 0;
}

/** Don't create any buffers less than 2k */
const size_t min_buffer_size = 2048;

/**
 * Grow a buffer so that it got at least a minimum size of available space.
 * I'm <b>always</b> allocating one extra byte to add a '\0' so that if you
 * use one of the str* functions you won't run into random memory.
 *
 * @param buffer the buffer to grow
 * @param min_free the minimum amount of free space I need
 * @return true if success, false otherwise
 */
bool grow_buffer(buffer_t *buffer, size_t min_free) {
    if (min_free == 0) {
        // no minimum size requested, just ensure that there is at least
        // one byte there...
        min_free = 1;
    }

    if (buffer->size - buffer->avail < min_free) {
        size_t next = buffer->size ? buffer->size << 1 : min_buffer_size;

        while ((next - buffer->avail) < min_free) {
            next <<= 1;
        }

        char *ptr = realloc(buffer->data, next + 1);
        if (ptr == NULL) {
            return false;
        }
        ptr[next] = '\0';
        buffer->data = ptr;
        buffer->size = next;
    }

    return true;
}

/**
 * Callback from libevent when we read from the REST socket
 * @param sock the readable socket
 * @param which what kind of events we may do
 * @param arg pointer to the libmembase instance
 */
static void vbucket_stream_handler(evutil_socket_t sock, short which, void *arg)
{
    assert(sock != INVALID_SOCKET);
    assert((which & EV_WRITE) == 0);

    libmembase_t instance = arg;

    ssize_t nr;
    size_t avail;
    buffer_t *buffer = &instance->vbucket_stream.input;
    do {
        if (!grow_buffer(buffer, 1)) {
            // ERROR MEMORY ALLOCATION!
            fprintf(stderr, "Failed to allocate memory\n");
            return ;
        }

        avail = (buffer->size - buffer->avail);
        nr = recv(instance->sock, buffer->data + buffer->avail, avail, 0);
        if (nr < 0) {
            switch (errno) {
            case EINTR:
                break;
            case EWOULDBLOCK:
                return ;
            default:
                /* ERROR READING SOCKET!! */
                fprintf(stderr, "Failed to read from socket: %s\n", strerror(errno));
                return ;
            }
        } else if (nr == 0) {
            /* Socket closed! */
            fprintf(stderr, "vbucket stream socket is closed!\n");
            exit(1);
            return ;
        }
        buffer->avail += (size_t)nr;
        buffer->data[buffer->avail] = '\0';
    } while ((size_t)nr == avail);

    if (instance->vbucket_stream.header == NULL) {
        if (parse_header(instance) == -1) {
            fprintf(stderr, "Illegal syntax!\n");
            abort();
        }
    }

    if (instance->vbucket_stream.header != NULL) {
        bool done;
        do {
            done = true;
            if (parse_chunk(instance)) {
                if (*instance->vbucket_stream.input.data == '{') {
                    libmembase_update_serverlist(instance);
                } else if (instance->vbucket_stream.chunk_size != 6 &&
                           memcmp(instance->vbucket_stream.input.data,
                                  "\n\n\n\n", 4 == 0)) {
                    fprintf(stderr, "Ignore unknown chunk: [%s]\n",
                            instance->vbucket_stream.input.data);
                }
                // prepare for the next update from the upsteam server:
                instance->vbucket_stream.input.avail -= instance->vbucket_stream.chunk_size;

                memmove(instance->vbucket_stream.input.data,
                        instance->vbucket_stream.input.data + instance->vbucket_stream.chunk_size,
                        instance->vbucket_stream.input.avail);
                instance->vbucket_stream.input.data[ instance->vbucket_stream.input.avail] = '\0';
                instance->vbucket_stream.chunk_size = (size_t)-1;
                if (instance->vbucket_stream.input.avail > 0) {
                    done = false;
                }
            }
        } while (!done);
    }
}

/**
 * @todo use async connects etc
 */
LIBMEMBASE_API
libmembase_error_t libmembase_connect(libmembase_t instance)
{
    char buffer[1024];
    ssize_t offset;

    offset = snprintf(buffer, sizeof(buffer),
                      "GET /pools/default/bucketsStreaming/%s HTTP/1.1\r\n",
                      instance->bucket ? instance->bucket : "");
    if (instance->user) {
        char cred[256];
        snprintf(cred, sizeof(cred), "%s:%s", instance->user, instance->passwd);
        char base64[256];
        if (libmembase_base64_encode(cred, base64, sizeof(base64)) == -1) {
            return LIBMEMBASE_E2BIG;
        }

        offset += snprintf(buffer + offset, sizeof(buffer) - (size_t)offset,
                           "Authorization: Basic %s\r\n", base64);
    }

    offset += snprintf(buffer + offset, sizeof(buffer) - (size_t)offset,
                       "\r\n");

    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,
        .ai_socktype = SOCK_STREAM,
        .ai_family = AF_UNSPEC
    };

    int error = getaddrinfo(instance->host, instance->port,
                            &hints, &instance->ai);
    if (error != 0) {
        return LIBMEMBASE_UNKNOWN_HOST;
    }

    struct addrinfo *ai = instance->ai;
    while (ai != NULL) {
        instance->sock = socket(ai->ai_family,
                                ai->ai_socktype,
                                ai->ai_protocol);

        if (instance->sock != -1) {
            if (connect(instance->sock, ai->ai_addr,
                        ai->ai_addrlen) != -1) {
                /*
                 * Connected!
                 * The REST socket may be idle for a _looooong_ time,
                 * so let's enable SO_KEEPALIVE. We don't care if this
                 * function fail, it just means that the connection may
                 * be dropped ;-)
                 */
                int val = 1;
                socklen_t len = sizeof(val);
                setsockopt(instance->sock, SOL_SOCKET, SO_KEEPALIVE,
                           &val, len);
                break;
            }
            EVUTIL_CLOSESOCKET(instance->sock);
            instance->sock = -1;
        }
        ai = ai->ai_next;
    }

    if (instance->sock == -1) {
        return LIBMEMBASE_UNKNOWN_HOST;
    }

    ssize_t len = offset;
    offset = 0;
    ssize_t nw;
    do {
        nw = send(instance->sock, buffer + offset, (size_t)(len - offset), 0);
        if (nw == -1) {
            if (errno != EINTR) {
                EVUTIL_CLOSESOCKET(instance->sock);
                return LIBMEMBASE_NETWORK_ERROR;
            }
        } else {
            offset += nw;
        }
    } while (offset < len);

    if (evutil_make_socket_nonblocking(instance->sock) != 0) {
        EVUTIL_CLOSESOCKET(instance->sock);
        return LIBMEMBASE_NETWORK_ERROR;
    }

    instance->ev_flags = EV_READ | EV_PERSIST;
    event_set(&instance->ev_event, instance->sock,
              instance->ev_flags, vbucket_stream_handler, instance);
    event_base_set(instance->ev_base, &instance->ev_event);
    if (event_add(&instance->ev_event, NULL) == -1) {
        return LIBMEMBASE_LIBEVENT_ERROR;
    }

    return LIBMEMBASE_SUCCESS;
}

