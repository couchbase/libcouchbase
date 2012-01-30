/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011 Couchbase, Inc.
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
 * This file contains the functions to create / destroy the libcouchbase instance
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"

/**
 * Get the version of the library.
 *
 * @param version where to store the numeric representation of the
 *         version (or NULL if you don't care)
 *
 * @return the textual description of the version ('\0'
 *          terminated). Do <b>not</b> try to release this string.
 *
 */
LIBCOUCHBASE_API
const char *libcouchbase_get_version(libcouchbase_uint32_t *version)
{
    if (version != NULL) {
        *version = (libcouchbase_uint32_t)LIBCOUCHBASE_VERSION;
    }

    return LIBCOUCHBASE_VERSION_STRING;
}

LIBCOUCHBASE_API
const char *libcouchbase_get_host(libcouchbase_t instance)
{
    return instance->host;
}

LIBCOUCHBASE_API
const char *libcouchbase_get_port(libcouchbase_t instance)
{
    return instance->port;
}

LIBCOUCHBASE_API
libcouchbase_t libcouchbase_create(const char *host,
                                   const char *user,
                                   const char *passwd,
                                   const char *bucket,
                                   struct libcouchbase_io_opt_st *io)
{
    char buffer[1024];
    libcouchbase_ssize_t offset;
    libcouchbase_t ret;
    char *p;

    if (io == NULL) {
        io = libcouchbase_create_io_ops(LIBCOUCHBASE_IO_OPS_DEFAULT,
                                        NULL, NULL);
        if (io == NULL) {
            /* You can't initialize the library without a io-handler! */
            return NULL;
        }
    }

    if (host == NULL) {
        host = "localhost";
    }

    if (bucket == NULL || strlen(bucket) == 0) {
        bucket = "default";
    }

    if (sasl_client_init(NULL) != SASL_OK) {
        return NULL;
    }

    if ((ret = calloc(1, sizeof(*ret))) == NULL) {
        return NULL;
    }
    libcouchbase_initialize_packet_handlers(ret);
    libcouchbase_behavior_set_syncmode(ret, LIBCOUCHBASE_ASYNCHRONOUS);

    ret->host = strdup(host);
    if ((p = strchr(ret->host, ':')) == NULL) {
        ret->port = "8091";
    } else {
        *p = '\0';
        ret->port = p + 1;
    }

    offset = snprintf(buffer, sizeof(buffer),
                      "GET /pools/default/bucketsStreaming/%s HTTP/1.1\r\n",
                      bucket);

    if (user && passwd) {
        char cred[256];
        char base64[256];
        snprintf(cred, sizeof(cred), "%s:%s", user, passwd);
        if (libcouchbase_base64_encode(cred, base64, sizeof(base64)) == -1) {
            libcouchbase_destroy(ret);
            return NULL;
        }

        offset += snprintf(buffer + offset, sizeof(buffer) - (libcouchbase_size_t)offset,
                           "Authorization: Basic %s\r\n", base64);
    }
    offset += snprintf(buffer + offset, sizeof(buffer)-(libcouchbase_size_t)offset, "\r\n");
    ret->http_uri = strdup(buffer);

    if (ret->host == NULL || ret->http_uri == NULL) {
        libcouchbase_destroy(ret);
        return NULL;
    }

    ret->sock = INVALID_SOCKET;

    /* No error has occurred yet. */
    ret->last_error = LIBCOUCHBASE_SUCCESS;

    /* setup io iops! */
    ret->io = io;
    ret->timeout.event = ret->io->create_timer(ret->io);
    assert(ret->timeout.event);

    libcouchbase_set_timeout(ret, LIBCOUCHBASE_DEFAULT_TIMEOUT);

    return ret;
}

LIBCOUCHBASE_API
void libcouchbase_destroy(libcouchbase_t instance)
{
    libcouchbase_size_t ii;
    free(instance->host);
    free(instance->http_uri);

    if (instance->sock != INVALID_SOCKET) {
        instance->io->delete_event(instance->io, instance->sock,
                                   instance->event);
        instance->io->destroy_event(instance->io, instance->event);
        instance->io->close(instance->io, instance->sock);
    }

    if (instance->timeout.event != NULL) {
        instance->io->delete_timer(instance->io, instance->timeout.event);
        instance->io->destroy_timer(instance->io, instance->timeout.event);
        instance->timeout.event = NULL;
    }

    if (instance->ai != NULL) {
        freeaddrinfo(instance->ai);
    }

    if (instance->vbucket_config != NULL) {
        vbucket_config_destroy(instance->vbucket_config);
    }

    for (ii = 0; ii < instance->nservers; ++ii) {
        libcouchbase_server_destroy(instance->servers + ii);
    }
    free(instance->servers);
    free(instance->backup_nodes);

    if (instance->io && instance->io->destructor) {
        instance->io->destructor(instance->io);
    }
    if (instance->vbucket_stream.header) {
        free(instance->vbucket_stream.header);
        instance->vbucket_stream.header = NULL;
    }

    memset(instance, 0xff, sizeof(*instance));
    free(instance);
}

/**
 * Callback functions called from libsasl to get the username to use for
 * authentication.
 *
 * @param context ponter to the libcouchbase_t instance running the sasl bits
 * @param id the piece of information libsasl wants
 * @param result where to store the result (OUT)
 * @param len The length of the data returned (OUT)
 * @return SASL_OK if succes
 */
static int sasl_get_username(void *context, int id, const char **result,
                             unsigned int *len)
{
    libcouchbase_t instance = context;
    if (!context || !result || (id != SASL_CB_USER && id != SASL_CB_AUTHNAME)) {
        return SASL_BADPARAM;
    }

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
 * @param context ponter to the libcouchbase_t instance running the sasl bits
 * @param id the piece of information libsasl wants
 * @param psecret where to store the result (OUT)
 * @return SASL_OK if succes
 */
static int sasl_get_password(sasl_conn_t *conn, void *context, int id,
                             sasl_secret_t **psecret)
{
    libcouchbase_t instance = context;
    if (!conn || ! psecret || id != SASL_CB_PASS) {
        return SASL_BADPARAM;
    }

    *psecret = &instance->sasl.password.secret;
    return SASL_OK;
}

static void apply_vbucket_config(libcouchbase_t instance, VBUCKET_CONFIG_HANDLE config)
{
    libcouchbase_uint16_t ii, max;
    libcouchbase_size_t num;
    const char *passwd;
    char *curnode;
    sasl_callback_t sasl_callbacks[4] = {
        { SASL_CB_USER, (int(*)(void))&sasl_get_username, instance },
        { SASL_CB_AUTHNAME, (int(*)(void))&sasl_get_username, instance },
        { SASL_CB_PASS, (int(*)(void))&sasl_get_password, instance },
        { SASL_CB_LIST_END, NULL, NULL }
    };

    num = (libcouchbase_size_t)vbucket_config_get_num_servers(config);
    instance->nservers = num;
    instance->servers = calloc(num, sizeof(libcouchbase_server_t));
    instance->vbucket_config = config;
    if (instance->backup_nodes) {
        free(instance->backup_nodes);
    }
    instance->backup_nodes = calloc(num, sizeof(char *));
    curnode = strdup(instance->host);
    strcat(curnode, instance->port);
    for (ii = 0; ii < (libcouchbase_size_t)num; ++ii) {
        instance->servers[ii].instance = instance;
        libcouchbase_server_initialize(instance->servers + ii, (int)ii);
        if (strcmp(curnode, instance->servers[ii].rest_api_server) == 0) {
            instance->backup_nodes[ii] = NULL;
        } else {
            instance->backup_nodes[ii] = instance->servers[ii].rest_api_server;
        }
        /* swap with random position < ii */
        if (ii > 0) {
            libcouchbase_size_t nn = (libcouchbase_size_t)(gethrtime() >> 10) % ii;
            char *pp = instance->backup_nodes[ii];
            instance->backup_nodes[ii] = instance->backup_nodes[nn];
            instance->backup_nodes[nn] = pp;
        }
    }
    free(curnode);
    instance->sasl.name = vbucket_config_get_user(instance->vbucket_config);
    memset(instance->sasl.password.buffer, 0,
           sizeof(instance->sasl.password.buffer));
    passwd = vbucket_config_get_password(instance->vbucket_config);
    if (passwd) {
        instance->sasl.password.secret.len = strlen(passwd);
        strcpy((char*)instance->sasl.password.secret.data, passwd);
    }
    memcpy(instance->sasl.callbacks, sasl_callbacks, sizeof(sasl_callbacks));

    /*
     * Run through all of the vbuckets and build a map of what they need.
     * It would have been nice if I could query libvbucket for the number
     * of vbuckets a server got, but there isn't at the moment..
     */
    max = (libcouchbase_uint16_t)vbucket_config_get_num_vbuckets(instance->vbucket_config);
    instance->nvbuckets = max;
    free(instance->vb_server_map);
    instance->vb_server_map = calloc(max, sizeof(libcouchbase_vbucket_t));
    for (ii = 0; ii < max; ++ii) {
        instance->vb_server_map[ii] = vbucket_get_master(instance->vbucket_config, ii);
    }
}

static void relocate_packets(libcouchbase_server_t *src,
                             libcouchbase_t dst_instance)
{
    struct libcouchbase_command_data_st ct;
    protocol_binary_request_header cmd;
    libcouchbase_server_t *dst;
    libcouchbase_uint32_t nbody, npacket;
    char *body;
    libcouchbase_size_t idx;
    libcouchbase_vbucket_t vb;

    while (libcouchbase_ringbuffer_read(&src->cmd_log, cmd.bytes, sizeof(cmd.bytes))) {
        nbody = ntohl(cmd.request.bodylen); /* extlen + nkey + nval */
        npacket = sizeof(cmd.bytes) + nbody;
        body = malloc(nbody);
        if (body == NULL) {
            libcouchbase_error_handler(dst_instance, LIBCOUCHBASE_ENOMEM,
                                       "Failed to allocate memory");
            return;
        }
        assert(libcouchbase_ringbuffer_read(&src->cmd_log, body, nbody) == nbody);
        vb = ntohs(cmd.request.vbucket);
        idx = (libcouchbase_size_t)vbucket_get_master(dst_instance->vbucket_config, vb);
        dst = dst_instance->servers + idx;
        assert(libcouchbase_ringbuffer_read(&src->output_cookies, &ct, sizeof(ct)) == sizeof(ct));

        assert(libcouchbase_ringbuffer_ensure_capacity(&dst->cmd_log, npacket));
        assert(libcouchbase_ringbuffer_write(&dst->cmd_log, cmd.bytes, sizeof(cmd.bytes)) == sizeof(cmd.bytes));
        assert(libcouchbase_ringbuffer_write(&dst->cmd_log, body, nbody) == nbody);
        assert(libcouchbase_ringbuffer_ensure_capacity(&dst->output_cookies, sizeof(ct)));
        assert(libcouchbase_ringbuffer_write(&dst->output_cookies, &ct, sizeof(ct)) == sizeof(ct));

        assert(!dst->connected);
        assert(libcouchbase_ringbuffer_ensure_capacity(&dst->pending, npacket));
        assert(libcouchbase_ringbuffer_write(&dst->pending, cmd.bytes, sizeof(cmd.bytes)) == sizeof(cmd.bytes));
        assert(libcouchbase_ringbuffer_write(&dst->pending, body, nbody) == nbody);
        assert(libcouchbase_ringbuffer_ensure_capacity(&dst->pending_cookies, sizeof(ct)));
        assert(libcouchbase_ringbuffer_write(&dst->pending_cookies, &ct, sizeof(ct)) == sizeof(ct));

        free(body);
        libcouchbase_server_send_packets(dst);
    }
}

/**
 * Update the list of servers and connect to the new ones
 * @param instance the instance to update the serverlist for.
 *
 * @todo use non-blocking connects and timeouts
 */
static void libcouchbase_update_serverlist(libcouchbase_t instance)
{
    libcouchbase_size_t ii;
    VBUCKET_CONFIG_HANDLE next_config, curr_config;
    VBUCKET_CONFIG_DIFF* diff = NULL;
    libcouchbase_size_t nservers;
    libcouchbase_server_t *servers, *ss;

    curr_config = instance->vbucket_config;
    next_config = vbucket_config_parse_string(instance->vbucket_stream.input.data);
    if (next_config == NULL) {
        libcouchbase_error_handler(instance, LIBCOUCHBASE_PROTOCOL_ERROR,
                                   instance->vbucket_stream.input.data);
        return;
    }
    instance->vbucket_stream.input.avail = 0;

    if (curr_config) {
        diff = vbucket_compare(curr_config, next_config);
        if (diff && (diff->sequence_changed || diff->n_vb_changes > 0)) {
            VBUCKET_DISTRIBUTION_TYPE dist_t = vbucket_config_get_distribution_type(next_config);
            nservers = instance->nservers;
            servers = instance->servers;
            apply_vbucket_config(instance, next_config);
            for (ii = 0; ii < nservers; ++ii) {
                ss = servers + ii;
                if (dist_t == VBUCKET_DISTRIBUTION_VBUCKET) {
                    relocate_packets(ss, instance);
                } else {
                    /* other distribution types (ketama) are relying on
                     * hashing key, therefore return TMPFAIL and force users
                     * to retry */
                    libcouchbase_failout_server(ss, LIBCOUCHBASE_ETMPFAIL);
                }
                libcouchbase_server_destroy(ss);
            }

            /* Destroy old config */
            vbucket_config_destroy(curr_config);

            /* Send data and notify listeners */
            for (ii = 0; ii < instance->nservers; ++ii) {
                ss = instance->servers + ii;
                if (instance->vbucket_state_listener != NULL) {
                    instance->vbucket_state_listener(ss);
                }
                if (ss->cmd_log.nbytes != 0) {
                    libcouchbase_server_send_packets(ss);
                }
            }
        }
    } else {
        assert(instance->servers == NULL);
        assert(instance->nservers == 0);
        apply_vbucket_config(instance, next_config);

        /* Notify anyone interested in this event... */
        if (instance->vbucket_state_listener != NULL) {
            for (ii = 0; ii < instance->nservers; ++ii) {
                instance->vbucket_state_listener(instance->servers + ii);
            }
        }
    }
}

/**
 * Try to parse the piece of data we've got available to see if we got all
 * the data for this "chunk"
 * @param instance the instance containing the data
 * @return 1 if we got all the data we need, 0 otherwise
 */
static int parse_chunk(libcouchbase_t instance)
{
    buffer_t *buffer = &instance->vbucket_stream.chunk;
    assert(instance->vbucket_stream.chunk_size != 0);

    if (instance->vbucket_stream.chunk_size == (libcouchbase_size_t)-1) {
        char *ptr = strstr(buffer->data, "\r\n");
        long val;
        if (ptr == NULL) {
            /* We need more data! */
            return 0;
        }
        ptr += 2;
        val = strtol(buffer->data, NULL, 16);
        val += 2;
        instance->vbucket_stream.chunk_size = (libcouchbase_size_t)val;
        buffer->avail -= (libcouchbase_size_t)(ptr - buffer->data);
        memmove(buffer->data, ptr, buffer->avail);
        buffer->data[buffer->avail] = '\0';
    }

    if (buffer->avail < instance->vbucket_stream.chunk_size) {
        /* need more data! */
        return 0;
    }

    return 1;
}

/**
 * Try to parse the headers in the input chunk.
 *
 * @param instance the instance containing the data
 * @return 0 success, 1 we need more data, -1 incorrect response
 */
static int parse_header(libcouchbase_t instance)
{
    int response_code;

    buffer_t *buffer = &instance->vbucket_stream.chunk;
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
    if(sscanf(buffer->data, "HTTP/1.1 %d", &response_code) != 1) {
        libcouchbase_error_handler(instance, LIBCOUCHBASE_PROTOCOL_ERROR,
                                   buffer->data);
    } else if(response_code != 200) {
        libcouchbase_error_t err;
        switch(response_code) {
        case 401:
            err = LIBCOUCHBASE_AUTH_ERROR;
            break;
        case 404:
            err = LIBCOUCHBASE_BUCKET_ENOENT;
            break;
        default:
            err = LIBCOUCHBASE_PROTOCOL_ERROR;
            break;
        }
        libcouchbase_error_handler(instance, err, buffer->data);
        return -1;
    }

    if (strstr(buffer->data, "Transfer-Encoding: chunked") == NULL &&
        strstr(buffer->data, "Transfer-encoding: chunked") == NULL) {
        libcouchbase_error_handler(instance, LIBCOUCHBASE_PROTOCOL_ERROR,
                                   buffer->data);
        return -1;
    }

    instance->vbucket_stream.header = strdup(buffer->data);
    /* realign remaining data.. */
    buffer->avail -= (libcouchbase_size_t)(ptr - buffer->data);
    memmove(buffer->data, ptr, buffer->avail);
    buffer->data[buffer->avail] = '\0';
    instance->vbucket_stream.chunk_size = (libcouchbase_size_t)-1;

    return 0;
}

/** Don't create any buffers less than 2k */
const libcouchbase_size_t min_buffer_size = 2048;

/**
 * Grow a buffer so that it got at least a minimum size of available space.
 * I'm <b>always</b> allocating one extra byte to add a '\0' so that if you
 * use one of the str* functions you won't run into random memory.
 *
 * @param buffer the buffer to grow
 * @param min_free the minimum amount of free space I need
 * @return 1 if success, 0 otherwise
 */
int grow_buffer(buffer_t *buffer, libcouchbase_size_t min_free) {
    if (min_free == 0) {
        /*
        ** no minimum size requested, just ensure that there is at least
        ** one byte there...
        */
        min_free = 1;
    }

    if (buffer->size - buffer->avail < min_free) {
        libcouchbase_size_t next = buffer->size ? buffer->size << 1 : min_buffer_size;
        char *ptr;

        while ((next - buffer->avail) < min_free) {
            next <<= 1;
        }

        ptr = realloc(buffer->data, next + 1);
        if (ptr == NULL) {
            return 0;
        }
        ptr[next] = '\0';
        buffer->data = ptr;
        buffer->size = next;
    }

    return 1;
}

static void libcouchbase_switch_to_backup_node(libcouchbase_t instance,
                                               libcouchbase_error_t error,
                                               const char *reason)
{
    libcouchbase_size_t nn;
    char *pp;
    int connected;

    if (instance->backup_nodes == NULL) {
        libcouchbase_error_handler(instance, error, reason);
        return;
    }
    connected = 0;
    nn = 0;
    while (!connected) {
        char *oldhost = instance->host;
        libcouchbase_error_t rc;

        while (instance->backup_nodes[nn] == NULL && nn < instance->nservers) {
            nn++;
        }
        if (instance->backup_nodes[nn] == NULL) {
            libcouchbase_error_handler(instance, LIBCOUCHBASE_NETWORK_ERROR,
                                       "failed to get config. All known nodes are dead.");
            return;
        }
        instance->host = strdup(instance->backup_nodes[nn]);
        instance->backup_nodes[nn] = NULL;
        if ((pp = strchr(instance->host, ':')) == NULL) {
            instance->port = "80";
        } else {
            *pp = '\0';
            instance->port = pp + 1;
        }
        free(oldhost);
        if (instance->vbucket_stream.header) {
            free(instance->vbucket_stream.header);
            instance->vbucket_stream.header = NULL;
        }
        instance->n_http_uri_sent = 0;

        /* try to connect to next node */
        rc = libcouchbase_connect(instance);
        connected = (rc == LIBCOUCHBASE_SUCCESS);
    }
}

/**
 * Callback from libevent when we read from the REST socket
 * @param sock the readable socket
 * @param which what kind of events we may do
 * @param arg pointer to the libcouchbase instance
 */
static void vbucket_stream_handler(libcouchbase_socket_t sock, short which, void *arg)
{
    libcouchbase_t instance = arg;
    libcouchbase_ssize_t nr;
    libcouchbase_size_t avail;
    buffer_t *buffer = &instance->vbucket_stream.chunk;
    assert(sock != INVALID_SOCKET);

    if ((which & LIBCOUCHBASE_WRITE_EVENT) == LIBCOUCHBASE_WRITE_EVENT) {
        libcouchbase_ssize_t nw;
        nw = instance->io->send(instance->io, instance->sock,
                                instance->http_uri + instance->n_http_uri_sent,
                                (libcouchbase_size_t)((libcouchbase_ssize_t)strlen(instance->http_uri) - instance->n_http_uri_sent),
                                0);
        if (nw == -1) {
            libcouchbase_error_handler(instance, LIBCOUCHBASE_NETWORK_ERROR,
                                       "Failed to send data to REST server");
            instance->io->delete_event(instance->io, instance->sock,
                                       instance->event);
            return;

        }

        instance->n_http_uri_sent += nw;
        if (instance->n_http_uri_sent == (libcouchbase_ssize_t)strlen(instance->http_uri)) {
            instance->io->update_event(instance->io, instance->sock,
                                       instance->event, LIBCOUCHBASE_READ_EVENT,
                                       instance, vbucket_stream_handler);
        }
    }

    if ((which & LIBCOUCHBASE_READ_EVENT) == 0) {
        return;
    }

    do {
        if (!grow_buffer(buffer, 1)) {
            libcouchbase_error_handler(instance, LIBCOUCHBASE_ENOMEM,
                                       "Failed to allocate memory");
            return ;
        }

        avail = (buffer->size - buffer->avail);
        nr = instance->io->recv(instance->io, instance->sock,
                                buffer->data + buffer->avail, avail, 0);
        if (nr < 0) {
            switch (instance->io->error) {
            case EINTR:
                break;
            case EWOULDBLOCK:
                return ;
            default:
                libcouchbase_error_handler(instance, LIBCOUCHBASE_NETWORK_ERROR,
                                           strerror(instance->io->error));
                return ;
            }
        } else if (nr == 0) {
            /* Socket closed. Pick up next server and try to connect */
            libcouchbase_switch_to_backup_node(instance,
                                               LIBCOUCHBASE_NETWORK_ERROR,
                                               NULL);
            return;
        }
        buffer->avail += (libcouchbase_size_t)nr;
        buffer->data[buffer->avail] = '\0';
    } while ((libcouchbase_size_t)nr == avail);

    if (instance->vbucket_stream.header == NULL) {
        if (parse_header(instance) == -1) {
            /* error already reported */
            libcouchbase_maybe_breakout(instance);
            return;
        }
    }

    if (instance->vbucket_stream.header != NULL) {
        int done;
        do {
            done = 1;
            if (parse_chunk(instance)) {
                /* @todo copy the data over to the input buffer there.. */
                char *term;
                if (!grow_buffer(&instance->vbucket_stream.input,
                                 instance->vbucket_stream.chunk_size)) {
                    abort();
                }
                memcpy(instance->vbucket_stream.input.data + instance->vbucket_stream.input.avail,
                       buffer->data, instance->vbucket_stream.chunk_size);
                instance->vbucket_stream.input.avail += instance->vbucket_stream.chunk_size;
                /* the chunk includes the \r\n at the end.. We shouldn't add
                ** that..
                */
                instance->vbucket_stream.input.avail -= 2;
                instance->vbucket_stream.input.data[instance->vbucket_stream.input.avail] = '\0';

                /* realign buffer */
                memmove(buffer->data, buffer->data + instance->vbucket_stream.chunk_size,
                        buffer->avail - instance->vbucket_stream.chunk_size);
                buffer->avail -= instance->vbucket_stream.chunk_size;
                term = strstr(instance->vbucket_stream.input.data, "\n\n\n\n");
                if (term != NULL) {
                    *term = '\0';
                    instance->vbucket_stream.input.avail -= 4;
                    libcouchbase_update_serverlist(instance);
                }

                instance->vbucket_stream.chunk_size = (libcouchbase_size_t)-1;
                if (buffer->avail > 0) {
                    done = 0;
                }
            }
        } while (!done);
    }

    /* Make it known that this was a success. */
    libcouchbase_error_handler(instance, LIBCOUCHBASE_SUCCESS, NULL);
}

static void libcouchbase_instance_connected(libcouchbase_t instance)
{
    instance->io->update_event(instance->io, instance->sock,
                               instance->event, LIBCOUCHBASE_RW_EVENT,
                               instance, vbucket_stream_handler);
}

static void libcouchbase_instance_connect_handler(libcouchbase_socket_t sock,
                                                  short which,
                                                  void *arg)
{
    libcouchbase_t instance = arg;
    int retry;

    do {
        if (instance->sock == INVALID_SOCKET) {
            /* Try to get a socket.. */
            while (instance->curr_ai != NULL) {
                instance->sock = instance->io->socket(instance->io,
                                                      instance->curr_ai->ai_family,
                                                      instance->curr_ai->ai_socktype,
                                                      instance->curr_ai->ai_protocol);
                if (instance->sock != INVALID_SOCKET) {
                    break;
                }
                instance->curr_ai = instance->curr_ai->ai_next;
            }
        }

        if (instance->curr_ai == NULL) {
            char errinfo[1024];
            snprintf(errinfo, sizeof(errinfo), "Failed to look up \"%s:%s\"",
                     instance->host, instance->port);
            libcouchbase_switch_to_backup_node(instance, LIBCOUCHBASE_NETWORK_ERROR, errinfo);
            return ;
        }

        retry = 0;
        if (instance->io->connect(instance->io,
                                  instance->sock,
                                  instance->curr_ai->ai_addr,
                                  (int)instance->curr_ai->ai_addrlen) == 0) {
            libcouchbase_instance_connected(instance);
            return ;
        } else {
            switch (instance->io->error) {
            case EINTR:
                retry = 1;
                break;
            case EISCONN:
                libcouchbase_instance_connected(instance);
                return ;
            case EWOULDBLOCK:
            case EINPROGRESS: /* First call to connect */
                instance->io->update_event(instance->io,
                                           instance->sock,
                                           instance->event,
                                           LIBCOUCHBASE_WRITE_EVENT,
                                           instance,
                                           libcouchbase_instance_connect_handler);
                return ;
            case EALREADY: /* Subsequent calls to connect */
                return ;

            default:
                if (errno != ECONNREFUSED) {
                    char errinfo[1024];
                    snprintf(errinfo, sizeof(errinfo), "Connection failed: %s",
                             strerror(instance->io->error));
                    libcouchbase_switch_to_backup_node(instance,
                                                       LIBCOUCHBASE_NETWORK_ERROR,
                                                       errinfo);
                    return ;
                }

                retry = 1;
                instance->curr_ai = instance->curr_ai->ai_next;
                instance->io->delete_event(instance->io,
                                           instance->sock,
                                           instance->event);
                instance->io->close(instance->io, instance->sock);
                instance->sock = INVALID_SOCKET;

            }
        }
    } while (retry);
    (void)sock;
    (void)which;
}

/**
 * @todo use async connects etc
 */
LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_connect(libcouchbase_t instance)
{
    struct addrinfo hints;
    int error;

    if (instance->sock != INVALID_SOCKET) {
        instance->io->delete_event(instance->io, instance->sock, instance->event);
        instance->io->destroy_event(instance->io, instance->event);
        instance->io->close(instance->io, instance->sock);
        instance->sock = INVALID_SOCKET;
    }
    if (instance->ai != NULL) {
        freeaddrinfo(instance->ai);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(instance->host, instance->port, &hints, &instance->ai);
    if (error != 0) {
        char errinfo[1024];
        snprintf(errinfo, sizeof(errinfo), "Failed to look up \"%s:%s\"",
                 instance->host, instance->port);
        return libcouchbase_error_handler(instance, LIBCOUCHBASE_UNKNOWN_HOST,
                                          errinfo);
    }

    instance->curr_ai = instance->ai;
    instance->event = instance->io->create_event(instance->io);
    instance->last_error = LIBCOUCHBASE_SUCCESS;
    libcouchbase_instance_connect_handler(INVALID_SOCKET, 0, instance);

    return instance->last_error;
}
