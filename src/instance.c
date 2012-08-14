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
#ifndef _WIN32
#include <dlfcn.h>
#endif

/* private function to safely free backup_nodes*/
static void free_backup_nodes(libcouchbase_t instance);
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
libcouchbase_int32_t libcouchbase_get_num_replicas(libcouchbase_t instance)
{
    if (instance->vbucket_config) {
        return instance->nreplicas;
    } else {
        return -1;
    }
}

static void setup_current_host(libcouchbase_t instance, const char *host)
{
    char *ptr;
    snprintf(instance->host, sizeof(instance->host), "%s", host);
    if ((ptr = strchr(instance->host, ':')) == NULL) {
        strcpy(instance->port, "8091");
    } else {
        *ptr = '\0';
        snprintf(instance->port, sizeof(instance->port), "%s", ptr + 1);
    }
}

static int setup_boostrap_hosts(libcouchbase_t ret, const char *host)
{
    const char *ptr = host;
    libcouchbase_size_t num = 0;
    int ii;

    while ((ptr = strchr(ptr, ';')) != NULL) {
        ++ptr;
        ++num;
    }

    /* Let's allocate the buffer space and copy the pointers
     * (the +2 and not +1 is because of the way we count the number of
     * bootstrap hosts (num == 0 means that we've got a single host etc)
     */
    if ((ret->backup_nodes = calloc(num + 2, sizeof(char *))) == NULL) {
        return -1;
    }

    ret->should_free_backup_nodes = 1;

    ptr = host;
    ii = 0;
    do {
        char nm[NI_MAXHOST + NI_MAXSERV + 2];
        const char *start = ptr;
        ptr = strchr(ptr, ';');
        if (ptr == NULL) {
            /* this is the last part */
            ret->backup_nodes[ii] = strdup(start);
            ptr = NULL;
        } else {
            /* copy everything up to ';' */
            unsigned long size = (unsigned long)ptr - (unsigned long)start;
            /* skip the entry if it's too long */
            if (size < sizeof(nm)) {
                memcpy(nm, start, ptr - start);
                *(nm + size) = '\0';
            }
            ++ptr;
            ret->backup_nodes[ii] = strdup(nm);
        }
        if (ret->backup_nodes[ii] == NULL) {
            do {
                free(ret->backup_nodes[ii--]);
            } while (ii > -1);
            return -1;
        }
        ++ii;
    } while (ptr != NULL);

    ret->backup_idx = 0;
    setup_current_host(ret, ret->backup_nodes[0]);

    return 0;
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

    if (setup_boostrap_hosts(ret, host) == -1) {
        free(ret);
        return NULL;
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

        ret->username = strdup(user);
        ret->password = strdup(passwd);
        offset += snprintf(buffer + offset, sizeof(buffer) - (libcouchbase_size_t)offset,
                           "Authorization: Basic %s\r\n", base64);
    }
    offset += snprintf(buffer + offset, sizeof(buffer) - (libcouchbase_size_t)offset, "\r\n");
    ret->http_uri = strdup(buffer);

    if (ret->http_uri == NULL) {
        libcouchbase_destroy(ret);
        return NULL;
    }
    ret->timers = hashset_create();

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
    free(instance->http_uri);

    for (ii = 0; ii < instance->timers->capacity; ++ii) {
        if (instance->timers->items[ii] > 1) {
            libcouchbase_timer_destroy(instance,
                                       (libcouchbase_timer_t)instance->timers->items[ii]);
        }
    }
    hashset_destroy(instance->timers);
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

    free_backup_nodes(instance);
    free(instance->servers);

    if (instance->io) {
#ifndef _WIN32
        void *dlhandle = NULL;
        if (instance->io->version == 1) {
            dlhandle = instance->io->dlhandle;
        }
#endif
        if (instance->io->destructor) {
            instance->io->destructor(instance->io);
        }
#ifndef _WIN32
        if (dlhandle) {
            dlclose(dlhandle);
        }
#endif
    }

    free(instance->vbucket_stream.input.data);
    free(instance->vbucket_stream.chunk.data);
    free(instance->vbucket_stream.header);
    free(instance->vb_server_map);
    free(instance->histogram);
    free(instance->username);
    free(instance->password);
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

libcouchbase_error_t libcouchbase_apply_vbucket_config(libcouchbase_t instance, VBUCKET_CONFIG_HANDLE config)
{
    libcouchbase_uint16_t ii, max;
    libcouchbase_size_t num;
    const char *passwd;
    char curnode[NI_MAXHOST + NI_MAXSERV + 2];
    sasl_callback_t sasl_callbacks[4] = {
        { SASL_CB_USER, (int( *)(void)) &sasl_get_username, instance },
        { SASL_CB_AUTHNAME, (int( *)(void)) &sasl_get_username, instance },
        { SASL_CB_PASS, (int( *)(void)) &sasl_get_password, instance },
        { SASL_CB_LIST_END, NULL, NULL }
    };

    instance->vbucket_config = config;
    num = (libcouchbase_size_t)vbucket_config_get_num_servers(config);
    /* servers array should be freed in the caller */
    instance->servers = calloc(num, sizeof(libcouchbase_server_t));
    if (instance->servers == NULL) {
        return libcouchbase_error_handler(instance, LIBCOUCHBASE_CLIENT_ENOMEM, "Failed to allocate memory");
    }
    instance->nservers = num;
    free_backup_nodes(instance);
    instance->backup_nodes = calloc(num + 1, sizeof(char *));
    if (instance->backup_nodes == NULL) {
        return libcouchbase_error_handler(instance, LIBCOUCHBASE_CLIENT_ENOMEM, "Failed to allocate memory");
    }
    snprintf(curnode, sizeof(curnode), "%s:%s", instance->host, instance->port);
    for (ii = 0; ii < num; ++ii) {
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
    instance->sasl.name = vbucket_config_get_user(instance->vbucket_config);
    memset(instance->sasl.password.buffer, 0,
           sizeof(instance->sasl.password.buffer));
    passwd = vbucket_config_get_password(instance->vbucket_config);
    if (passwd) {
        instance->sasl.password.secret.len = strlen(passwd);
        if (instance->sasl.password.secret.len < sizeof(instance->sasl.password.buffer) - offsetof(sasl_secret_t, data)) {
            memcpy(instance->sasl.password.secret.data, passwd, instance->sasl.password.secret.len);
        } else {
            return libcouchbase_error_handler(instance, LIBCOUCHBASE_EINVAL, "Password too long");
        }
    }
    memcpy(instance->sasl.callbacks, sasl_callbacks, sizeof(sasl_callbacks));

    instance->nreplicas = vbucket_config_get_num_replicas(instance->vbucket_config);
    instance->dist_type = vbucket_config_get_distribution_type(instance->vbucket_config);
    /*
     * Run through all of the vbuckets and build a map of what they need.
     * It would have been nice if I could query libvbucket for the number
     * of vbuckets a server got, but there isn't at the moment..
     */
    max = (libcouchbase_uint16_t)vbucket_config_get_num_vbuckets(instance->vbucket_config);
    instance->nvbuckets = max;
    free(instance->vb_server_map);
    instance->vb_server_map = calloc(max, sizeof(libcouchbase_vbucket_t));
    if (instance->vb_server_map == NULL) {
        return libcouchbase_error_handler(instance, LIBCOUCHBASE_CLIENT_ENOMEM, "Failed to allocate memory");
    }
    for (ii = 0; ii < max; ++ii) {
        instance->vb_server_map[ii] = (libcouchbase_uint16_t)vbucket_get_master(instance->vbucket_config, ii);
    }
    return LIBCOUCHBASE_SUCCESS;
}

static void relocate_packets(libcouchbase_server_t *src,
                             libcouchbase_t dst_instance)
{
    struct libcouchbase_command_data_st ct;
    protocol_binary_request_header cmd;
    libcouchbase_server_t *dst;
    libcouchbase_size_t nbody, npacket;
    char *body;
    libcouchbase_size_t idx;
    libcouchbase_vbucket_t vb;

    while (ringbuffer_read(&src->cmd_log, cmd.bytes, sizeof(cmd.bytes))) {
        nbody = ntohl(cmd.request.bodylen); /* extlen + nkey + nval */
        npacket = sizeof(cmd.bytes) + nbody;
        body = malloc(nbody);
        if (body == NULL) {
            libcouchbase_error_handler(dst_instance, LIBCOUCHBASE_CLIENT_ENOMEM,
                                       "Failed to allocate memory");
            return;
        }
        assert(ringbuffer_read(&src->cmd_log, body, nbody) == nbody);
        vb = ntohs(cmd.request.vbucket);
        idx = (libcouchbase_size_t)vbucket_get_master(dst_instance->vbucket_config, vb);
        dst = dst_instance->servers + idx;
        if (src->connected) {
            assert(ringbuffer_read(&src->output_cookies, &ct, sizeof(ct)) == sizeof(ct));
        } else {
            assert(ringbuffer_read(&src->pending_cookies, &ct, sizeof(ct)) == sizeof(ct));
        }

        assert(ringbuffer_ensure_capacity(&dst->cmd_log, npacket));
        assert(ringbuffer_write(&dst->cmd_log, cmd.bytes, sizeof(cmd.bytes)) == sizeof(cmd.bytes));
        assert(ringbuffer_write(&dst->cmd_log, body, nbody) == nbody);
        assert(ringbuffer_ensure_capacity(&dst->output_cookies, sizeof(ct)));
        assert(ringbuffer_write(&dst->output_cookies, &ct, sizeof(ct)) == sizeof(ct));

        assert(!dst->connected);
        assert(ringbuffer_ensure_capacity(&dst->pending, npacket));
        assert(ringbuffer_write(&dst->pending, cmd.bytes, sizeof(cmd.bytes)) == sizeof(cmd.bytes));
        assert(ringbuffer_write(&dst->pending, body, nbody) == nbody);
        assert(ringbuffer_ensure_capacity(&dst->pending_cookies, sizeof(ct)));
        assert(ringbuffer_write(&dst->pending_cookies, &ct, sizeof(ct)) == sizeof(ct));

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
    VBUCKET_CONFIG_DIFF *diff = NULL;
    libcouchbase_size_t nservers;
    libcouchbase_server_t *servers, *ss;

    curr_config = instance->vbucket_config;
    next_config = vbucket_config_create();
    if (next_config == NULL) {
        libcouchbase_error_handler(instance, LIBCOUCHBASE_CLIENT_ENOMEM,
                                   "Failed to allocate memory for config");
        return;
    }
    if (vbucket_config_parse(next_config, LIBVBUCKET_SOURCE_MEMORY,
                             instance->vbucket_stream.input.data) != 0) {
        libcouchbase_error_handler(instance, LIBCOUCHBASE_PROTOCOL_ERROR,
                                   vbucket_get_error_message(next_config));
        vbucket_config_destroy(next_config);
        return;
    }
    instance->vbucket_stream.input.avail = 0;

    if (curr_config) {
        diff = vbucket_compare(curr_config, next_config);
        if (diff && (diff->sequence_changed || diff->n_vb_changes > 0)) {
            VBUCKET_DISTRIBUTION_TYPE dist_t = vbucket_config_get_distribution_type(next_config);
            nservers = instance->nservers;
            servers = instance->servers;
            if (libcouchbase_apply_vbucket_config(instance, next_config) != LIBCOUCHBASE_SUCCESS) {
                vbucket_free_diff(diff);
                vbucket_config_destroy(next_config);
                return;
            }
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
            free(servers);

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
            instance->callbacks.configuration(instance,
                                              LIBCOUCHBASE_CONFIGURATION_CHANGED);

        } else {
            instance->callbacks.configuration(instance,
                                              LIBCOUCHBASE_CONFIGURATION_UNCHANGED);
            vbucket_config_destroy(next_config);
        }
        if (diff) {
            vbucket_free_diff(diff);
        }
    } else {
        assert(instance->servers == NULL);
        assert(instance->nservers == 0);
        if (libcouchbase_apply_vbucket_config(instance, next_config) != LIBCOUCHBASE_SUCCESS) {
            vbucket_config_destroy(next_config);
            return;
        }

        /* Notify anyone interested in this event... */
        if (instance->vbucket_state_listener != NULL) {
            for (ii = 0; ii < instance->nservers; ++ii) {
                instance->vbucket_state_listener(instance->servers + ii);
            }
        }
        instance->callbacks.configuration(instance,
                                          LIBCOUCHBASE_CONFIGURATION_NEW);
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

    if (instance->vbucket_stream.chunk_size == (libcouchbase_size_t) - 1) {
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
    if (sscanf(buffer->data, "HTTP/1.1 %d", &response_code) != 1) {
        libcouchbase_error_handler(instance, LIBCOUCHBASE_PROTOCOL_ERROR,
                                   buffer->data);
    } else if (response_code != 200) {
        libcouchbase_error_t err;
        switch (response_code) {
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
    instance->vbucket_stream.chunk_size = (libcouchbase_size_t) - 1;

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
int grow_buffer(buffer_t *buffer, libcouchbase_size_t min_free)
{
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

/* This function does any resetting of various book-keeping related with the
 * current REST API socket.
 */
static void libcouchbase_instance_reset_stream_state(libcouchbase_t instance)
{
    free(instance->vbucket_stream.input.data);
    free(instance->vbucket_stream.chunk.data);
    free(instance->vbucket_stream.header);
    memset(&instance->vbucket_stream, 0, sizeof(instance->vbucket_stream));
    instance->n_http_uri_sent = 0;
}

static int libcouchbase_switch_to_backup_node(libcouchbase_t instance,
                                              libcouchbase_error_t error,
                                              const char *reason)
{
    if (instance->backup_nodes == NULL) {
        /* No known backup nodes */
        libcouchbase_error_handler(instance, error, reason);
        return -1;
    }

    if (instance->backup_nodes[instance->backup_idx] == NULL) {
        libcouchbase_error_handler(instance, error, reason);
        return -1;
    }

    do {
        /* Keep on trying the nodes until all of them failed ;-) */
        if (libcouchbase_connect(instance) == LIBCOUCHBASE_SUCCESS) {
            return 0;
        }
    } while (instance->backup_nodes[instance->backup_idx] == NULL);
    /* All known nodes are dead */
    libcouchbase_error_handler(instance, error, reason);
    return -1;
}

static void libcouchbase_instance_connerr(libcouchbase_t instance,
                                          libcouchbase_error_t err,
                                          const char *errinfo)
{
    if (instance->sock != INVALID_SOCKET) {
        instance->io->delete_event(instance->io, instance->sock, instance->event);
        instance->io->close(instance->io, instance->sock);
        instance->sock = INVALID_SOCKET;
    }

    /* We try and see if the connection attempt can be relegated to another
     * REST API entry point. If we can, the following should return something
     * other than -1...
     */

    if (libcouchbase_switch_to_backup_node(instance, err, errinfo) != -1) {
        return;
    }

    /* ..otherwise, we have a currently irrecoverable error. bail out all the
     * pending commands, if applicable and/or deliver a final failure for
     * initial connect attempts.
     */

    if (!instance->vbucket_config) {
        /* Initial connection, no pending commands, and connect timer */
        instance->io->delete_timer(instance->io, instance->timeout.event);
    } else {
        libcouchbase_size_t ii;
        for (ii = 0; ii < instance->nservers; ++ii) {
            libcouchbase_failout_server(instance->servers + ii, err);
        }
    }

    /* check to see if we can breakout of the event loop. don't hang on REST
     * API connection attempts.
     */
    libcouchbase_maybe_breakout(instance);
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
                                strlen(instance->http_uri) - instance->n_http_uri_sent,
                                0);
        if (nw == -1) {
            libcouchbase_error_handler(instance, LIBCOUCHBASE_NETWORK_ERROR,
                                       "Failed to send data to REST server");
            instance->io->delete_event(instance->io, instance->sock,
                                       instance->event);
            return;

        }

        instance->n_http_uri_sent += nw;
        if (instance->n_http_uri_sent == strlen(instance->http_uri)) {
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
            libcouchbase_error_handler(instance, LIBCOUCHBASE_CLIENT_ENOMEM,
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
            (void)libcouchbase_instance_connerr(instance,
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
                buffer->data[buffer->avail] = '\0';
                term = strstr(instance->vbucket_stream.input.data, "\n\n\n\n");
                if (term != NULL) {
                    *term = '\0';
                    instance->vbucket_stream.input.avail -= 4;
                    libcouchbase_update_serverlist(instance);
                }

                instance->vbucket_stream.chunk_size = (libcouchbase_size_t) - 1;
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
    instance->backup_idx = 0;
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
    int first_try = (sock == INVALID_SOCKET);
    libcouchbase_connect_status_t connstatus = LIBCOUCHBASE_CONNECT_OK;
    int save_errno;
    do {
        if (instance->sock == INVALID_SOCKET) {
            /* Try to get a socket.. */
            instance->sock = libcouchbase_gai2sock(instance,
                                                   &instance->curr_ai,
                                                   &save_errno);

            /* Reset the stream state, we run this only during a new socket. */
            libcouchbase_instance_reset_stream_state(instance);
        }

        if (instance->curr_ai == NULL) {
            char errinfo[1024];
            libcouchbase_error_t our_errno;
            libcouchbase_sockconn_errinfo(save_errno,
                                          instance->host,
                                          instance->port,
                                          instance->ai,
                                          errinfo,
                                          sizeof(errinfo),
                                          &our_errno);

            if (first_try && instance->sock != INVALID_SOCKET) {
                /* Ensure our connerr function doesn't try to delete a
                 * nonexistent event */
                instance->io->close(instance->io, instance->sock);
                instance->sock = INVALID_SOCKET;
            }

            libcouchbase_instance_connerr(instance, our_errno, errinfo);
            return ;
        }

        retry = 0;
        if (instance->io->connect(instance->io,
                                  instance->sock,
                                  instance->curr_ai->ai_addr,
                                  (unsigned int)instance->curr_ai->ai_addrlen) == 0) {
            libcouchbase_instance_connected(instance);
            return ;
        } else {
            save_errno = instance->io->error;
            connstatus = libcouchbase_connect_status(save_errno);

            switch (connstatus) {
            case LIBCOUCHBASE_CONNECT_EINTR:
                retry = 1;
                break;
            case LIBCOUCHBASE_CONNECT_EISCONN:
                libcouchbase_instance_connected(instance);
                return ;
            case LIBCOUCHBASE_CONNECT_EINPROGRESS:
                instance->io->update_event(instance->io,
                                           instance->sock,
                                           instance->event,
                                           LIBCOUCHBASE_WRITE_EVENT,
                                           instance,
                                           libcouchbase_instance_connect_handler);
                return ;
            case LIBCOUCHBASE_CONNECT_EALREADY: /* Subsequent calls to connect */
                return ;

            default: {
                /* Save errno because of possible subsequent errors */
                if (instance->sock != INVALID_SOCKET) {
                    if (!first_try) {
                        /* Event updated */
                        instance->io->delete_event(instance->io,
                                                   instance->sock,
                                                   instance->event);
                    }
                    instance->io->close(instance->io, instance->sock);
                    instance->sock = INVALID_SOCKET;
                }
                if (connstatus == LIBCOUCHBASE_CONNECT_EFAIL &&
                        instance->curr_ai->ai_next) {
                    /* Here we handle 'medium-type' errors which are not a hard
                     * failure, but mean that we need to retry the connect() with
                     * different parameters.
                     */
                    retry = 1;
                    instance->curr_ai = instance->curr_ai->ai_next;
                    break;
                } else {
                    char errinfo[1024];
                    snprintf(errinfo, sizeof(errinfo), "Connection failed: %s",
                             strerror(instance->io->error));
                    libcouchbase_instance_connerr(instance,
                                                  LIBCOUCHBASE_CONNECT_ERROR,
                                                  errinfo);
                    return ;
                }
            }

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

    do {
        setup_current_host(instance,
                           instance->backup_nodes[instance->backup_idx++]);
        error = getaddrinfo(instance->host, instance->port,
                            &hints, &instance->ai);
        if (error != 0) {
            /* Ok, we failed to look up that server.. look up the next
             * in the list
             */
            if (instance->backup_nodes[instance->backup_idx] == NULL) {
                char errinfo[1024];
                snprintf(errinfo, sizeof(errinfo),
                         "Failed to look up \"%s:%s\"",
                         instance->host, instance->port);
                return libcouchbase_error_handler(instance,
                                                  LIBCOUCHBASE_UNKNOWN_HOST,
                                                  errinfo);
            }
        }
    } while (error != 0);

    instance->curr_ai = instance->ai;
    instance->event = instance->io->create_event(instance->io);
    instance->last_error = LIBCOUCHBASE_SUCCESS;
    libcouchbase_instance_connect_handler(INVALID_SOCKET, 0, instance);

    return instance->last_error;
}

static void free_backup_nodes(libcouchbase_t instance)
{
    if (instance->should_free_backup_nodes) {
        char **ptr = instance->backup_nodes;
        while (*ptr != NULL) {
            free(*ptr);
            ptr++;
        }
        instance->should_free_backup_nodes = 0;
    }
    free(instance->backup_nodes);
    instance->backup_nodes = NULL;
}
