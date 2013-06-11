/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2013 Couchbase, Inc.
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
static void free_backup_nodes(lcb_t instance);

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
const char *lcb_get_version(lcb_uint32_t *version)
{
    if (version != NULL) {
        *version = (lcb_uint32_t)LCB_VERSION;
    }

    return LCB_VERSION_STRING;
}

LIBCOUCHBASE_API
const char *lcb_get_host(lcb_t instance)
{
    return instance->connection.host;
}

LIBCOUCHBASE_API
const char *lcb_get_port(lcb_t instance)
{
    return instance->connection.port;
}


LIBCOUCHBASE_API
lcb_int32_t lcb_get_num_replicas(lcb_t instance)
{
    if (instance->vbucket_config) {
        return instance->nreplicas;
    } else {
        return -1;
    }
}

LIBCOUCHBASE_API
lcb_int32_t lcb_get_num_nodes(lcb_t instance)
{
    if (instance->vbucket_config) {
        return instance->nservers;
    } else {
        return -1;
    }
}

/**
 * Return a NULL-terminated list of servers (host:port) for the entire cluster.
 */
LIBCOUCHBASE_API
const char *const *lcb_get_server_list(lcb_t instance)
{
    /* cast it so we get the full const'ness */
    return (const char * const *)instance->backup_nodes;
}


static lcb_error_t validate_hostname(const char *host, char **realhost)
{
    /* The http parser aborts if it finds a space.. we don't want our
     * program to core, so run a prescan first
     */
    int len = strlen(host);
    int ii;
    char *schema = strstr(host, "://");
    char *path;
    int port = 8091;
    int numcolons = 0;

    for (ii = 0; ii < len; ++ii) {
        if (isspace(host[ii])) {
            return LCB_INVALID_HOST_FORMAT;
        }
    }

    if (schema != NULL) {
        size_t size;
        size = schema - host;
        if (size != 4 && strncasecmp(host, "http", 4) != 0) {
            return LCB_INVALID_HOST_FORMAT;
        }
        host += 7;
        len -= 7;
        port = 80;
    }

    path = strchr(host, '/');
    if (path != NULL) {
        size_t size;
        if (strcmp(path, "/pools") != 0 && strcmp(path, "/pools/") != 0) {
            return LCB_INVALID_HOST_FORMAT;
        }
        size = path - host;
        len = (int)size;
    }

    if (strchr(host, ':') != NULL) {
        port = 0;
    }

    for (ii = 0; ii < len; ++ii) {
        if (isalnum(host[ii]) == 0) {
            switch (host[ii]) {
            case ':' :
                ++numcolons;
                break;
            case '.' :
            case '-' :
            case '_' :
                break;
            default:
                /* Invalid character in the hostname */
                return LCB_INVALID_HOST_FORMAT;
            }
        }
    }

    if (numcolons > 1) {
        return LCB_INVALID_HOST_FORMAT;
    }

    if (port == 0) {
        if ((*realhost = strdup(host)) == NULL) {
            return LCB_CLIENT_ENOMEM;
        }

        (*realhost)[len] = '\0';
    } else {
        if ((*realhost = malloc(len + 10)) == NULL) {
            return LCB_CLIENT_ENOMEM;
        }
        memcpy(*realhost, host, len);
        sprintf(*realhost + len, ":%d", port);
    }

    return LCB_SUCCESS;
}

static lcb_error_t setup_boostrap_hosts(lcb_t ret, const char *host)
{
    const char *ptr = host;
    lcb_size_t num = 0;
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
        return LCB_CLIENT_ENOMEM;
    }

    ret->should_free_backup_nodes = 1;

    ptr = host;
    ii = 0;
    do {
        char nm[NI_MAXHOST + NI_MAXSERV + 2];
        const char *start = ptr;
        lcb_error_t error;

        ptr = strchr(ptr, ';');
        ret->backup_nodes[ii] = NULL;
        if (ptr == NULL) {
            /* this is the last part */
            error = validate_hostname(start, &ret->backup_nodes[ii]);
            ptr = NULL;
        } else {
            /* copy everything up to ';' */
            unsigned long size = (unsigned long)ptr - (unsigned long)start;
            /* skip the entry if it's too long */
            if (size < sizeof(nm)) {
                memcpy(nm, start, (lcb_size_t)(ptr - start));
                *(nm + size) = '\0';
            }
            ++ptr;
            error = validate_hostname(nm, &ret->backup_nodes[ii]);
        }
        if (error != LCB_SUCCESS) {
            while (ii > 0) {
                free(ret->backup_nodes[ii--]);
            }
            return error;
        }
        ++ii;
    } while (ptr != NULL);

    ret->backup_idx = 0;
    return LCB_SUCCESS;
}

static const char *get_nonempty_string(const char *s)
{
    if (s != NULL && strlen(s) == 0) {
        return NULL;
    }
    return s;
}

LIBCOUCHBASE_API
lcb_error_t lcb_create(lcb_t *instance,
                       const struct lcb_create_st *options)
{
    const char *host = NULL;
    const char *user = NULL;
    const char *passwd = NULL;
    const char *bucket = NULL;
    struct lcb_io_opt_st *io = NULL;
    char buffer[1024];
    lcb_ssize_t offset = 0;
    lcb_type_t type = LCB_TYPE_BUCKET;
    lcb_t obj;
    lcb_error_t err;

    if (options != NULL) {
        switch (options->version) {
        case 0:
            host = get_nonempty_string(options->v.v0.host);
            user = get_nonempty_string(options->v.v0.user);
            passwd = get_nonempty_string(options->v.v0.passwd);
            bucket = get_nonempty_string(options->v.v0.bucket);
            io = options->v.v0.io;
            break;
        case 1:
            type = options->v.v1.type;
            host = get_nonempty_string(options->v.v1.host);
            user = get_nonempty_string(options->v.v1.user);
            passwd = get_nonempty_string(options->v.v1.passwd);
            io = options->v.v1.io;
            switch (type) {
            case LCB_TYPE_BUCKET:
                bucket = get_nonempty_string(options->v.v1.bucket);
                break;
            case LCB_TYPE_CLUSTER:
                if (user == NULL || passwd == NULL) {
                    return LCB_EINVAL;
                }
                break;
            }
            break;
        default:
            return LCB_EINVAL;
        }
    }

    if (host == NULL) {
        host = "localhost";
    }

    if (bucket == NULL) {
        bucket = "default";
    }

    if (sasl_client_init(NULL) != SASL_OK) {
        return LCB_EINTERNAL;
    }

    if ((obj = calloc(1, sizeof(*obj))) == NULL) {
        return LCB_CLIENT_ENOMEM;
    }
    *instance = obj;
    obj->type = type;
    obj->compat.type = (lcb_compat_t)0xdead;

    if (io == NULL) {
        lcb_io_opt_t ops;
        if ((err = lcb_create_io_ops(&ops, NULL)) != LCB_SUCCESS) {
            /* You can't initialize the library without a io-handler! */
            return err;
        }
        io = ops;
        io->v.v0.need_cleanup = 1;
    }
    obj->io = io;
    lcb_initialize_packet_handlers(obj);
    lcb_behavior_set_syncmode(obj, LCB_ASYNCHRONOUS);
    lcb_behavior_set_ipv6(obj, LCB_IPV6_DISABLED);
    lcb_set_timeout(obj, LCB_DEFAULT_TIMEOUT);
    lcb_behavior_set_config_errors_threshold(obj, LCB_DEFAULT_CONFIG_ERRORS_THRESHOLD);

    err = lcb_connection_init(&obj->connection, obj);
    if (err != LCB_SUCCESS) {
        lcb_destroy(obj);
        return err;
    }

    obj->connection.data = obj;

    err = setup_boostrap_hosts(obj, host);
    if (err != LCB_SUCCESS) {
        lcb_destroy(obj);
        return err;
    }
    obj->timers = hashset_create();
    obj->http_requests = hashset_create();
    /* No error has occurred yet. */
    obj->last_error = LCB_SUCCESS;

    switch (type) {
    case LCB_TYPE_BUCKET:
        offset = snprintf(buffer, sizeof(buffer),
                          "GET /pools/default/bucketsStreaming/%s HTTP/1.1\r\n",
                          bucket);
        break;
    case LCB_TYPE_CLUSTER:
        offset = snprintf(buffer, sizeof(buffer), "GET /pools/ HTTP/1.1\r\n");
        break;
    default:
        return LCB_EINVAL;
    }

    if (user && passwd) {
        char cred[256];
        char base64[256];
        snprintf(cred, sizeof(cred), "%s:%s", user, passwd);
        if (lcb_base64_encode(cred, base64, sizeof(base64)) == -1) {
            lcb_destroy(obj);
            return LCB_EINTERNAL;
        }
        obj->username = strdup(user);
        obj->password = strdup(passwd);
        offset += snprintf(buffer + offset, sizeof(buffer) - (lcb_size_t)offset,
                           "Authorization: Basic %s\r\n", base64);
    }

    offset += snprintf(buffer + offset, sizeof(buffer) - (lcb_size_t)offset,
                       "%s", LCB_LAST_HTTP_HEADER);

    /* Add space for: Host: \r\n\r\n" */
    obj->http_uri = malloc(strlen(buffer) + strlen(host) + 80);
    if (obj->http_uri == NULL) {
        lcb_destroy(obj);
        return LCB_CLIENT_ENOMEM;
    }
    strcpy(obj->http_uri, buffer);

    return LCB_SUCCESS;
}


LIBCOUCHBASE_API
void lcb_destroy(lcb_t instance)
{
    lcb_size_t ii;
    free(instance->http_uri);

    if (instance->timers != NULL) {
        for (ii = 0; ii < instance->timers->capacity; ++ii) {
            if (instance->timers->items[ii] > 1) {
                lcb_timer_destroy(instance,
                                  (lcb_timer_t)instance->timers->items[ii]);
            }
        }
        hashset_destroy(instance->timers);
    }
    lcb_connection_cleanup(&instance->connection);

    if (instance->vbucket_config != NULL) {
        vbucket_config_destroy(instance->vbucket_config);
    }

    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_destroy(instance->servers + ii);
    }

    if (instance->http_requests) {
        for (ii = 0; ii < instance->http_requests->capacity; ++ii) {
            if (instance->http_requests->items[ii] > 1) {
                lcb_http_request_t htreq =
                    (lcb_http_request_t)instance->http_requests->items[ii];

                /* we should figure out a better error code for this.. */
                lcb_http_request_finish(instance, NULL, htreq, LCB_ERROR);
            }
        }
    }

    hashset_destroy(instance->http_requests);
    free_backup_nodes(instance);
    free(instance->servers);
    if (instance->io && instance->io->v.v0.need_cleanup) {
        lcb_destroy_io_ops(instance->io);
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
 * @param context ponter to the lcb_t instance running the sasl bits
 * @param id the piece of information libsasl wants
 * @param result where to store the result (OUT)
 * @param len The length of the data returned (OUT)
 * @return SASL_OK if succes
 */
static int sasl_get_username(void *context, int id, const char **result,
                             unsigned int *len)
{
    lcb_t instance = context;
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
 * @param context ponter to the lcb_t instance running the sasl bits
 * @param id the piece of information libsasl wants
 * @param psecret where to store the result (OUT)
 * @return SASL_OK if succes
 */
static int sasl_get_password(sasl_conn_t *conn, void *context, int id,
                             sasl_secret_t **psecret)
{
    lcb_t instance = context;
    if (!conn || ! psecret || id != SASL_CB_PASS) {
        return SASL_BADPARAM;
    }

    *psecret = &instance->sasl.password.secret;
    return SASL_OK;
}

lcb_error_t lcb_apply_vbucket_config(lcb_t instance, VBUCKET_CONFIG_HANDLE config)
{
    lcb_uint16_t ii, max, buii;
    lcb_size_t num;
    const char *passwd;
    sasl_callback_t sasl_callbacks[4];

    sasl_callbacks[0].id = SASL_CB_USER;
    sasl_callbacks[0].proc = (int( *)(void)) &sasl_get_username;
    sasl_callbacks[0].context = instance;
    sasl_callbacks[1].id = SASL_CB_AUTHNAME;
    sasl_callbacks[1].proc = (int( *)(void)) &sasl_get_username;
    sasl_callbacks[1].context = instance;
    sasl_callbacks[2].id = SASL_CB_PASS;
    sasl_callbacks[2].proc = (int( *)(void)) &sasl_get_password;
    sasl_callbacks[2].context = instance;
    sasl_callbacks[3].id = SASL_CB_LIST_END;
    sasl_callbacks[3].proc = NULL;
    sasl_callbacks[3].context = NULL;

    instance->vbucket_config = config;
    instance->weird_things = 0;
    num = (lcb_size_t)vbucket_config_get_num_servers(config);
    /* servers array should be freed in the caller */
    instance->servers = calloc(num, sizeof(lcb_server_t));
    if (instance->servers == NULL) {
        return lcb_error_handler(instance, LCB_CLIENT_ENOMEM, "Failed to allocate memory");
    }
    instance->nservers = num;
    free_backup_nodes(instance);
    instance->backup_nodes = calloc(num + 1, sizeof(char *));
    if (instance->backup_nodes == NULL) {
        return lcb_error_handler(instance, LCB_CLIENT_ENOMEM, "Failed to allocate memory");
    }
    for (buii = 0, ii = 0; ii < num; ++ii) {
        instance->servers[ii].instance = instance;
        lcb_server_initialize(instance->servers + ii, (int)ii);
        instance->backup_nodes[buii] = instance->servers[ii].rest_api_server;
        /* swap with random position < ii */
        if (buii > 0) {
            lcb_size_t nn = (lcb_size_t)(gethrtime() >> 10) % buii;
            char *pp = instance->backup_nodes[buii];
            instance->backup_nodes[ii] = instance->backup_nodes[nn];
            instance->backup_nodes[nn] = pp;
        }
        buii++;
    }

    instance->sasl.name = vbucket_config_get_user(instance->vbucket_config);
    memset(instance->sasl.password.buffer, 0,
           sizeof(instance->sasl.password.buffer));
    passwd = vbucket_config_get_password(instance->vbucket_config);
    if (passwd) {
        instance->sasl.password.secret.len = (unsigned long)strlen(passwd);
        if (instance->sasl.password.secret.len < sizeof(instance->sasl.password.buffer) - offsetof(sasl_secret_t, data)) {
            memcpy(instance->sasl.password.secret.data, passwd, instance->sasl.password.secret.len);
        } else {
            return lcb_error_handler(instance, LCB_EINVAL, "Password too long");
        }
    }
    memcpy(instance->sasl.callbacks, sasl_callbacks, sizeof(sasl_callbacks));

    instance->nreplicas = (lcb_uint16_t)vbucket_config_get_num_replicas(instance->vbucket_config);
    instance->dist_type = vbucket_config_get_distribution_type(instance->vbucket_config);
    /*
     * Run through all of the vbuckets and build a map of what they need.
     * It would have been nice if I could query libvbucket for the number
     * of vbuckets a server got, but there isn't at the moment..
     */
    max = (lcb_uint16_t)vbucket_config_get_num_vbuckets(instance->vbucket_config);
    instance->nvbuckets = max;
    free(instance->vb_server_map);
    instance->vb_server_map = calloc(max, sizeof(lcb_vbucket_t));
    if (instance->vb_server_map == NULL) {
        return lcb_error_handler(instance, LCB_CLIENT_ENOMEM, "Failed to allocate memory");
    }
    for (ii = 0; ii < max; ++ii) {
        instance->vb_server_map[ii] = (lcb_uint16_t)vbucket_get_master(instance->vbucket_config, ii);
    }
    return LCB_SUCCESS;
}

static void relocate_packets(lcb_server_t *src,
                             lcb_t dst_instance)
{
    struct lcb_command_data_st ct;
    protocol_binary_request_header cmd;
    lcb_server_t *dst;
    lcb_size_t nbody, npacket;
    char *body;
    int idx;
    lcb_vbucket_t vb;

    while (ringbuffer_read(&src->cmd_log, cmd.bytes, sizeof(cmd.bytes))) {
        nbody = ntohl(cmd.request.bodylen); /* extlen + nkey + nval */
        npacket = sizeof(cmd.bytes) + nbody;
        body = malloc(nbody);
        if (body == NULL) {
            lcb_error_handler(dst_instance, LCB_CLIENT_ENOMEM,
                              "Failed to allocate memory");
            return;
        }
        lcb_assert(ringbuffer_read(&src->cmd_log, body, nbody) == nbody);
        vb = ntohs(cmd.request.vbucket);
        idx = vbucket_get_master(dst_instance->vbucket_config, vb);
        if (idx < 0) {
            /* looks like master isn't ready to accept the data, try another
             * one, maybe from fast forward map. this function will never
             * give -1 */
            idx = vbucket_found_incorrect_master(dst_instance->vbucket_config, vb, idx);
        }
        dst = dst_instance->servers + (lcb_size_t)idx;
        lcb_assert(ringbuffer_read(&src->output_cookies, &ct, sizeof(ct)) == sizeof(ct) ||
                   ringbuffer_read(&src->pending_cookies, &ct, sizeof(ct)) == sizeof(ct));

        lcb_assert(ringbuffer_ensure_capacity(&dst->cmd_log, npacket));
        lcb_assert(ringbuffer_write(&dst->cmd_log, cmd.bytes, sizeof(cmd.bytes)) == sizeof(cmd.bytes));
        lcb_assert(ringbuffer_write(&dst->cmd_log, body, nbody) == nbody);
        lcb_assert(ringbuffer_ensure_capacity(&dst->output_cookies, sizeof(ct)));
        lcb_assert(ringbuffer_write(&dst->output_cookies, &ct, sizeof(ct)) == sizeof(ct));

        lcb_assert(ringbuffer_ensure_capacity(&dst->pending, npacket));
        lcb_assert(ringbuffer_write(&dst->pending, cmd.bytes, sizeof(cmd.bytes)) == sizeof(cmd.bytes));
        lcb_assert(ringbuffer_write(&dst->pending, body, nbody) == nbody);
        lcb_assert(ringbuffer_ensure_capacity(&dst->pending_cookies, sizeof(ct)));
        lcb_assert(ringbuffer_write(&dst->pending_cookies, &ct, sizeof(ct)) == sizeof(ct));

        free(body);
        lcb_server_send_packets(dst);
    }
}

/**
 * Read the configuration data from the socket. Also write the config to the
 * cachefile, if such exists, and the config is valid.
 */
static int grab_http_config(lcb_t instance, VBUCKET_CONFIG_HANDLE *config)
{
    *config = vbucket_config_create();
    if (*config == NULL) {
        lcb_error_handler(instance, LCB_CLIENT_ENOMEM,
                          "Failed to allocate memory for config");
        return -1;
    }

    if (vbucket_config_parse(*config, LIBVBUCKET_SOURCE_MEMORY,
                             instance->vbucket_stream.input.data) != 0) {
        lcb_error_handler(instance, LCB_PROTOCOL_ERROR,
                          vbucket_get_error_message(*config));
        vbucket_config_destroy(*config);
        return -1;
    }
    instance->vbucket_stream.input.avail = 0;

    if (instance->compat.type == LCB_CACHED_CONFIG) {
        FILE *fp = fopen(instance->compat.value.cached.cachefile, "w");
        if (fp) {
            fprintf(fp, "%s{{{fb85b563d0a8f65fa8d3d58f1b3a0708}}}",
                    instance->vbucket_stream.input.data);
            fclose(fp);
        }
        instance->compat.value.cached.updating = 0;
        instance->compat.value.cached.mtime = time(NULL) - 1;
    }
    return 0;
}

/**
 * Update the list of servers and connect to the new ones
 *
 * @param instance the instance to update the serverlist for.
 * @param next_config a ready-to-use VBUCKET_CONFIG_HANDLE containing the
 * updated config. May be null, in which case the config from the read buffer
 * is used.
 *
 * @todo use non-blocking connects and timeouts
 */
void lcb_update_vbconfig(lcb_t instance,
                         VBUCKET_CONFIG_HANDLE next_config)
{
    lcb_size_t ii;
    VBUCKET_CONFIG_HANDLE curr_config;
    VBUCKET_CONFIG_DIFF *diff = NULL;
    lcb_size_t nservers;
    lcb_server_t *servers, *ss;
    int is_cached = next_config != NULL;

    curr_config = instance->vbucket_config;

    /**
     * If we're not passed a new config object, it means we parse it from the
     * read buffer. Otherwise assume it's from some "compat" mode
     */
    if (!next_config) {
        if (grab_http_config(instance, &next_config) == -1) {
            return;
        }
    }

    if (curr_config) {
        diff = vbucket_compare(curr_config, next_config);
        if (diff && (diff->sequence_changed || diff->n_vb_changes > 0)) {
            VBUCKET_DISTRIBUTION_TYPE dist_t = vbucket_config_get_distribution_type(next_config);
            nservers = instance->nservers;
            servers = instance->servers;
            if (lcb_apply_vbucket_config(instance, next_config) != LCB_SUCCESS) {
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
                    lcb_failout_server(ss, LCB_CLIENT_ETMPFAIL);
                }
                lcb_server_destroy(ss);
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
                    lcb_server_send_packets(ss);
                }
            }
            instance->callbacks.configuration(instance,
                                              LCB_CONFIGURATION_CHANGED);

        } else {
            instance->callbacks.configuration(instance,
                                              LCB_CONFIGURATION_UNCHANGED);
            vbucket_config_destroy(next_config);
        }
        if (diff) {
            vbucket_free_diff(diff);
        }
    } else {
        lcb_assert(instance->servers == NULL);
        lcb_assert(instance->nservers == 0);
        if (lcb_apply_vbucket_config(instance, next_config) != LCB_SUCCESS) {
            vbucket_config_destroy(next_config);
            return;
        }

        /* Notify anyone interested in this event... */
        if (instance->vbucket_state_listener != NULL) {
            for (ii = 0; ii < instance->nservers; ++ii) {
                instance->vbucket_state_listener(instance->servers + ii);
            }
        }
        instance->callbacks.configuration(instance, LCB_CONFIGURATION_NEW);
        instance->connection_ready = 1;
    }

    /**
     * Remove the timer. We aren't waiting for updated configurations anyway
     */
    lcb_connection_delete_timer(&instance->connection);

    /**
     * If we're using a cached config, we should not need a socket connection.
     * Disconnect the socket, if it's there
     */
    if (is_cached) {
        lcb_connection_close(&instance->connection);
    }

    lcb_maybe_breakout(instance);

}

/* This function does any resetting of various book-keeping related with the
 * current REST API socket.
 */

int lcb_switch_to_backup_node(lcb_t instance,
                              lcb_error_t error,
                              const char *reason)
{
    if (instance->backup_nodes == NULL) {
        /* No known backup nodes */
        lcb_error_handler(instance, error, reason);
        return -1;
    }

    if (instance->backup_nodes[instance->backup_idx] == NULL) {
        lcb_error_handler(instance, error, reason);
        return -1;
    }

    do {
        /* Keep on trying the nodes until all of them failed ;-) */
        if (lcb_instance_start_connection(instance) == LCB_SUCCESS) {
            return 0;
        }
    } while (instance->backup_nodes[instance->backup_idx] != NULL);
    /* All known nodes are dead */
    lcb_error_handler(instance, error, reason);
    return -1;
}

/**
 * Callback from libevent when we read from the REST socket
 * @param sock the readable socket
 * @param which what kind of events we may do
 * @param arg pointer to the libcouchbase instance
 */
void lcb_vbucket_stream_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_t instance = arg;
    lcb_connection_t conn = &instance->connection;
    assert(sock != INVALID_SOCKET);
    lcb_sockrw_status_t status;

    if ((which & LCB_WRITE_EVENT) == LCB_WRITE_EVENT) {

        status = lcb_sockrw_write(conn, conn->output);
        if (status != LCB_SOCKRW_WROTE && status != LCB_SOCKRW_WOULDBLOCK) {
            lcb_instance_connerr(instance,
                                 LCB_NETWORK_ERROR,
                                 "Problem with sending data. "
                                 "Failed to send data to REST server");
            return;
        }

        if (lcb_sockrw_flushed(conn)) {
            lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
        }

    }

    if ((which & LCB_READ_EVENT) == 0) {
        return;
    }

    status = lcb_sockrw_slurp(conn, conn->input);
    if (status != LCB_SOCKRW_READ && status != LCB_SOCKRW_WOULDBLOCK) {
        lcb_instance_connerr(instance,
                             LCB_NETWORK_ERROR,
                             "Problem with reading data. "
                             "Failed to send read data from REST server");
        return;
    }
    lcb_parse_vbucket_stream(instance);
    lcb_sockrw_set_want(conn, LCB_READ_EVENT, 0);
    lcb_sockrw_apply_want(conn);
}

LIBCOUCHBASE_API
lcb_error_t lcb_connect(lcb_t instance)
{
    instance->backup_idx = 0;
    if (instance->compat.type == LCB_CACHED_CONFIG &&
            instance->vbucket_config != NULL &&
            instance->compat.value.cached.updating == 0) {
        return LCB_SUCCESS;
    }

    /**
     * Schedule the connection to begin, start the timer:
     */
    return lcb_instance_start_connection(instance);
}

static void free_backup_nodes(lcb_t instance)
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
