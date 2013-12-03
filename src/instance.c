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
    return instance->bootstrap.connection->host;
}

LIBCOUCHBASE_API
const char *lcb_get_port(lcb_t instance)
{
    return instance->bootstrap.connection->port;
}


LIBCOUCHBASE_API
lcb_int32_t lcb_get_num_replicas(lcb_t instance)
{
    if (instance->config.handle) {
        return instance->config.nreplicas;
    } else {
        return -1;
    }
}

LIBCOUCHBASE_API
lcb_int32_t lcb_get_num_nodes(lcb_t instance)
{
    if (instance->config.handle) {
        return (lcb_int32_t)instance->nservers;
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
    return (const char * const *)instance->config.backup_nodes;
}


static lcb_error_t validate_hostname(lcb_t instance, const char *host, char **realhost)
{
    /* The http parser aborts if it finds a space.. we don't want our
     * program to core, so run a prescan first
     */
    lcb_size_t len = strlen(host);
    lcb_size_t ii;
    char *schema = strstr(host, "://");
    char *path;
    int port;
    int numcolons = 0;

    switch (instance->bootstrap.type) {
    case LCB_CONFIG_TRANSPORT_HTTP:
        port = 8091;
        break;
    case LCB_CONFIG_TRANSPORT_CCCP:
        port = 11210;
        break;
    }
    for (ii = 0; ii < len; ++ii) {
        if (isspace(host[ii])) {
            return LCB_INVALID_HOST_FORMAT;
        }
    }

    if (schema != NULL) {
        lcb_size_t size;
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
        lcb_size_t size;
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

static lcb_error_t setup_bootstrap_hosts(lcb_t ret, const char *host)
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
    ret->config.backup_nodes = calloc(num + 2, sizeof(char *));
    if (ret->config.backup_nodes == NULL) {
        return LCB_CLIENT_ENOMEM;
    }
    ret->config.should_free_backup_nodes = 1;

    ptr = host;
    ii = 0;
    do {
        char nm[NI_MAXHOST + NI_MAXSERV + 2];
        const char *start = ptr;
        lcb_error_t error;

        ptr = strchr(ptr, ';');
        ret->config.backup_nodes[ii] = NULL;
        if (ptr == NULL) {
            /* this is the last part */
            error = validate_hostname(ret, start, &ret->config.backup_nodes[ii]);
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
            error = validate_hostname(ret, nm, &ret->config.backup_nodes[ii]);
        }
        if (error != LCB_SUCCESS) {
            while (ii > 0) {
                free(ret->config.backup_nodes[ii--]);
            }
            return error;
        }

        ++ii;
    } while (ptr != NULL);

    if (ret->config.randomize_bootstrap_nodes) {
        ii = 1;
        while (ret->config.backup_nodes[ii] != NULL) {
            lcb_size_t nidx = (lcb_size_t)(gethrtime() >> 10) % ii;
            char *other = ret->config.backup_nodes[nidx];
            ret->config.backup_nodes[nidx] = ret->config.backup_nodes[ii];
            ret->config.backup_nodes[ii] = other;
            ++ii;
        }
    }

    ret->config.backup_idx = 0;
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
lcb_error_t lcb_create(lcb_t *instance, const struct lcb_create_st *options)
{
    struct lcb_create_st opts;
    lcb_error_t err;
    lcb_t obj;

    memset(&opts, 0, sizeof(opts));
    opts.version = 2;
    opts.v.v2.type = LCB_TYPE_BUCKET;
    opts.v.v2.transport = LCB_CONFIG_TRANSPORT_HTTP;
    if (options != NULL) {
        switch (options->version) {
        case 0:
            opts.v.v2.host = get_nonempty_string(options->v.v0.host);
            opts.v.v2.user = get_nonempty_string(options->v.v0.user);
            opts.v.v2.passwd = get_nonempty_string(options->v.v0.passwd);
            opts.v.v2.bucket = get_nonempty_string(options->v.v0.bucket);
            opts.v.v2.io = options->v.v0.io;
            break;
        case 1:
            opts.v.v2.host = get_nonempty_string(options->v.v1.host);
            opts.v.v2.user = get_nonempty_string(options->v.v1.user);
            opts.v.v2.passwd = get_nonempty_string(options->v.v1.passwd);
            opts.v.v2.bucket = get_nonempty_string(options->v.v1.bucket);
            opts.v.v2.io = options->v.v1.io;
            opts.v.v2.type = options->v.v1.type;
            break;
        case 2:
            opts.v.v2.host = get_nonempty_string(options->v.v2.host);
            opts.v.v2.user = get_nonempty_string(options->v.v2.user);
            opts.v.v2.passwd = get_nonempty_string(options->v.v2.passwd);
            opts.v.v2.bucket = get_nonempty_string(options->v.v2.bucket);
            opts.v.v2.io = options->v.v2.io;
            opts.v.v2.type = options->v.v2.type;
            opts.v.v2.transport = options->v.v2.transport;
            break;
        default:
            return LCB_EINVAL;
        }
    }

    if (opts.v.v2.host == NULL) {
        opts.v.v2.host = "localhost";
    }
    if (opts.v.v2.bucket == NULL) {
        opts.v.v2.bucket = "default";
    }
    switch (opts.v.v2.type) {
    case LCB_TYPE_CLUSTER:
        if (opts.v.v2.user == NULL || opts.v.v2.passwd == NULL) {
            return LCB_EINVAL;
        }
        break;
    case LCB_TYPE_BUCKET:
        if (opts.v.v2.user) {
            /* Do not allow people use Administrator account for data access */
            if (strcmp(opts.v.v2.user, opts.v.v2.bucket) != 0) {
                return LCB_INVALID_USERNAME;
            }
        } else {
            /* Fallback to bucket name if the username is missing */
            opts.v.v2.user = opts.v.v2.bucket;
        }
        break;
    default:
        return LCB_EINVAL;
    }
    obj = calloc(1, sizeof(*obj));
    if (obj == NULL) {
        return LCB_CLIENT_ENOMEM;
    }
    switch (opts.v.v2.transport) {
    case LCB_CONFIG_TRANSPORT_HTTP:
        lcb_bootstrap_use_http(obj);
        break;
    case LCB_CONFIG_TRANSPORT_CCCP:
        lcb_bootstrap_use_cccp(obj);
        break;
    default:
        lcb_destroy(obj);
        return LCB_EINVAL;
    }
    obj->bucket = strdup(opts.v.v2.bucket);
    if (obj->bucket == NULL) {
        lcb_destroy(obj);
        return LCB_CLIENT_ENOMEM;
    }
    if (opts.v.v2.user) {
        obj->username = strdup(opts.v.v2.user);
        if (obj->username == NULL) {
            lcb_destroy(obj);
            return LCB_CLIENT_ENOMEM;
        }
    }
    if (opts.v.v2.passwd) {
        obj->password = strdup(opts.v.v2.passwd);
        if (obj->password == NULL) {
            lcb_destroy(obj);
            return LCB_CLIENT_ENOMEM;
        }
    }
    /* No error has occurred yet. */
    obj->last_error = LCB_SUCCESS;
    obj->type = opts.v.v2.type;
    obj->compat.type = (lcb_compat_t)0xdead;
    if (opts.v.v2.io == NULL) {
        lcb_io_opt_t ops;
        err = lcb_create_io_ops(&ops, NULL);
        if (err != LCB_SUCCESS) {
            /* You can't initialize the library without a io-handler! */
            lcb_destroy(obj);
            return err;
        }
        opts.v.v2.io = ops;
        opts.v.v2.io->v.v0.need_cleanup = 1;
    }
    obj->io = opts.v.v2.io;
    obj->config.randomize_bootstrap_nodes = 1;
    obj->config.syncmode = LCB_ASYNCHRONOUS;
    obj->config.ipv6 = LCB_IPV6_DISABLED;
    obj->config.operation_timeout = LCB_DEFAULT_TIMEOUT;
    obj->config.bootstrap_timeout = LCB_DEFAULT_CONFIGURATION_TIMEOUT;
    obj->config.views_timeout = LCB_DEFAULT_VIEW_TIMEOUT;
    obj->config.rbufsize = LCB_DEFAULT_RBUFSIZE;
    obj->config.wbufsize = LCB_DEFAULT_WBUFSIZE;
    obj->config.durability_timeout = LCB_DEFAULT_DURABILITY_TIMEOUT;
    obj->config.durability_interval = LCB_DEFAULT_DURABILITY_INTERVAL;
    obj->config.http_timeout = LCB_DEFAULT_HTTP_TIMEOUT;
    obj->config.max_redir = LCB_DEFAULT_CONFIG_MAXIMUM_REDIRECTS;
    lcb_initialize_packet_handlers(obj);
    err = setup_bootstrap_hosts(obj, opts.v.v2.host);
    if (err != LCB_SUCCESS) {
        lcb_destroy(obj);
        return err;
    }
    obj->timers = hashset_create();
    if (obj->timers == NULL) {
        lcb_destroy(obj);
        return LCB_CLIENT_ENOMEM;
    }
    obj->http_requests = hashset_create();
    if (obj->http_requests == NULL) {
        lcb_destroy(obj);
        return LCB_CLIENT_ENOMEM;
    }
    obj->durability_polls = hashset_create();
    if (obj->durability_polls == NULL) {
        lcb_destroy(obj);
        return LCB_CLIENT_ENOMEM;
    }
    if (!ringbuffer_initialize(&obj->purged_buf, 4096)) {
        lcb_destroy(obj);
        return LCB_CLIENT_ENOMEM;
    }
    if (!ringbuffer_initialize(&obj->purged_cookies, 4096)) {
        lcb_destroy(obj);
        return LCB_CLIENT_ENOMEM;
    }
    err = obj->bootstrap.setup(obj);
    if (err != LCB_SUCCESS) {
        lcb_destroy(obj);
        return err;
    }

    *instance = obj;
    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
void lcb_destroy(lcb_t instance)
{
    lcb_size_t ii;

    instance->bootstrap.cleanup(instance);
    if (instance->timers != NULL) {
        for (ii = 0; ii < instance->timers->capacity; ++ii) {
            if (instance->timers->items[ii] > 1) {
                lcb_timer_destroy(instance,
                                  (lcb_timer_t)instance->timers->items[ii]);
            }
        }
        hashset_destroy(instance->timers);
    }

    if (instance->durability_polls) {
        struct lcb_durability_set_st **dset_list;
        lcb_size_t nitems = hashset_num_items(instance->durability_polls);
        dset_list = (struct lcb_durability_set_st **)
                    hashset_get_items(instance->durability_polls, NULL);
        if (dset_list) {
            for (ii = 0; ii < nitems; ii++) {
                lcb_durability_dset_destroy(dset_list[ii]);
            }
            free(dset_list);
        }
        hashset_destroy(instance->durability_polls);
    }

    if (instance->config.handle != NULL) {
        vbucket_config_destroy(instance->config.handle);
    }

    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_destroy(instance->servers + ii);
    }

    if (instance->http_requests) {
        for (ii = 0; ii < instance->http_requests->capacity; ++ii) {
            if (instance->http_requests->items[ii] > 1) {
                lcb_http_request_t htreq =
                    (lcb_http_request_t)instance->http_requests->items[ii];

                /**
                 * We don't want to invoke callbacks *or* remove it from our
                 * hash table
                 */
                htreq->status |= LCB_HTREQ_S_CBINVOKED | LCB_HTREQ_S_HTREMOVED;

                /* we should figure out a better error code for this.. */
                lcb_http_request_finish(instance, htreq, LCB_ERROR);
            }
        }
    }

    hashset_destroy(instance->http_requests);
    lcb_free_backup_nodes(instance);
    free(instance->servers);
    if (instance->io && instance->io->v.v0.need_cleanup) {
        lcb_destroy_io_ops(instance->io);
    }

    ringbuffer_destruct(&instance->purged_buf);
    ringbuffer_destruct(&instance->purged_cookies);
    free(instance->histogram);
    free(instance->bucket);
    free(instance->username);
    free(instance->password);
    free(instance->sasl_mech_force);
    memset(instance, 0xff, sizeof(*instance));
    free(instance);
}

LIBCOUCHBASE_API
lcb_error_t lcb_connect(lcb_t instance)
{
    instance->config.backup_idx = 0;
    return instance->bootstrap.connect(instance);
}

void lcb_free_backup_nodes(lcb_t instance)
{
    if (instance->config.should_free_backup_nodes) {
        char **ptr = instance->config.backup_nodes;
        while (*ptr != NULL) {
            free(*ptr);
            ptr++;
        }
        instance->config.should_free_backup_nodes = 0;
    }
    free(instance->config.backup_nodes);
    instance->config.backup_nodes = NULL;
    instance->config.backup_idx = 0;
}

LIBCOUCHBASE_API
void *lcb_mem_alloc(lcb_size_t size)
{
    return malloc(size);
}

LIBCOUCHBASE_API
void lcb_mem_free(void *ptr)
{
    free(ptr);
}
