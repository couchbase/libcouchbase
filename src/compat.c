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
 * This file contains the functions to create / destroy the
 * libcouchbase instance
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"

static libcouchbase_error_t create_memcached(const struct libcouchbase_memcached_st *user,
                                             VBUCKET_CONFIG_HANDLE vbconfig);


LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_create_compat(libcouchbase_cluster_t type,
                                                const void *specific,
                                                libcouchbase_t *instance,
                                                struct libcouchbase_io_opt_st *io)
{
    libcouchbase_error_t ret = LIBCOUCHBASE_NOT_SUPPORTED;

    *instance = libcouchbase_create(NULL, NULL, NULL, NULL, io);
    if (*instance == NULL) {
        return LIBCOUCHBASE_ENOMEM;
    }

    VBUCKET_CONFIG_HANDLE config = vbucket_config_create();
    if (config == NULL) {
        libcouchbase_destroy(*instance);
        *instance = NULL;
        return LIBCOUCHBASE_ENOMEM;
    }

    if (type == LIBCOUCHBASE_MEMCACHED_CLUSTER) {
        ret = create_memcached(specific, config);
    }

    if (ret == LIBCOUCHBASE_SUCCESS) {
        libcouchbase_apply_vbucket_config(*instance, config);
    } else {
        vbucket_config_destroy(config);
        libcouchbase_destroy(*instance);
        *instance = NULL;
    }

    return ret;
}

static libcouchbase_error_t create_memcached(const struct libcouchbase_memcached_st *user,
                                             VBUCKET_CONFIG_HANDLE vbconfig)
{
    ringbuffer_t buffer;
    char *copy = strdup(user->serverlist);
    char head[1024];
    int first;
    char *ptr = copy;
    int fail;
    int offset = 0;

    if (copy == NULL) {
        return LIBCOUCHBASE_ENOMEM;
    }

    if (libcouchbase_ringbuffer_initialize(&buffer, 1024) == -1) {
        free(copy);
        return LIBCOUCHBASE_ENOMEM;
    }

    head[0] = '\0';
    offset += sprintf(head + offset, "%s", "{");
    offset += sprintf(head + offset, "%s", "\"bucketType\":\"memcached\",");
    offset += sprintf(head + offset, "%s", "\"nodeLocator\":\"ketama\",");
    if (user->username != NULL) {
        offset += sprintf(head + offset, "%s", "\"authType\":\"sasl\",");
        offset += sprintf(head + offset, "%s", "\"name\":\"");
        offset += sprintf(head + offset, "%s", user->username);
        offset += sprintf(head + offset, "%s", "\",");
        if (user->password != NULL) {
            offset += sprintf(head + offset, "%s", "\"saslPassword\":\"");
            offset += sprintf(head + offset, "%s", user->password);
            offset += sprintf(head + offset, "%s", "\",");
        }
    }

    offset += sprintf(head + offset, "%s", "\"nodes\": [");
    libcouchbase_ringbuffer_write(&buffer, head, strlen(head));

    /* Let's add the hosts... */
    first = 1;
    do {
        char *tok;
        char *next = strchr(ptr, ';');
        const char *port = "11211";
        size_t length;

        if (next != NULL) {
            *next = '\0';
        }

        tok = strchr(ptr, ':');
        if (tok != NULL) {
            *tok = '\0';
            port = tok + 1;
            if ((tok = strchr(ptr, ':')) != NULL) {
                *tok = '\0'; /* Remove weight for now */
            }
        }

        length = snprintf(head, sizeof(head),
                          "%c{\"hostname\":\"%s\",\"ports\":{\"direct\":%s}}",
                          first ? ' ' : ',', ptr, port);
        first = 0;

        if (libcouchbase_ringbuffer_ensure_capacity(&buffer, length) == -1) {
            free(copy);
            return LIBCOUCHBASE_ENOMEM;
        }

        libcouchbase_ringbuffer_write(&buffer, head, length);

        if (next != NULL) {
            ptr = next + 1;
        } else {
            ptr = NULL;
        }
    } while (ptr != NULL);

    if (libcouchbase_ringbuffer_ensure_capacity(&buffer, 3) == -1) {
        free(copy);
        return LIBCOUCHBASE_ENOMEM;
    }

    libcouchbase_ringbuffer_write(&buffer, "]}", 3); /* Include '\0' */

    /* Now let's parse the config! */
    fail = vbucket_config_parse(vbconfig, LIBVBUCKET_SOURCE_MEMORY,
                                (char*)libcouchbase_ringbuffer_get_read_head(&buffer));
    free(copy);
    libcouchbase_ringbuffer_destruct(&buffer);

    if (fail) {
        /* Hmm... internal error! */
        return LIBCOUCHBASE_EINTERNAL;
    }

    return LIBCOUCHBASE_SUCCESS;
}
