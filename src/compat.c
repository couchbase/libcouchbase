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

static lcb_error_t create_memcached(const struct lcb_memcached_st *user,
                                    VBUCKET_CONFIG_HANDLE vbconfig);


LIBCOUCHBASE_API
lcb_error_t lcb_create_compat(lcb_cluster_t type,
                              const void *specific,
                              lcb_t *instance,
                              struct lcb_io_opt_st *io)
{
    lcb_error_t ret = LCB_NOT_SUPPORTED;
    VBUCKET_CONFIG_HANDLE config;

    *instance = lcb_create(NULL, NULL, NULL, NULL, io);
    if (*instance == NULL) {
        return LCB_CLIENT_ENOMEM;
    }

    config = vbucket_config_create();
    if (config == NULL) {
        lcb_destroy(*instance);
        *instance = NULL;
        return LCB_CLIENT_ENOMEM;
    }

    if (type == LCB_MEMCACHED_CLUSTER) {
        ret = create_memcached(specific, config);
    }

    if (ret == LCB_SUCCESS) {
        lcb_apply_vbucket_config(*instance, config);
    } else {
        vbucket_config_destroy(config);
        lcb_destroy(*instance);
        *instance = NULL;
    }

    return ret;
}

static lcb_error_t create_memcached(const struct lcb_memcached_st *user,
                                    VBUCKET_CONFIG_HANDLE vbconfig)
{
    ringbuffer_t buffer;
    char *copy = strdup(user->serverlist);
    char head[1024];
    int first;
    char *ptr = copy;
    int fail;
    lcb_ssize_t offset = 0;

    if (copy == NULL) {
        return LCB_CLIENT_ENOMEM;
    }

    if (ringbuffer_initialize(&buffer, 1024) == -1) {
        free(copy);
        return LCB_CLIENT_ENOMEM;
    }

    head[0] = '\0';
    offset += snprintf(head + offset, sizeof(head) - offset, "%s", "{");
    offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                       "\"bucketType\":\"memcached\",");
    offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                       "\"nodeLocator\":\"ketama\",");
    if (user->username != NULL) {
        offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                           "\"authType\":\"sasl\",");
        offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                           "\"name\":\"");
        offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                           user->username);
        offset += snprintf(head + offset, sizeof(head) - offset, "%s", "\",");
        if (user->password != NULL) {
            offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                               "\"saslPassword\":\"");
            offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                               user->password);
            offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                               "\",");
        }
    }

    offset += snprintf(head + offset, sizeof(head) - offset, "%s",
                       "\"nodes\": [");
    ringbuffer_write(&buffer, head, strlen(head));

    /* Let's add the hosts... */
    first = 1;
    do {
        char *tok;
        char *next = strchr(ptr, ';');
        const char *port = "11211";
        lcb_ssize_t length;

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

        if (ringbuffer_ensure_capacity(&buffer, length) == -1) {
            free(copy);
            return LCB_CLIENT_ENOMEM;
        }

        ringbuffer_write(&buffer, head, length);

        if (next != NULL) {
            ptr = next + 1;
        } else {
            ptr = NULL;
        }
    } while (ptr != NULL);

    if (ringbuffer_ensure_capacity(&buffer, 3) == -1) {
        free(copy);
        return LCB_CLIENT_ENOMEM;
    }

    ringbuffer_write(&buffer, "]}", 3); /* Include '\0' */

    /* Now let's parse the config! */
    fail = vbucket_config_parse(vbconfig, LIBVBUCKET_SOURCE_MEMORY,
                                (char *)ringbuffer_get_read_head(&buffer));
    free(copy);
    ringbuffer_destruct(&buffer);

    if (fail) {
        /* Hmm... internal error! */
        return LCB_EINTERNAL;
    }

    return LCB_SUCCESS;
}
