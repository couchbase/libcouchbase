/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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

#include "internal.h"

static int switch_node(lcb_t instance, lcb_error_t error, const char *reason);

void lcb_bootstrap_timeout_handler(lcb_connection_t conn, lcb_error_t err)
{
    lcb_t instance = conn->instance;
    const char *msg = "Configuration update timed out";
    lcb_assert(instance->config.state != LCB_CONFSTATE_CONFIGURED);

    if (instance->config.state == LCB_CONFSTATE_UNINIT) {
        /**
         * If lcb_connect was called explicitly then it means there are no
         * pending operations and we should just break out because we have
         * no valid configuration.
         */
        lcb_error_handler(instance, LCB_CONNECT_ERROR,
                          "Could not connect to server within allotted time");
        lcb_maybe_breakout(instance);
        return;
    }

    lcb_bootstrap_error(instance, err, msg, 0);
}

void lcb_bootstrap_error(lcb_t instance, lcb_error_t err,
                         const char *errinfo, lcb_conferr_opt_t options)
{
    lcb_connection_close(instance->bootstrap.connection);
    /* We try and see if the connection attempt can be relegated to another
     * REST API entry point. If we can, the following should return something
     * other than -1...
     */
    if (instance->config.state == LCB_CONFSTATE_CONFIGURED) {
        instance->config.state = LCB_CONFSTATE_RETRY;
    }

    if (instance->config.backup_nodes[instance->config.backup_idx] == NULL) {
        instance->config.backup_idx = 0;
    }

    if (switch_node(instance, err, errinfo) != -1) {
        return;
    }

    /* ..otherwise, we have a currently irrecoverable error. bail out all the
     * pending commands, if applicable and/or deliver a final failure for
     * initial connect attempts.
     */
    if (instance->config.handle && (options & LCB_CONNFERR_NO_FAILOUT) == 0) {
        lcb_size_t ii;
        for (ii = 0; ii < instance->nservers; ++ii) {
            lcb_failout_server(instance->servers + ii, err);
        }
    }

    if (options & LCB_CONFERR_NO_BREAKOUT) {
        /**
         * Requested no breakout.
         *
         * TODO: We might want to re-activate the timer
         * in the future and wait until a node becomes available; however
         * since this is currently simply a code refactoring, we'll hold this
         * off until later
         */
    } else {
        lcb_maybe_breakout(instance);
    }
}

static int switch_node(lcb_t instance, lcb_error_t error, const char *reason)
{
    if (instance->bootstrap.connection->state == LCB_CONNSTATE_INPROGRESS) {
        return 0; /* We're still connecting. Don't do anything here */
    }

    if (instance->config.backup_nodes == NULL) {
        /* No known backup nodes */
        lcb_error_handler(instance, error, reason);
        return -1;
    }

    if (instance->config.backup_nodes[instance->config.backup_idx] == NULL) {
        lcb_error_handler(instance, error, reason);
        return -1;
    }

    do {
        if (instance->bootstrap.type == LCB_CONFIG_TRANSPORT_HTTP &&
            instance->compat.type == LCB_CACHED_CONFIG) {
            instance->compat.value.cached.updating = 1;
        }
        /* Keep on trying the nodes until all of them failed
         * It will advance instance->config.backup_idx while calling
         * setup_current_host
         */
        if (instance->bootstrap.connect(instance) == LCB_SUCCESS) {
            return 0;
        }
    } while (instance->config.backup_nodes[instance->config.backup_idx] != NULL);
    /* All known nodes are dead */
    lcb_error_handler(instance, error, reason);
    return -1;
}

lcb_error_t lcb_init_next_host(lcb_t instance, int default_port)
{
    char *ptr;
    int error;
    lcb_connection_t conn = &instance->bootstrap.via.http.connection;

    do {
        snprintf(conn->host, sizeof(conn->host), "%s",
                 instance->config.backup_nodes[instance->config.backup_idx++]);
        ptr = strchr(conn->host, ':');
        if (ptr == NULL) {
            snprintf(conn->port, sizeof(conn->port), "%d", default_port);
        } else {
            *ptr = '\0';
            snprintf(conn->port, sizeof(conn->port), "%s", ptr + 1);
        }
        error = lcb_connection_getaddrinfo(conn, 1);
        if (error != 0) {
            /* Ok, we failed to look up that server.. look up the next
             * in the list
             */
            if (instance->config.backup_nodes[instance->config.backup_idx] == NULL) {
                char errinfo[1024];
                snprintf(errinfo, sizeof(errinfo), "Failed to look up \"%s:%s\"",
                         conn->host, conn->port);
                return lcb_error_handler(instance, LCB_UNKNOWN_HOST, errinfo);
            }
        }
    } while (error != 0);
    return LCB_SUCCESS;
}
