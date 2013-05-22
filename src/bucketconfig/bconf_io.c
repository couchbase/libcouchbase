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

/**
 * This file contains connection routines for the instance
 *
 * @author Mark Nunberg
 */

#include "internal.h"

static void lcb_instance_reset_stream_state(lcb_t instance)
{
    free(instance->vbucket_stream.input.data);
    free(instance->vbucket_stream.chunk.data);
    free(instance->vbucket_stream.header);
    memset(&instance->vbucket_stream, 0, sizeof(instance->vbucket_stream));
    instance->n_http_uri_sent = 0;
}


void lcb_instance_connerr(lcb_t instance,
                                 lcb_error_t err,
                                 const char *errinfo)
{
    lcb_connection_close(&instance->connection);
    /* We try and see if the connection attempt can be relegated to another
     * REST API entry point. If we can, the following should return something
     * other than -1...
     */

    if (lcb_switch_to_backup_node(instance, err, errinfo) != -1) {
        return;
    }

    /* ..otherwise, we have a currently irrecoverable error. bail out all the
     * pending commands, if applicable and/or deliver a final failure for
     * initial connect attempts.
     */

    if (!instance->vbucket_config) {
        /* Initial connection, no pending commands, and connect timer */
        lcb_connection_delete_timer(&instance->connection);
    } else {
        lcb_size_t ii;
        for (ii = 0; ii < instance->nservers; ++ii) {
            lcb_failout_server(instance->servers + ii, err);
        }
    }

    /* check to see if we can breakout of the event loop. don't hang on REST
     * API connection attempts.
     */
    lcb_maybe_breakout(instance);
}


static void instance_connect_done_handler(lcb_connection_t conn,
                                          lcb_error_t err)
{
    lcb_t instance = conn->instance;
    if (err == LCB_SUCCESS) {
        instance->backup_idx = 0;
        instance->io->v.v0.update_event(instance->io, conn->sockfd,
                                        conn->event, LCB_RW_EVENT,
                                        instance, lcb_vbucket_stream_handler);

    } else if (err == LCB_ETIMEDOUT) {
        lcb_error_handler(instance,
                          LCB_CONNECT_ERROR,
                          "Could not connect to server within allotted time");
        instance->timeout.next = 0;
        lcb_maybe_breakout(instance);

    } else {
        lcb_instance_connerr(instance, err, "Couldn't connect");
    }
}

static void setup_current_host(lcb_t instance, const char *host)
{
    char *ptr;
    lcb_connection_t conn = &instance->connection;
    snprintf(conn->host, sizeof(conn->host), "%s", host);
    if ((ptr = strchr(conn->host, ':')) == NULL) {
        strcpy(conn->port, "8091");
    } else {
        *ptr = '\0';
        snprintf(conn->port, sizeof(conn->port), "%s", ptr + 1);
    }
}

lcb_error_t lcb_instance_start_connection(lcb_t instance)
{
    int error;
    char *ptr;
    lcb_connection_t conn = &instance->connection;
    lcb_connection_result_t connres;

    /**
     * First, close the connection, if there's an open socket from a previous
     * one.
     */
    lcb_connection_close(&instance->connection);
    lcb_instance_reset_stream_state(instance);

    instance->n_http_uri_sent = 0;
    conn->on_connect_complete = instance_connect_done_handler;

    do {
        setup_current_host(instance,
                           instance->backup_nodes[instance->backup_idx++]);
        error = lcb_connection_getaddrinfo(conn, 1);

        if (error != 0) {
            /* Ok, we failed to look up that server.. look up the next
             * in the list
             */
            if (instance->backup_nodes[instance->backup_idx] == NULL) {
                char errinfo[1024];
                snprintf(errinfo, sizeof(errinfo),
                         "Failed to look up \"%s:%s\"",
                         conn->host, conn->port);
                return lcb_error_handler(instance,
                                         LCB_UNKNOWN_HOST,
                                         errinfo);
            }
        }
    } while (error != 0);

    instance->last_error = LCB_SUCCESS;

    /* We need to fix the host part... */
    ptr = strstr(instance->http_uri, LCB_LAST_HTTP_HEADER);
    assert(ptr);
    ptr += strlen(LCB_LAST_HTTP_HEADER);
    sprintf(ptr, "Host: %s:%s\r\n\r\n", conn->host, conn->port);

    connres = lcb_connection_start(conn, 1, instance->timeout.usec);
    if (connres == LCB_CONN_ERROR) {
        return lcb_error_handler(instance, LCB_CONNECT_ERROR,
                                 "Couldn't schedule connection");
    }

    if (instance->syncmode == LCB_SYNCHRONOUS) {
        lcb_wait(instance);
    }

    return instance->last_error;
}
