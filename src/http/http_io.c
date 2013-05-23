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

static void http_io_start(lcb_http_request_t req, short events);

static void request_event_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_http_request_t req = arg;
    lcb_t instance = req->instance;
    lcb_server_t *server = req->server;
    lcb_ssize_t rv;
    int should_continue = 1;
    lcb_error_t err = LCB_SUCCESS;

    if (which & LCB_READ_EVENT) {
        lcb_sockrw_status_t status;

        status = lcb_sockrw_slurp(&req->connection, &req->input);
        if (status != LCB_SOCKRW_READ && status != LCB_SOCKRW_WOULDBLOCK) {
            should_continue = 0;
            err = LCB_NETWORK_ERROR;

        } else {
            rv = lcb_http_request_do_parse(req);
            if (rv == 0) {
                /* Request completed */
                should_continue = 0;

            } else if (rv < 0) {
                /* Request format error */
                should_continue = 0;
                err = LCB_PROTOCOL_ERROR;
            } else {
                /* Still want more data: */
                http_io_start(req, LCB_READ_EVENT);
            }
        }
    }

    if (should_continue && (which & LCB_WRITE_EVENT)) {
        lcb_sockrw_status_t status;

        status = lcb_sockrw_write(&req->connection, &req->output);

        if (status != LCB_SOCKRW_WROTE && status != LCB_SOCKRW_WOULDBLOCK) {
            err = LCB_NETWORK_ERROR;
            should_continue = 0;

        } else if (req->output.nbytes == 0) {
            http_io_start(req, LCB_READ_EVENT);

        } else {
            http_io_start(req, LCB_RW_EVENT);
        }
    }

    if (!should_continue) {
        lcb_http_request_finish(instance, server, req, err);
    }

    /* log whatever error ocurred here */
    lcb_error_handler(instance, err, NULL);
    (void)sock;
}


static void request_connected(lcb_connection_t conn, lcb_error_t err)
{
    lcb_http_request_t req = (lcb_http_request_t)conn->data;
    if (err != LCB_SUCCESS) {
        lcb_http_request_finish(req->instance,
                                req->server,
                                req,
                                err);
        return;
    }

    http_io_start(req, LCB_WRITE_EVENT);
}

lcb_error_t lcb_http_request_connect(lcb_http_request_t req)
{
    lcb_connection_result_t result;
    lcb_connection_t conn = &req->connection;
    conn->on_connect_complete = request_connected;
    conn->instance = req->instance;
    conn->data = req;
    lcb_connection_getaddrinfo(conn, 0);
    result = lcb_connection_start(conn, 1, 0);

    if (result != LCB_CONN_INPROGRESS) {
        return LCB_CONNECT_ERROR;
    }

    return LCB_SUCCESS;
}

static void http_io_start(lcb_http_request_t req, short events)
{
    lcb_io_opt_t io = req->io;
    io->v.v0.update_event(io,
                          req->connection.sockfd,
                          req->connection.event,
                          events,
                          req,
                          request_event_handler);
}
