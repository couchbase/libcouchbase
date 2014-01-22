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

static int request_do_parse(lcb_http_request_t req)
{
    int rv = lcb_http_request_do_parse(req);

    if (rv == 0 && req->instance != NULL) {
        lcb_connection_activate_timer(&req->connection);
    }
    return rv;
}

static void io_read(lcb_connection_t conn)
{
    lcb_http_request_t req = conn->data;
    lcb_t instance = req->instance;
    int rv, is_done = 0;
    lcb_error_t err = LCB_SUCCESS;

    /** Delay the timer */
    lcb_connection_delay_timer(conn);

    rv = request_do_parse(req);
    if (rv == 0) {
        is_done = 1;

    } else if (rv < 0) {
        is_done = 1;

        if (req->redirect_to) {
            lcb_settings *settings = &instance->settings;
            if (settings->max_redir != -1 &&
                      settings->max_redir == req->redircount) {
                err = LCB_TOO_MANY_REDIRECTS;
                req->redirect_to = NULL;
            }
        } else {
            err = LCB_PROTOCOL_ERROR;
        }
    } else {
        lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
    }

    if (is_done) {
        if (req->redirect_to) {
            req->url = req->redirect_to;
            req->nurl = strlen(req->url);
            req->redirect_to = NULL;
            err = lcb_http_verify_url(req, NULL, 0);
            if (err == LCB_SUCCESS) {
                err = lcb_http_request_exec(req);
            } else {
                lcb_http_request_finish(instance, req, err);
            }
        } else {
            lcb_http_request_finish(instance, req, err);
        }
    } else {
        lcb_sockrw_apply_want(conn);
    }

    lcb_http_request_decref(req);
}

static void io_error(lcb_connection_t conn)
{
    lcb_http_request_t req = conn->data;
    lcb_http_request_finish(req->instance, req, LCB_NETWORK_ERROR);
}

static void request_timed_out(lcb_connection_t conn, lcb_error_t err)
{
    lcb_http_request_t req = (lcb_http_request_t)conn->data;
    lcb_http_request_finish(req->instance, req, err);
}



static void request_connected(lcb_connection_t conn, lcb_error_t err)
{
    lcb_http_request_t req = (lcb_http_request_t)conn->data;
    if (err != LCB_SUCCESS) {
        lcb_http_request_finish(req->instance, req, err);
        return;
    }

    lcb_sockrw_set_want(&req->connection, LCB_WRITE_EVENT, 1);
    lcb_sockrw_apply_want(&req->connection);
}

lcb_error_t lcb_http_request_connect(lcb_http_request_t req)
{
    struct lcb_io_use_st use;
    lcb_connection_result_t result;
    lcb_uint32_t timeout;
    lcb_connection_t conn = &req->connection;
    conn->on_connect_complete = request_connected;
    conn->on_timeout = request_timed_out;

    timeout = req->reqtype == LCB_HTTP_TYPE_VIEW ?
            req->instance->settings.views_timeout :
            req->instance->settings.http_timeout;

    lcb_connection_getaddrinfo(conn, 0);

    result = lcb_connection_start(conn, 1);
    if (result != LCB_CONN_INPROGRESS) {
        return LCB_CONNECT_ERROR;
    }

    lcb_connuse_easy(&use, req, timeout, io_read, io_error, request_timed_out);
    lcb_connection_use(conn, &use);
    return LCB_SUCCESS;
}
