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
#include "logging.h"
#include "settings.h"
#include <lcbio/ssl.h>

#define LOGARGS(req, lvl) \
    req->instance->settings, "http-io", LCB_LOG_##lvl, __FILE__, __LINE__



struct parser_ctx_st {
    lcb_t instance;
    lcb_http_request_t req;
};

static int http_parser_header_cb(http_parser *p, const char *bytes,
                                 lcb_size_t nbytes)
{
    struct parser_ctx_st *ctx = p->data;
    lcb_http_request_t req = ctx->req;
    struct lcb_http_header_st *item;

    item = calloc(1, sizeof(struct lcb_http_header_st));
    if (item == NULL) {
        lcb_error_handler(req->instance, LCB_CLIENT_ENOMEM,
                          "Failed to allocate buffer");
        return -1;
    }
    item->data = malloc(nbytes + 1);
    if (item->data == NULL) {
        free(item);
        lcb_error_handler(req->instance, LCB_CLIENT_ENOMEM,
                          "Failed to allocate buffer");
        return -1;
    }
    memcpy(item->data, bytes, nbytes);
    item->data[nbytes] = '\0';
    item->next = req->headers_list;
    req->headers_list = item;
    req->nheaders++;
    return 0;
}

static int http_parser_headers_complete_cb(http_parser *p)
{
    struct parser_ctx_st *ctx = p->data;
    lcb_http_request_t req = ctx->req;
    struct lcb_http_header_st *hdr;
    lcb_size_t ii;
    lcb_t instance = req->instance;
    const char *location = NULL;

    /* +1 pointer for NULL-terminator */
    req->headers = calloc(req->nheaders + 1, sizeof(const char *));
    for (ii = req->nheaders - 1, hdr = req->headers_list; hdr; --ii, hdr = hdr->next) {
        req->headers[ii] = hdr->data;
        if (strcasecmp("Location", hdr->data) == 0) {
            if (hdr->next) {
                location = req->headers[ii + 1];
            }
        }
    }
    if (p->status_code >= 300 && p->status_code < 400) {
        req->redircount++;
        if (location) {
            req->redirect_to = strdup(location);
            if (!req->redirect_to) {
                lcb_http_request_finish(instance, req, LCB_CLIENT_ENOMEM);
            }
        }
        return 1;
    }
    return 0;
}

static int http_parser_body_cb(http_parser *p, const char *bytes, lcb_size_t nbytes)
{
    struct parser_ctx_st *ctx = p->data;
    lcb_http_request_t req = ctx->req;
    lcb_http_resp_t resp;

    if (req->status != LCB_HTREQ_S_ONGOING) {
        return 0;
    }

    if (req->chunked) {
        lcb_setup_lcb_http_resp_t(&resp, p->status_code, req->path, req->npath,
                                  req->headers, bytes, nbytes);
        req->on_data(req, req->instance, req->command_cookie, LCB_SUCCESS, &resp);
    } else {
        if (!ringbuffer_ensure_capacity(&req->result, nbytes)) {
            lcb_error_handler(req->instance, LCB_CLIENT_ENOMEM,
                              "Failed to allocate buffer");
            return -1;
        }
        ringbuffer_write(&req->result, bytes, nbytes);
    }
    return 0;
}

static int http_parser_complete_cb(http_parser *p)
{
    struct parser_ctx_st *ctx = p->data;
    lcb_http_request_t req = ctx->req;
    char *bytes = NULL;
    lcb_size_t np = 0, nbytes = 0;
    lcb_http_resp_t resp;

    if (req->status != LCB_HTREQ_S_ONGOING || req->redirect_to) {
        return 0;
    }

    if (!req->chunked) {
        nbytes = req->result.nbytes;
        if (ringbuffer_is_continous(&req->result, RINGBUFFER_READ, nbytes)) {
            bytes = ringbuffer_get_read_head(&req->result);
        } else {
            if ((bytes = malloc(nbytes)) == NULL) {
                lcb_error_handler(req->instance, LCB_CLIENT_ENOMEM, NULL);
                return -1;
            }
            np = ringbuffer_peek(&req->result, bytes, nbytes);
            if (np != nbytes) {
                lcb_error_handler(req->instance, LCB_EINTERNAL, NULL);
                free(bytes);
                return -1;
            }
        }
    }
    lcb_setup_lcb_http_resp_t(&resp, p->status_code, req->path, req->npath,
                              req->headers, bytes, nbytes);

    if (req->on_complete) {
        req->on_complete(req,
                         req->instance,
                         req->command_cookie,
                         LCB_SUCCESS,
                         &resp);
    }

    if (!req->chunked) {
        ringbuffer_consumed(&req->result, nbytes);
        if (np) {   /* release peek storage */
            free(bytes);
        }
    }
    req->status |= LCB_HTREQ_S_CBINVOKED;
    return 0;
}

lcb_error_t lcb_http_parse_setup(lcb_http_request_t req)
{
    struct parser_ctx_st *parser_ctx;

    req->parser = malloc(sizeof(http_parser));
    if (req->parser == NULL) {
        return LCB_CLIENT_ENOMEM;
    }

    _lcb_http_parser_init(req->parser, HTTP_RESPONSE);

    parser_ctx = malloc(sizeof(struct parser_ctx_st));
    if (parser_ctx == NULL) {
        return LCB_CLIENT_ENOMEM;
    }
    parser_ctx->instance = req->instance;
    parser_ctx->req = req;
    req->parser->data = parser_ctx;

    req->parser_settings.on_body = (http_data_cb)http_parser_body_cb;
    req->parser_settings.on_message_complete = (http_cb)http_parser_complete_cb;
    req->parser_settings.on_header_field = (http_data_cb)http_parser_header_cb;
    req->parser_settings.on_header_value = (http_data_cb)http_parser_header_cb;
    req->parser_settings.on_headers_complete = (http_cb)http_parser_headers_complete_cb;
    return LCB_SUCCESS;
}

static void
io_read(lcbio_CTX *ctx, unsigned nr)
{
    lcb_http_request_t req = lcbio_ctx_data(ctx);
    lcb_t instance = req->instance;
    /** this variable set to 0 (in progress), -1 (error), 1 (done) */
    int rv = 0;
    int is_done = 0;
    lcb_error_t err = LCB_SUCCESS;
    lcbio_CTXRDITER iter;
    req->refcount++;

    /** Delay the timer */
    lcb_timer_rearm(req->io_timer, req->timeout);

    /** Todo: We can peek inside the RDB interface instead */
    LCBIO_CTX_ITERFOR(ctx, &iter, nr) {
        lcb_size_t nb;
        char *buf;
        unsigned nbuf;

        buf = lcbio_ctx_ribuf(&iter);
        nbuf = lcbio_ctx_risize(&iter);
        nb = _lcb_http_parser_execute(req->parser, &req->parser_settings, buf, nbuf);

        if (nb == nbuf) {
            continue;
        }

        if (HTTP_PARSER_ERRNO(req->parser) != HPE_OK) {
            /** Error */
            rv = -1;
        }
        if (req->status != LCB_HTREQ_S_ONGOING) {
            rv = 1;
        } else {
            rv = 0;
        }
        break;
    }

    if (rv != 0) {
        is_done = 1;

    } else if (rv < 0) {
        is_done = 1;

        if (req->redirect_to) {
            lcb_settings *settings = instance->settings;
            if (settings->max_redir != -1 &&
                      settings->max_redir == req->redircount) {
                err = LCB_TOO_MANY_REDIRECTS;
                req->redirect_to = NULL;
            }
        } else {
            err = LCB_PROTOCOL_ERROR;
        }
    } else {
        lcbio_ctx_rwant(ctx, 1);
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
        lcbio_ctx_schedule(ctx);
    }

    lcb_http_request_decref(req);
}

static void
io_error(lcbio_CTX *ctx, lcb_error_t err)
{
    lcb_http_request_t req = lcbio_ctx_data(ctx);
    lcb_http_request_finish(req->instance, req, err);
}

static void
request_timed_out(lcb_timer_t tm, lcb_t u, const void *cookie)
{
    lcb_http_request_t req = (lcb_http_request_t)cookie;
    lcb_http_request_finish(req->instance, req, LCB_ETIMEDOUT);
    (void)u;
    (void)tm;
}



static void
on_connected(lcbio_SOCKET *sock, void *arg, lcb_error_t err, lcbio_OSERR syserr)
{
    lcb_http_request_t req = arg;
    lcbio_EASYPROCS procs;
    lcb_settings *settings = req->instance->settings;

    LCBIO_CONNREQ_CLEAR(&req->creq);

    if (err != LCB_SUCCESS) {
        lcb_log(LOGARGS(req, ERR), "Connection to failed with Err=0x%x", err);
        lcb_http_request_finish(req->instance, req, err);
        return;
    }

    lcbio_sslify_if_needed(sock, settings);

    procs.cb_err = io_error;
    procs.cb_read = io_read;
    req->ioctx = lcbio_ctx_new(sock, arg, &procs);
    lcbio_ctx_put(req->ioctx, req->outbuf.base, req->outbuf.nused);
    lcbio_ctx_rwant(req->ioctx, 1);
    lcbio_ctx_schedule(req->ioctx);
}

lcb_error_t
lcb_http_request_connect(lcb_http_request_t req)
{
    lcb_host_t dest;
    lcbio_pCONNSTART cs;
    lcb_settings *settings = req->instance->settings;

    memcpy(dest.host, req->host, req->nhost);
    dest.host[req->nhost] = '\0';
    memcpy(dest.port, req->port, req->nport);
    dest.port[req->nport] = '\0';

    req->timeout = req->reqtype == LCB_HTTP_TYPE_VIEW ?
            settings->views_timeout : settings->http_timeout;

    cs = lcbio_connect(req->io, settings, &dest, req->timeout, on_connected, req);
    if (!cs) {
        return LCB_CONNECT_ERROR;
    }
    req->creq.type = LCBIO_CONNREQ_RAW;
    req->creq.u.cs = cs;

    if (!req->io_timer) {
        req->io_timer = lcb_timer_create_simple(req->io,
                                                req,
                                                req->timeout,
                                                request_timed_out);
    } else {
        lcb_timer_rearm(req->io_timer, req->timeout);
    }

    return LCB_SUCCESS;
}
