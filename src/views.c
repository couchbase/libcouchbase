/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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
#include <event.h>
#include <event2/http.h>
#include <event2/http_struct.h>

/* The internal context for libevent HTTP client callbacks */
struct view_context_st
{
    libcouchbase_t instance;
    char *uri;                  /* verified view URI */
    const void *cookie;         /* opaque command cookie */
    struct evhttp_connection *conn;
    struct evhttp_request *request;
    struct evhttp_uri *evuri;
    libcouchbase_http_method_t method;
    int chunked;
};


static void view_context_free(struct view_context_st *ctx)
{
    if (ctx) {
        if (ctx->uri) {
            free(ctx->uri);
            ctx->uri = NULL;
        }
        if (ctx->evuri) {
            evhttp_uri_free(ctx->evuri);
            ctx->evuri = NULL;
        }
        if (ctx->conn) {
            evhttp_connection_free(ctx->conn);
            ctx->conn = NULL;
        }
        free(ctx);
    }
}

static libcouchbase_error_t translate_response_code(int response_code)
{
    /* TODO perhaps they could me mapped more accurately */
    switch(response_code)
    {
    case HTTP_OK:                   /* 200 request completed ok */
    case HTTP_NOCONTENT:            /* 204 request does not have content */
            return LIBCOUCHBASE_SUCCESS;

    case HTTP_NOTFOUND:             /* 404 could not find content for uri */
            return LIBCOUCHBASE_KEY_ENOENT;

    case HTTP_MOVEPERM:             /* 301 the uri moved permanently */
    case HTTP_MOVETEMP:             /* 302 the uri moved temporarily */
    case HTTP_NOTMODIFIED:          /* 304 page was not modified from last */
    case HTTP_BADMETHOD:            /* 405 method not allowed for this uri */
    case HTTP_ENTITYTOOLARGE:       /* 413 */
    case HTTP_EXPECTATIONFAILED:    /* 417 we can't handle this expectation */
    case HTTP_INTERNAL:             /* 500 internal error */
    case HTTP_NOTIMPLEMENTED:       /* 501 not implemented */
    case HTTP_SERVUNAVAIL:          /* 503 the server is not available */
    default:
            return LIBCOUCHBASE_EINTERNAL;
    }
}

/* This callback will be triggered by libevent when response is downloaded
 * completely. Here we notify clients using libcouchbase_view_complete_callback()
 * or trigger the last libcouchbase_view_data_callback() call to signal that
 * response is over.
 */
static void on_complete_cb(struct evhttp_request *req, void *arg)
{
    struct view_context_st *ctx = arg;
    const unsigned char *bytes;
    size_t nbytes;
    libcouchbase_error_t rc = translate_response_code(req->response_code);

    /* notify the client with error code and response body. if client
     * requested chunked output this callback just call view_data() callback
     * with empty buffer and with response body otherwise */
    bytes = evbuffer_pullup(req->input_buffer, -1);
    nbytes = evbuffer_get_length(req->input_buffer);
    if (ctx->chunked) {
        ctx->instance->callbacks.doc_data(ctx->instance, ctx->cookie, rc,
                                          ctx->uri, bytes, nbytes);
    } else {
        ctx->instance->callbacks.doc_complete(ctx->instance, ctx->cookie, rc,
                                              ctx->uri, bytes, nbytes);
    }

    /* and free resources we captured earlier in the context */
    view_context_free(ctx);
}

/* This callback will be triggered for each chunk of response body. The
 * clinent will be notified using libcouchbase_view_data_callback() */
static void on_data_cb(struct evhttp_request *req, void *arg)
{
    struct view_context_st *ctx = arg;
    const unsigned char *bytes;
    size_t nbytes;

    /* notify the client with error code and a chunck of response body */
    libcouchbase_error_t rc = translate_response_code(req->response_code);
    bytes = evbuffer_pullup(req->input_buffer, -1);
    nbytes = evbuffer_get_length(req->input_buffer);
    ctx->instance->callbacks.doc_data(ctx->instance, ctx->cookie,
                                      rc, ctx->uri, bytes, nbytes);
}

/* Execute CouchDB view using URI part with design document id, view name and
 * optional query parameters. To access the result client must setup at least
 * one of view callbacks:
 *
 *  * libcouchbase_doc_complete_callback() -- yields whole response body.
 *  * libcouchbase_doc_data_callback() -- yields view response chunk by
 *    chunk. Useful when it needed to parse results as soon as they appear in
 *    the stream.
 *
 * @example Fetch first 10 docs from the bucket
 *
 *    libcouchbase_make_doc_request(instance, NULL, "_all_docs?limit=10",
 *                                  LIBCOUCHBASE_HTTP_METHOD_GET,
 *                                  NULL, 0, true);
 *
 * @example Filter first 10 docs using POST request
 *
 *    const char body[] = "{\"keys\": [\"test_1000\", \"test_10002\"]}"
 *    libcouchbase_make_doc_request(instance, NULL, "_all_docs?limit=10",
 *                                  LIBCOUCHBASE_HTTP_METHOD_GET,
 *                                  body, sizeof(body), true);
 */
LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_make_doc_request(libcouchbase_t instance,
                                                   const void *command_cookie,
                                                   const char *path,
                                                   libcouchbase_http_method_t method,
                                                   const void *body,
                                                   size_t nbody,
                                                   bool chunked)
{
    struct view_context_st *ctx;
    const char *hostname;
    int port;
    size_t nn;
    libcouchbase_server_t server;

    /* ensure vbucket config is ready */
    if (instance->vbucket_config == NULL) {
        return LIBCOUCHBASE_ETMPFAIL;
    }
    if (instance->nservers < 1) {
        return LIBCOUCHBASE_EINTERNAL;
    }
    /* pick random server */
    nn = (size_t)(gethrtime() >> 10) % instance->nservers;
    server = instance->servers[nn];

    if (!server.couch_api_base) {
        return LIBCOUCHBASE_NOT_SUPPORTED;
    }

    ctx = calloc(1, sizeof(struct view_context_st));
    if (!ctx) {
        return LIBCOUCHBASE_EINTERNAL;
    }
    ctx->instance = instance;
    ctx->cookie = command_cookie;

    ctx->uri = calloc(1024, sizeof(char));
    if (!ctx->uri) {
        view_context_free(ctx);
        return LIBCOUCHBASE_EINTERNAL;
    }
    snprintf(ctx->uri, 1024, "%s%s%s", server.couch_api_base,
             (path[0] == '/') ? "" : "/",  path);

    /* parse URI to ensure it is properly formed */
    ctx->evuri = evhttp_uri_parse(ctx->uri);
    if (!ctx->evuri) {
        view_context_free(ctx);
        return LIBCOUCHBASE_EINVAL;
    }

    hostname = evhttp_uri_get_host(ctx->evuri);
    port = evhttp_uri_get_port(ctx->evuri);

    /* it will return NULL when buffer is too small */
    if (!evhttp_uri_join(ctx->evuri, ctx->uri, 1024)) {
        view_context_free(ctx);
        return LIBCOUCHBASE_EINVAL;
    }

    // @TODO FIXME!
    ctx->conn = evhttp_connection_base_new(instance->io->cookie, NULL, hostname, (uint16_t)port);
    if (!ctx->conn) {
        view_context_free(ctx);
        return LIBCOUCHBASE_NETWORK_ERROR;
    }
    /* create request object and setup on-complete callback */
    ctx->request = evhttp_request_new(on_complete_cb, ctx);
    if (!ctx->request) {
        view_context_free(ctx);
        return LIBCOUCHBASE_EINTERNAL;
    }

    /* setup chunked callback if the client ready to handle response as a
     * stream. it will be called each time libevent will put something in
     * input buffer */
    ctx->chunked = chunked;
    if (chunked) {
        evhttp_request_set_chunked_cb(ctx->request, on_data_cb);
    }
    evhttp_add_header(ctx->request->output_headers, "User-Agent", "libcouchbase/"LIBCOUCHBASE_VERSION_STRING);
    evhttp_add_header(ctx->request->output_headers, "Host", hostname);
    evhttp_add_header(ctx->request->output_headers, "Accept", "application/json");

    ctx->method = method;
    if (body) {
        evbuffer_add(ctx->request->output_buffer, body, nbody);
    }
    if (evhttp_make_request(ctx->conn, ctx->request, (enum evhttp_cmd_type)ctx->method, ctx->uri) < 0) {
        view_context_free(ctx);
        return LIBCOUCHBASE_EINTERNAL;
    }

    return LIBCOUCHBASE_SUCCESS;
}
