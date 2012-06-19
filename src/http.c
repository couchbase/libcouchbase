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

static const char *method_strings[] = {
    "GET ",    /* LIBCOUCHBASE_HTTP_METHOD_GET */
    "POST ",   /* LIBCOUCHBASE_HTTP_METHOD_POST */
    "PUT ",    /* LIBCOUCHBASE_HTTP_METHOD_PUT */
    "DELETE "  /* LIBCOUCHBASE_HTTP_METHOD_DELETE */
};


static const char http_version[] = " HTTP/1.1\r\n";
static const char headers[] = "User-Agent: libcouchbase/"LIBCOUCHBASE_VERSION_STRING"\r\n"
                              "Accept: application/json\r\n";

void libcouchbase_http_request_destroy(libcouchbase_http_request_t req)
{
    if (req) {
        if (req->io) {
            if (req->event) {
                req->io->destroy_event(req->io, req->event);
            }
            if (req->sock != INVALID_SOCKET) {
                req->io->close(req->io, req->sock);
            }
        }
        if (req->root_ai) {
            freeaddrinfo(req->root_ai);
        }
        free(req->url);
        free(req->host);
        ringbuffer_destruct(&req->input);
        ringbuffer_destruct(&req->output);
        ringbuffer_destruct(&req->result);
    }
    memset(req, 0xff, sizeof(struct libcouchbase_http_request_st));
    free(req);
}

static int http_parser_body_cb(http_parser *p, const char *bytes, size_t nbytes)
{
    libcouchbase_error_t rc;
    libcouchbase_http_request_t req = p->data;

    if (!hashset_is_member(req->server->http_requests, req)) {
        return 0;
    }
    if (req->chunked) {
        rc = (p->status_code / 100 == 2) ?  LIBCOUCHBASE_SUCCESS : LIBCOUCHBASE_PROTOCOL_ERROR;
        req->on_data(req, req->instance,
                     req->command_cookie,
                     rc, p->status_code,
                     req->path,
                     req->npath,
                     bytes, nbytes);
    } else {
        if (!ringbuffer_ensure_capacity(&req->result, nbytes)) {
            libcouchbase_error_handler(req->instance, LIBCOUCHBASE_ENOMEM,
                                       "Failed to allocate buffer");
            return -1;
        }
        ringbuffer_write(&req->result, bytes, nbytes);
    }
    return 0;
}

static int http_parser_complete_cb(http_parser *p)
{
    libcouchbase_error_t rc;
    libcouchbase_http_request_t req = p->data;
    char *bytes = NULL;
    libcouchbase_size_t np = 0, nbytes = 0;

    if (!hashset_is_member(req->server->http_requests, req)) {
        return 0;
    }
    rc = (p->status_code / 100 == 2) ?  LIBCOUCHBASE_SUCCESS : LIBCOUCHBASE_PROTOCOL_ERROR;
    if (!req->chunked) {
        nbytes = req->result.nbytes;
        if (ringbuffer_is_continous(&req->result, RINGBUFFER_READ, nbytes)) {
            bytes = ringbuffer_get_read_head(&req->result);
        } else {
            if ((bytes = malloc(nbytes)) == NULL) {
                libcouchbase_error_handler(req->instance, LIBCOUCHBASE_ENOMEM, NULL);
                return -1;
            }
            np = ringbuffer_peek(&req->input, bytes, nbytes);
            if (np != nbytes) {
                libcouchbase_error_handler(req->instance, LIBCOUCHBASE_EINTERNAL, NULL);
                free(bytes);
                return -1;
            }
        }
    }
    req->on_complete(req, req->instance,
                     req->command_cookie,
                     rc, p->status_code,
                     req->path,
                     req->npath,
                     bytes, nbytes);
    if (!req->chunked) {
        ringbuffer_consumed(&req->result, nbytes);
        if (np) {   /* release peek storage */
            free(bytes);
        }
    }
    return 0;
}

static int request_do_fill_input_buffer(libcouchbase_http_request_t req)
{
    struct libcouchbase_iovec_st iov[2];
    libcouchbase_ssize_t nr;

    if (!ringbuffer_ensure_capacity(&req->input, 8192)) {
        libcouchbase_error_handler(req->instance, LIBCOUCHBASE_ENOMEM,
                                   "Failed to allocate buffer");
        return -1;
    }

    ringbuffer_get_iov(&req->input, RINGBUFFER_WRITE, iov);

    nr = req->io->recvv(req->io, req->sock, iov, 2);
    if (nr == -1) {
        switch (req->io->error) {
        case EINTR:
            break;
        case EWOULDBLOCK:
            return 0;
        default:
            req->on_complete(req, req->instance,
                             req->command_cookie,
                             LIBCOUCHBASE_NETWORK_ERROR,
                             0, req->path, req->npath, NULL, 0);
            return -1;
        }
    } else {
        ringbuffer_produced(&req->input, (libcouchbase_size_t)nr);
    }

    return 0;
}

static int request_do_read(libcouchbase_http_request_t req)
{
    libcouchbase_size_t nb = 0, np = 0;
    char *bytes;
    libcouchbase_size_t nbytes;

    if (request_do_fill_input_buffer(req)) {
        /* error or would block */
        return -1;
    }
    nbytes = req->input.nbytes;
    bytes = ringbuffer_get_read_head(&req->input);
    if (!ringbuffer_is_continous(&req->input, RINGBUFFER_READ, nbytes)) {
        if ((bytes = malloc(nbytes)) == NULL) {
            libcouchbase_error_handler(req->instance, LIBCOUCHBASE_ENOMEM, NULL);
            return -1;
        }
        np = ringbuffer_peek(&req->input, bytes, nbytes);
        if (np != nbytes) {
            libcouchbase_error_handler(req->instance, LIBCOUCHBASE_EINTERNAL, NULL);
            free(bytes);
            return -1;
        }
    }

    if (nbytes > 0) {
        nb = http_parser_execute(req->parser, &req->parser_settings, bytes, nbytes);
        ringbuffer_consumed(&req->input, nbytes);
        if (np) {   /* release peek storage */
            free(bytes);
        }
        if (HTTP_PARSER_ERRNO(req->parser) != HPE_OK) {
            return -1;
        }
        if (req->cancelled) {
            return 0;
        } else {
            return nb;
        }
    }
    return 0;
}

static int request_do_write(libcouchbase_http_request_t req)
{
    do {
        struct libcouchbase_iovec_st iov[2];
        libcouchbase_ssize_t nw;

        ringbuffer_get_iov(&req->output, RINGBUFFER_READ, iov);
        nw = req->io->sendv(req->io, req->sock, iov, 2);
        if (nw == -1) {
            switch (req->io->error) {
            case EINTR:
                /* retry */
                break;
            case EWOULDBLOCK:
                return 0;
            default:
                req->on_complete(req, req->instance,
                                 req->command_cookie,
                                 LIBCOUCHBASE_NETWORK_ERROR,
                                 0, req->path, req->npath, NULL, 0);
                return -1;
            }
        } else {
            ringbuffer_consumed(&req->output, (libcouchbase_size_t)nw);
        }
    } while (req->output.nbytes > 0);

    return 0;
}

static void request_event_handler(libcouchbase_socket_t sock, short which, void *arg)
{
    libcouchbase_http_request_t req = arg;
    libcouchbase_t instance = req->instance;
    libcouchbase_server_t *server = req->server;
    int rv;
    (void)sock;

    if (which & LIBCOUCHBASE_READ_EVENT) {
        rv =  request_do_read(req);
        if (rv > 0) {
            instance->io->update_event(instance->io, req->sock,
                                       req->event, LIBCOUCHBASE_READ_EVENT,
                                       req, request_event_handler);
        } else if (rv < 0) {
            req->on_complete(req, instance,
                             req->command_cookie,
                             LIBCOUCHBASE_NETWORK_ERROR,
                             0, req->path, req->npath, NULL, 0);
            return;
        } else {
            /* considering request was completed and release it */
            hashset_remove(server->http_requests, req);
            libcouchbase_http_request_destroy(req);
        }
    }
    if (which & LIBCOUCHBASE_WRITE_EVENT) {
        if (request_do_write(req) != 0) {
            req->on_complete(req, instance,
                             req->command_cookie,
                             LIBCOUCHBASE_NETWORK_ERROR,
                             0, req->path, req->npath, NULL, 0);
            return;
        }
        if (req->output.nbytes == 0) {
            instance->io->update_event(instance->io, req->sock,
                                       req->event, LIBCOUCHBASE_READ_EVENT,
                                       req, request_event_handler);
        } else {
            instance->io->update_event(instance->io, req->sock,
                                       req->event, LIBCOUCHBASE_WRITE_EVENT,
                                       req, request_event_handler);
        }
    }
    if (instance->wait && hashset_num_items(server->http_requests) == 0) {
        instance->wait = 0;
        instance->io->stop_event_loop(instance->io);
    }
    /* Make it known that this was a success. */
    libcouchbase_error_handler(instance, LIBCOUCHBASE_SUCCESS, NULL);
}

static libcouchbase_error_t request_connect(libcouchbase_http_request_t req);

static void request_connect_handler(libcouchbase_socket_t sock, short which, void *arg)
{
    request_connect((libcouchbase_http_request_t)arg);
    (void)sock;
    (void)which;
}


static void request_connected(libcouchbase_http_request_t req)
{
    req->io->update_event(req->io, req->sock,
                          req->event, LIBCOUCHBASE_WRITE_EVENT,
                          req, request_event_handler);
}

static libcouchbase_error_t request_connect(libcouchbase_http_request_t req)
{
    int retry;
    int save_errno;

    do {
        if (req->sock == INVALID_SOCKET) {
            /* Try to get a socket.. */
            req->sock = libcouchbase_gai2sock(req->instance,
                                              &req->curr_ai,
                                              &save_errno);
        }

        if (req->curr_ai == NULL) {
            req->on_complete(req, req->instance,
                             req->command_cookie,
                             LIBCOUCHBASE_CONNECT_ERROR,
                             0, req->path, req->npath, NULL, 0);
            return LIBCOUCHBASE_CONNECT_ERROR;
        }

        retry = 0;
        if (req->io->connect(req->io,
                             req->sock,
                             req->curr_ai->ai_addr,
                             (int)req->curr_ai->ai_addrlen) == 0) {
            /* connected */
            request_connected(req);
            return LIBCOUCHBASE_SUCCESS;
        } else {
            switch (libcouchbase_connect_status(req->io->error)) {
            case LIBCOUCHBASE_CONNECT_EINTR:
                retry = 1;
                break;
            case LIBCOUCHBASE_CONNECT_EISCONN:
                request_connected(req);
                return LIBCOUCHBASE_SUCCESS;
            case LIBCOUCHBASE_CONNECT_EINPROGRESS: /*first call to connect*/
                req->io->update_event(req->io,
                                      req->sock,
                                      req->event,
                                      LIBCOUCHBASE_WRITE_EVENT,
                                      req,
                                      request_connect_handler);
                return LIBCOUCHBASE_SUCCESS;
            case LIBCOUCHBASE_CONNECT_EALREADY: /* Subsequent calls to connect */
                return LIBCOUCHBASE_SUCCESS;

            case LIBCOUCHBASE_CONNECT_EFAIL:
                if (req->curr_ai->ai_next) {
                    retry = 1;
                    req->curr_ai = req->curr_ai->ai_next;
                    req->io->delete_event(req->io, req->sock, req->event);
                    req->io->close(req->io, req->sock);
                    req->sock = INVALID_SOCKET;
                    break;
                } /* Else, we fallthrough */

            default:
                req->on_complete(req, req->instance,
                                 req->command_cookie,
                                 LIBCOUCHBASE_CONNECT_ERROR,
                                 0, req->path, req->npath, NULL, 0);
                return LIBCOUCHBASE_CONNECT_ERROR;
            }
        }
    } while (retry);

    return LIBCOUCHBASE_SUCCESS;
}

static libcouchbase_http_request_t libcouchbase_make_http_request(libcouchbase_t instance,
                                                                  const void *command_cookie,
                                                                  libcouchbase_server_t *server,
                                                                  const char *base,
                                                                  libcouchbase_size_t nbase,
                                                                  const char *path,
                                                                  libcouchbase_size_t npath,
                                                                  const void *body,
                                                                  libcouchbase_size_t nbody,
                                                                  libcouchbase_http_method_t method,
                                                                  int chunked,
                                                                  libcouchbase_error_t *error)
{
    libcouchbase_size_t nn;
    libcouchbase_http_request_t req;

    if (method >= LIBCOUCHBASE_HTTP_METHOD_MAX) {
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_EINVAL);
        return NULL;
    }
    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
        return NULL;
    }
    req = calloc(1, sizeof(struct libcouchbase_http_request_st));
    if (!req) {
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);
        return NULL;
    }
    req->instance = instance;
    req->io = instance->io;
    req->server = server;
    req->command_cookie = command_cookie;
    req->path = path;
    req->npath = npath;
    req->on_complete = instance->callbacks.couch_complete;
    req->on_data = instance->callbacks.couch_data;
    req->chunked = chunked;

#define BUFF_APPEND(dst, src, len)                                                      \
        if (len != ringbuffer_write(dst, src, len)) {                                   \
            libcouchbase_http_request_destroy(req);                                    \
            *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_EINTERNAL); \
            return NULL;                                                                \
        }

    {
        /* Build URL */
        ringbuffer_t urlbuf;

        if (ringbuffer_initialize(&urlbuf, 1024) == -1) {
            libcouchbase_http_request_destroy(req);
            *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);
            return NULL;
        }
        if (!ringbuffer_ensure_capacity(&urlbuf, nbase + npath + 1)) {
            ringbuffer_destruct(&urlbuf);
            libcouchbase_http_request_destroy(req);
            *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);
            return NULL;
        }
        BUFF_APPEND(&urlbuf, base, nbase);
        if (path[0] != '/') {
            BUFF_APPEND(&urlbuf, "/", 1);
        }
        BUFF_APPEND(&urlbuf, path, npath);
        req->nurl = urlbuf.nbytes;
        req->url = calloc(req->nurl + 1, sizeof(char));
        if (req->url == NULL) {
            ringbuffer_destruct(&urlbuf);
            libcouchbase_http_request_destroy(req);
            *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);
            return NULL;
        }
        nn = ringbuffer_read(&urlbuf, req->url, req->nurl);
        if (nn != req->nurl) {
            ringbuffer_destruct(&urlbuf);
            libcouchbase_http_request_destroy(req);
            *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_EINTERNAL);
            return NULL;
        }
        req->url[req->nurl] = '\0';
        ringbuffer_destruct(&urlbuf);
    }

    {
        /* Parse URL */
        unsigned int required_fields = ((1 << UF_HOST) | (1 << UF_PORT) | (1 << UF_PATH));

        if (http_parser_parse_url(req->url, req->nurl, 0, &req->url_info)
                || (req->url_info.field_set & required_fields) != required_fields) {
            /* parse error or missing URL part */
            libcouchbase_http_request_destroy(req);
            *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_EINVAL);
            return NULL;
        }
    }

    {
        /* Render HTTP request */
        nn = strlen(method_strings[method]) + req->url_info.field_data[UF_PATH].len + sizeof(http_version);
        if (req->url_info.field_set & UF_QUERY) {
            nn += req->url_info.field_data[UF_QUERY].len + 1;
        }
        nn += sizeof(headers);
        nn += 10 + req->url_info.field_data[UF_HOST].len +
              req->url_info.field_data[UF_PORT].len; /* Host: example.com:666\r\n\r\n */

        if (!ringbuffer_ensure_capacity(&req->output, nn)) {
            libcouchbase_http_request_destroy(req);
            *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);
            return NULL;
        }

#define EXTRACT_URL_PART(field, dst, len)                                               \
        dst = malloc((len + 1) * sizeof(char));                                         \
        if (dst == NULL) {                                                              \
            libcouchbase_http_request_destroy(req);                                    \
            *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);    \
            return NULL;                                                                \
        }                                                                               \
        strncpy(dst, req->url + req->url_info.field_data[field].off, len);              \
        dst[len] = '\0';

        nn = strlen(method_strings[method]);
        BUFF_APPEND(&req->output, method_strings[method], nn);
        nn = req->url_info.field_data[UF_PATH].len;
        BUFF_APPEND(&req->output, req->url + req->url_info.field_data[UF_PATH].off, nn);
        nn = req->url_info.field_data[UF_QUERY].len;
        if (nn) {
            BUFF_APPEND(&req->output, req->url + req->url_info.field_data[UF_QUERY].off - 1, nn + 1);
        }
        nn = strlen(http_version);
        BUFF_APPEND(&req->output, http_version, nn);
        nn = strlen(headers);
        BUFF_APPEND(&req->output, headers, nn);
        BUFF_APPEND(&req->output, "Host: ", 6);
        nn = req->url_info.field_data[UF_HOST].len;
        EXTRACT_URL_PART(UF_HOST, req->host, nn);
        BUFF_APPEND(&req->output, req->host, nn);
        nn = req->url_info.field_data[UF_PORT].len;
        EXTRACT_URL_PART(UF_PORT, req->port, nn);
        /* copy port with leading colon */
        BUFF_APPEND(&req->output, req->url + req->url_info.field_data[UF_PORT].off - 1, nn + 1);
        if (method != LIBCOUCHBASE_HTTP_METHOD_GET && nbody) {
            char *post_headers = calloc(512, sizeof(char));
            if (post_headers == NULL) {
                libcouchbase_http_request_destroy(req);
                *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);
                return NULL;
            }
            nn = snprintf(post_headers, 512, "\r\nContent-Type: application/json\r\n"
                          "Content-Length: %ld\r\n\r\n", (long)nbody);
            if (!ringbuffer_ensure_capacity(&req->output, nbody + nn)) {
                libcouchbase_http_request_destroy(req);
                *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);
                return NULL;
            }
            BUFF_APPEND(&req->output, post_headers, nn);
            BUFF_APPEND(&req->output, body, nbody);
        } else {
            BUFF_APPEND(&req->output, "\r\n\r\n", 4);
        }
#undef EXTRACT_URL_PART
    }

#undef BUFF_APPEND

    /* Initialize HTTP parser */
    req->parser = malloc(sizeof(http_parser));
    if (req->parser == NULL) {
        libcouchbase_http_request_destroy(req);
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ENOMEM);
        return NULL;
    }
    http_parser_init(req->parser, HTTP_RESPONSE);
    /* Set back reference to the request */
    req->parser->data = req;
    req->parser_settings.on_body = http_parser_body_cb;
    req->parser_settings.on_message_complete = http_parser_complete_cb;


    /* Store request reference in the server struct */
    hashset_add(server->http_requests, req);

    {
        /* Get server socket address */
        int err;
        struct addrinfo hints;

        req->event = req->io->create_event(req->io);
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_UNSPEC;
        err = getaddrinfo(req->host, req->port, &hints, &req->root_ai);
        req->curr_ai = req->root_ai;
        if (err != 0) {
            req->curr_ai = req->root_ai = NULL;
        }
        req->sock = INVALID_SOCKET;
    }

    *error = libcouchbase_synchandler_return(instance, request_connect(req));
    return req;
}

LIBCOUCHBASE_API
libcouchbase_http_request_t libcouchbase_make_couch_request(libcouchbase_t instance,
                                                            const void *command_cookie,
                                                            const char *path,
                                                            libcouchbase_size_t npath,
                                                            const void *body,
                                                            libcouchbase_size_t nbody,
                                                            libcouchbase_http_method_t method,
                                                            int chunked,
                                                            libcouchbase_error_t *error)
{
    const char *base = NULL;
    libcouchbase_size_t nn, nbase;
    libcouchbase_server_t *server;

    /* pick random server */
    nn = (libcouchbase_size_t)(gethrtime() >> 10) % instance->nservers;
    server = instance->servers + nn;

    /* memcached buckets don't support views */
    if (!server->couch_api_base) {
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NOT_SUPPORTED);
        return NULL;
    }
    base = server->couch_api_base;
    nbase = strlen(base);

    return libcouchbase_make_http_request(instance, command_cookie, server,
                                          base, nbase, path, npath, body,
                                          nbody, method, chunked, error);
}

LIBCOUCHBASE_API
libcouchbase_http_request_t libcouchbase_make_management_request(libcouchbase_t instance,
                                                                 const void *command_cookie,
                                                                 const char *path,
                                                                 libcouchbase_size_t npath,
                                                                 const void *body,
                                                                 libcouchbase_size_t nbody,
                                                                 libcouchbase_http_method_t method,
                                                                 int chunked,
                                                                 libcouchbase_error_t *error)
{
    const char *base = NULL;
    libcouchbase_size_t nn, nbase;
    libcouchbase_server_t *server;

    /* pick random server */
    nn = (libcouchbase_size_t)(gethrtime() >> 10) % instance->nservers;
    server = instance->servers + nn;

    /* memcached buckets don't support views */
    if (!server->rest_api_server) {
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NOT_SUPPORTED);
        return NULL;
    }
    base = server->rest_api_server;
    nbase = strlen(base);

    return libcouchbase_make_http_request(instance, command_cookie, server,
                                          base, nbase, path, npath, body,
                                          nbody, method, chunked, error);
}

LIBCOUCHBASE_API
void libcouchbase_cancel_http_request(libcouchbase_http_request_t request)
{
    hashset_remove(request->server->http_requests, request);
    request->cancelled = 1;
}
