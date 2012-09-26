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
    "GET ",    /* LCB_HTTP_METHOD_GET */
    "POST ",   /* LCB_HTTP_METHOD_POST */
    "PUT ",    /* LCB_HTTP_METHOD_PUT */
    "DELETE "  /* LCB_HTTP_METHOD_DELETE */
};


static const char http_version[] = " HTTP/1.1\r\n";
static const char req_headers[] = "User-Agent: libcouchbase/"LCB_VERSION_STRING"\r\n"
                                  "Accept: application/json\r\n";

void lcb_http_request_destroy(lcb_http_request_t req)
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
        free(req->path);
        free(req->url);
        free(req->host);
        free(req->port);
        free(req->parser);
        ringbuffer_destruct(&req->input);
        ringbuffer_destruct(&req->output);
        ringbuffer_destruct(&req->result);
        {
            struct lcb_http_header_st *tmp, *hdr = req->headers_list;
            while (hdr) {
                tmp = hdr->next;
                free(hdr);
                hdr = tmp;
            }
        }
    }
    memset(req, 0xff, sizeof(struct lcb_http_request_st));
    free(req);
}

static int http_parser_header_cb(http_parser *p, const char *bytes,
                                 lcb_size_t nbytes)
{
    lcb_http_request_t req = p->data;
    struct lcb_http_header_st *item;

    item = calloc(1, sizeof(struct lcb_http_header_st));
    if (item == NULL) {
        lcb_error_handler(req->instance, LCB_CLIENT_ENOMEM,
                          "Failed to allocate buffer");
        return -1;
    }
    item->data = malloc(nbytes + 1);
    if (item->data == NULL) {
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
    lcb_http_request_t req = p->data;
    struct lcb_http_header_st *hdr;
    lcb_size_t ii;

    /* +1 pointer for NULL-terminator */
    req->headers = calloc(req->nheaders + 1, sizeof(const char *));
    for (ii = req->nheaders - 1, hdr = req->headers_list; hdr; --ii, hdr = hdr->next) {
        req->headers[ii] = hdr->data;
    }
    return 0;
}

static void setup_lcb_http_resp_t(lcb_http_resp_t *resp,
                                  lcb_http_status_t status,
                                  const char *path,
                                  lcb_size_t npath,
                                  const char *const *headers,
                                  const void *bytes,
                                  lcb_size_t nbytes)
{
    memset(resp, 0, sizeof(*resp));
    resp->version = 0;
    resp->v.v0.status = status;
    resp->v.v0.path = path;
    resp->v.v0.npath = npath;
    resp->v.v0.headers = headers;
    resp->v.v0.bytes = bytes;
    resp->v.v0.nbytes = nbytes;
}

static int http_parser_body_cb(http_parser *p, const char *bytes, lcb_size_t nbytes)
{
    lcb_error_t rc;
    lcb_http_request_t req = p->data;

    if (!hashset_is_member(req->server->http_requests, req)) {
        return 0;
    }
    if (req->chunked) {
        lcb_http_resp_t resp;
        setup_lcb_http_resp_t(&resp, p->status_code, req->path, req->npath,
                              req->headers, bytes, nbytes);
        rc = (p->status_code / 100 == 2) ?  LCB_SUCCESS : LCB_PROTOCOL_ERROR;
        req->on_data(req, req->instance, req->command_cookie, rc, &resp);
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
    lcb_error_t rc;
    lcb_http_request_t req = p->data;
    char *bytes = NULL;
    lcb_size_t np = 0, nbytes = 0;
    lcb_http_resp_t resp;

    req->completed = 1;
    if (!hashset_is_member(req->server->http_requests, req)) {
        return 0;
    }
    rc = (p->status_code / 100 == 2) ?  LCB_SUCCESS : LCB_PROTOCOL_ERROR;
    if (!req->chunked) {
        nbytes = req->result.nbytes;
        if (ringbuffer_is_continous(&req->result, RINGBUFFER_READ, nbytes)) {
            bytes = ringbuffer_get_read_head(&req->result);
        } else {
            if ((bytes = malloc(nbytes)) == NULL) {
                lcb_error_handler(req->instance, LCB_CLIENT_ENOMEM, NULL);
                return -1;
            }
            np = ringbuffer_peek(&req->input, bytes, nbytes);
            if (np != nbytes) {
                lcb_error_handler(req->instance, LCB_EINTERNAL, NULL);
                free(bytes);
                return -1;
            }
        }
    }
    setup_lcb_http_resp_t(&resp, p->status_code, req->path, req->npath,
                          req->headers, bytes, nbytes);
    req->on_complete(req, req->instance, req->command_cookie, rc, &resp);
    if (!req->chunked) {
        ringbuffer_consumed(&req->result, nbytes);
        if (np) {   /* release peek storage */
            free(bytes);
        }
    }
    return 0;
}

static int request_do_fill_input_buffer(lcb_http_request_t req)
{
    struct lcb_iovec_st iov[2];
    lcb_ssize_t nr;
    lcb_http_resp_t resp;

    if (!ringbuffer_ensure_capacity(&req->input, 8192)) {
        lcb_error_handler(req->instance, LCB_CLIENT_ENOMEM,
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
            setup_lcb_http_resp_t(&resp, 0, req->path, req->npath,
                                  NULL, NULL, 0);
            req->on_complete(req, req->instance, req->command_cookie,
                             LCB_NETWORK_ERROR, &resp);
            return -1;
        }
    } else {
        ringbuffer_produced(&req->input, (lcb_size_t)nr);
    }

    return 0;
}

static lcb_ssize_t request_do_read(lcb_http_request_t req)
{
    lcb_size_t nb = 0, np = 0;
    char *bytes;
    lcb_size_t nbytes;

    if (request_do_fill_input_buffer(req)) {
        /* error or would block */
        return -1;
    }
    nbytes = req->input.nbytes;
    bytes = ringbuffer_get_read_head(&req->input);
    if (!ringbuffer_is_continous(&req->input, RINGBUFFER_READ, nbytes)) {
        if ((bytes = malloc(nbytes)) == NULL) {
            lcb_error_handler(req->instance, LCB_CLIENT_ENOMEM, NULL);
            return -1;
        }
        np = ringbuffer_peek(&req->input, bytes, nbytes);
        if (np != nbytes) {
            lcb_error_handler(req->instance, LCB_EINTERNAL, NULL);
            free(bytes);
            return -1;
        }
    }

    if (nbytes > 0) {
        nb = (lcb_size_t)http_parser_execute(req->parser, &req->parser_settings, bytes, nbytes);
        ringbuffer_consumed(&req->input, nbytes);
        if (np) {   /* release peek storage */
            free(bytes);
        }
        if (HTTP_PARSER_ERRNO(req->parser) != HPE_OK) {
            return -1;
        }
        if (req->cancelled || req->completed) {
            return 0;
        } else {
            return (lcb_ssize_t)nb;
        }
    }
    return 0;
}

static int request_do_write(lcb_http_request_t req)
{
    do {
        struct lcb_iovec_st iov[2];
        lcb_ssize_t nw;
        lcb_http_resp_t resp;

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
                setup_lcb_http_resp_t(&resp, 0, req->path, req->npath,
                                      NULL, NULL, 0);
                req->on_complete(req, req->instance, req->command_cookie,
                                 LCB_NETWORK_ERROR, &resp);
                return -1;
            }
        } else {
            ringbuffer_consumed(&req->output, (lcb_size_t)nw);
        }
    } while (req->output.nbytes > 0);

    return 0;
}

static void request_event_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_http_request_t req = arg;
    lcb_t instance = req->instance;
    lcb_server_t *server = req->server;
    lcb_ssize_t rv;
    lcb_http_resp_t resp;

    if (which & LCB_READ_EVENT) {
        rv = request_do_read(req);
        if (rv > 0) {
            instance->io->update_event(instance->io, req->sock,
                                       req->event, LCB_READ_EVENT,
                                       req, request_event_handler);
        } else if (rv < 0) {
            setup_lcb_http_resp_t(&resp, 0, req->path, req->npath,
                                  NULL, NULL, 0);
            req->on_complete(req, req->instance, req->command_cookie,
                             LCB_NETWORK_ERROR, &resp);
            return;
        } else {
            /* considering request was completed and release it */
            hashset_remove(server->http_requests, req);
            lcb_http_request_destroy(req);
        }
    }
    if (which & LCB_WRITE_EVENT) {
        if (request_do_write(req) != 0) {
            setup_lcb_http_resp_t(&resp, 0, req->path, req->npath,
                                  NULL, NULL, 0);
            req->on_complete(req, req->instance, req->command_cookie,
                             LCB_NETWORK_ERROR, &resp);
            return;
        }
        if (req->output.nbytes == 0) {
            instance->io->update_event(instance->io, req->sock,
                                       req->event, LCB_READ_EVENT,
                                       req, request_event_handler);
        } else {
            instance->io->update_event(instance->io, req->sock,
                                       req->event, LCB_WRITE_EVENT,
                                       req, request_event_handler);
        }
    }
    if (instance->wait && hashset_num_items(server->http_requests) == 0) {
        instance->wait = 0;
        instance->io->stop_event_loop(instance->io);
    }
    /* Make it known that this was a success. */
    lcb_error_handler(instance, LCB_SUCCESS, NULL);
    (void)sock;
}

static lcb_error_t request_connect(lcb_http_request_t req);

static void request_connect_handler(lcb_socket_t sock, short which, void *arg)
{
    request_connect((lcb_http_request_t)arg);
    (void)sock;
    (void)which;
}


static void request_connected(lcb_http_request_t req)
{
    req->io->update_event(req->io, req->sock,
                          req->event, LCB_WRITE_EVENT,
                          req, request_event_handler);
}

static lcb_error_t request_connect(lcb_http_request_t req)
{
    int retry;
    int save_errno;
    lcb_http_resp_t resp;

    do {
        if (req->sock == INVALID_SOCKET) {
            /* Try to get a socket.. */
            req->sock = lcb_gai2sock(req->instance,
                                     &req->curr_ai,
                                     &save_errno);
        }

        if (req->curr_ai == NULL) {
            setup_lcb_http_resp_t(&resp, 0, req->path, req->npath,
                                  NULL, NULL, 0);
            req->on_complete(req, req->instance, req->command_cookie,
                             LCB_CONNECT_ERROR, &resp);
            return LCB_CONNECT_ERROR;
        }

        retry = 0;
        if (req->io->connect(req->io,
                             req->sock,
                             req->curr_ai->ai_addr,
                             (unsigned int)req->curr_ai->ai_addrlen) == 0) {
            /* connected */
            request_connected(req);
            return LCB_SUCCESS;
        } else {
            switch (lcb_connect_status(req->io->error)) {
            case LCB_CONNECT_EINTR:
                retry = 1;
                break;
            case LCB_CONNECT_EISCONN:
                request_connected(req);
                return LCB_SUCCESS;
            case LCB_CONNECT_EINPROGRESS: /*first call to connect*/
                req->io->update_event(req->io,
                                      req->sock,
                                      req->event,
                                      LCB_WRITE_EVENT,
                                      req,
                                      request_connect_handler);
                return LCB_SUCCESS;
            case LCB_CONNECT_EALREADY: /* Subsequent calls to connect */
                return LCB_SUCCESS;

            case LCB_CONNECT_EFAIL:
                if (req->curr_ai->ai_next) {
                    retry = 1;
                    req->curr_ai = req->curr_ai->ai_next;
                    req->io->delete_event(req->io, req->sock, req->event);
                    req->io->close(req->io, req->sock);
                    req->sock = INVALID_SOCKET;
                    break;
                } /* Else, we fallthrough */

            default:
                setup_lcb_http_resp_t(&resp, 0, req->path, req->npath,
                                      NULL, NULL, 0);
                req->on_complete(req, req->instance, req->command_cookie,
                                 LCB_CONNECT_ERROR, &resp);
                return LCB_CONNECT_ERROR;
            }
        }
    } while (retry);

    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
lcb_error_t lcb_make_http_request(lcb_t instance,
                                  const void *command_cookie,
                                  lcb_http_type_t type,
                                  const lcb_http_cmd_t *cmd,
                                  lcb_http_request_t *request)
{
    lcb_http_request_t req;
    const char *base = NULL, *username = NULL;
    char *password = NULL;
    lcb_size_t nn, nbase;
    lcb_server_t *server;

    if (type >= LCB_HTTP_TYPE_MAX) {
        return lcb_synchandler_return(instance, LCB_EINVAL);
    }
    if (cmd->v.v0.method >= LCB_HTTP_METHOD_MAX) {
        return lcb_synchandler_return(instance, LCB_EINVAL);
    }
    if (cmd->v.v0.content_type == NULL) {
        return lcb_synchandler_return(instance, LCB_EINVAL);
    }
    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return lcb_synchandler_return(instance, LCB_CLIENT_ETMPFAIL);
    }
    /* pick random server */
    nn = (lcb_size_t)(gethrtime() >> 10) % instance->nservers;
    server = instance->servers + nn;
    req = calloc(1, sizeof(struct lcb_http_request_st));
    if (!req) {
        return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
    }
    if (request) {
        *request = req;
    }
    switch (type) {
    case LCB_HTTP_TYPE_VIEW:
        if (!server->couch_api_base) {
            return lcb_synchandler_return(instance, LCB_NOT_SUPPORTED);
        }
        base = server->couch_api_base;
        nbase = strlen(base);
        username = instance->sasl.name;
        if (instance->sasl.password.secret.len) {
            password = calloc(instance->sasl.password.secret.len + 1, sizeof(char));
            if (!password) {
                return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
            }
            memcpy(password, instance->sasl.password.secret.data, instance->sasl.password.secret.len);
        }
        req->on_complete = instance->callbacks.view_complete;
        req->on_data = instance->callbacks.view_data;
        break;
    case LCB_HTTP_TYPE_MANAGEMENT:
        if (!server->rest_api_server) {
            return lcb_synchandler_return(instance, LCB_NOT_SUPPORTED);
        }
        base = server->rest_api_server;
        nbase = strlen(base);
        username = instance->username;
        if (instance->password) {
            password = strdup(instance->password);
        }
        req->on_complete = instance->callbacks.management_complete;
        req->on_data = instance->callbacks.management_data;
        break;
    default:
        lcb_http_request_destroy(req);
        return lcb_synchandler_return(instance, LCB_EINVAL);
    }
    req->instance = instance;
    req->io = instance->io;
    req->server = server;
    req->command_cookie = command_cookie;

    req->npath = cmd->v.v0.npath;
    if ((req->path = malloc(req->npath)) == NULL) {
        lcb_http_request_destroy(req);
        return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
    }
    memcpy(req->path, cmd->v.v0.path, req->npath);

    req->chunked = cmd->v.v0.chunked;
    req->method = cmd->v.v0.method;

#define BUFF_APPEND(dst, src, len)                                  \
        if (len != ringbuffer_write(dst, src, len)) {               \
            lcb_http_request_destroy(req);                          \
            return lcb_synchandler_return(instance, LCB_EINTERNAL); \
        }

    {
        /* Build URL */
        ringbuffer_t urlbuf;
        lcb_size_t nmisc = 1;

        if (ringbuffer_initialize(&urlbuf, 1024) == -1) {
            lcb_http_request_destroy(req);
            return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
        }
        if (memcmp(base, "http://", 7) != 0) {
            nmisc += 7;
        }
        if (!ringbuffer_ensure_capacity(&urlbuf, nbase + req->npath + nmisc)) {
            ringbuffer_destruct(&urlbuf);
            lcb_http_request_destroy(req);
            return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
        }
        if (nmisc > 1) {
            BUFF_APPEND(&urlbuf, "http://", 7);
        }
        BUFF_APPEND(&urlbuf, base, nbase);
        if (req->path[0] != '/') {
            BUFF_APPEND(&urlbuf, "/", 1);
        }
        BUFF_APPEND(&urlbuf, req->path, req->npath);
        req->nurl = urlbuf.nbytes;
        req->url = calloc(req->nurl + 1, sizeof(char));
        if (req->url == NULL) {
            ringbuffer_destruct(&urlbuf);
            lcb_http_request_destroy(req);
            return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
        }
        nn = ringbuffer_read(&urlbuf, req->url, req->nurl);
        if (nn != req->nurl) {
            ringbuffer_destruct(&urlbuf);
            lcb_http_request_destroy(req);
            return lcb_synchandler_return(instance, LCB_EINTERNAL);
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
            lcb_http_request_destroy(req);
            return lcb_synchandler_return(instance, LCB_EINVAL);
        }
    }

    {
        /* Render HTTP request */
        char auth[256];
        lcb_size_t nauth = 0, nbody = cmd->v.v0.nbody;
        const char *content_type = cmd->v.v0.content_type;
        const char *body = cmd->v.v0.body;
        if (password) {
            if (username) {
                char cred[256];
                snprintf(cred, sizeof(cred), "%s:%s", username, password);
                if (lcb_base64_encode(cred, auth, sizeof(auth)) == -1) {
                    lcb_http_request_destroy(req);
                    return lcb_synchandler_return(instance, LCB_EINVAL);
                }
                nauth = strlen(auth);
            }
            free(password);
        }
        nn = strlen(method_strings[req->method]) + req->url_info.field_data[UF_PATH].len + sizeof(http_version);
        if (req->url_info.field_set & UF_QUERY) {
            nn += (lcb_size_t)req->url_info.field_data[UF_QUERY].len + 1;
        }
        nn += sizeof(req_headers);
        if (nauth) {
            nn += 23 + nauth; /* Authorization: Basic ... */
        }
        nn += 10 + (lcb_size_t)req->url_info.field_data[UF_HOST].len +
              req->url_info.field_data[UF_PORT].len; /* Host: example.com:666\r\n\r\n */
        if (nbody) {
            if (content_type == NULL) {
                content_type = "application/json";
            }
            nn += strlen(content_type);
        }

        if (!ringbuffer_ensure_capacity(&req->output, nn)) {
            lcb_http_request_destroy(req);
            return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
        }

#define EXTRACT_URL_PART(field, dst, len)                                   \
        dst = malloc((len + 1) * sizeof(char));                             \
        if (dst == NULL) {                                                  \
            lcb_http_request_destroy(req);                                  \
            return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);     \
        }                                                                   \
        strncpy(dst, req->url + req->url_info.field_data[field].off, len);  \
        dst[len] = '\0';

        nn = strlen(method_strings[req->method]);
        BUFF_APPEND(&req->output, method_strings[req->method], nn);
        nn = req->url_info.field_data[UF_PATH].len;
        BUFF_APPEND(&req->output, req->url + req->url_info.field_data[UF_PATH].off, nn);
        nn = req->url_info.field_data[UF_QUERY].len;
        if (nn) {
            BUFF_APPEND(&req->output, req->url + req->url_info.field_data[UF_QUERY].off - 1, nn + 1);
        }
        nn = strlen(http_version);
        BUFF_APPEND(&req->output, http_version, nn);
        nn = strlen(req_headers);
        BUFF_APPEND(&req->output, req_headers, nn);
        if (nauth) {
            BUFF_APPEND(&req->output, "Authorization: Basic ", 21);
            BUFF_APPEND(&req->output, auth, nauth);
            BUFF_APPEND(&req->output, "\r\n", 2);
        }
        BUFF_APPEND(&req->output, "Host: ", 6);
        nn = req->url_info.field_data[UF_HOST].len;
        EXTRACT_URL_PART(UF_HOST, req->host, nn);
        BUFF_APPEND(&req->output, req->host, nn);
        nn = req->url_info.field_data[UF_PORT].len;
        EXTRACT_URL_PART(UF_PORT, req->port, nn);
        /* copy port with leading colon */
        BUFF_APPEND(&req->output, req->url + req->url_info.field_data[UF_PORT].off - 1, nn + 1);
        if (req->method == LCB_HTTP_METHOD_PUT ||
                req->method == LCB_HTTP_METHOD_POST) {
            char *post_headers = calloc(512, sizeof(char));
            int ret;

            if (post_headers == NULL) {
                lcb_http_request_destroy(req);
                return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
            }
            ret = snprintf(post_headers, 512, "\r\nContent-Type: %s\r\n"
                           "Content-Length: %ld\r\n\r\n", content_type, (long)nbody);
            if (ret < 0) {
                lcb_http_request_destroy(req);
                return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
            }
            if (!ringbuffer_ensure_capacity(&req->output, nbody + (lcb_size_t)ret)) {
                lcb_http_request_destroy(req);
                return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
            }
            BUFF_APPEND(&req->output, post_headers, (lcb_size_t)ret);
            if (nbody) {
                BUFF_APPEND(&req->output, body, nbody);
            }
            free(post_headers);
        } else {
            BUFF_APPEND(&req->output, "\r\n\r\n", 4);
        }
#undef EXTRACT_URL_PART
    }

#undef BUFF_APPEND

    /* Initialize HTTP parser */
    req->parser = malloc(sizeof(http_parser));
    if (req->parser == NULL) {
        lcb_http_request_destroy(req);
        return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
    }
    http_parser_init(req->parser, HTTP_RESPONSE);
    /* Set back reference to the request */
    req->parser->data = req;
    req->parser_settings.on_body = (http_data_cb)http_parser_body_cb;
    req->parser_settings.on_message_complete = (http_cb)http_parser_complete_cb;
    req->parser_settings.on_header_field = (http_data_cb)http_parser_header_cb;
    req->parser_settings.on_header_value = (http_data_cb)http_parser_header_cb;
    req->parser_settings.on_headers_complete = (http_cb)http_parser_headers_complete_cb;

    /* Store request reference in the server struct */
    hashset_add(server->http_requests, req);

    {
        /* Get server socket address */
        int err;
        req->event = req->io->create_event(req->io);
        err = lcb_getaddrinfo(instance, req->host, req->port, &req->root_ai);
        req->curr_ai = req->root_ai;
        if (err != 0) {
            req->curr_ai = req->root_ai = NULL;
        }
        req->sock = INVALID_SOCKET;
    }

    return lcb_synchandler_return(instance, request_connect(req));
}

LIBCOUCHBASE_API
void lcb_cancel_http_request(lcb_t instance, lcb_http_request_t request)
{
    lcb_size_t ii;
    for (ii = 0; ii < instance->nservers; ++ii) {
        if (hashset_is_member(instance->servers[ii].http_requests, request)) {
            request->cancelled = 1;
        }
    }
}
