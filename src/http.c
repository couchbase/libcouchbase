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
                req->io->v.v0.destroy_event(req->io, req->event);
            }
            if (req->sock != INVALID_SOCKET) {
                req->io->v.v0.close(req->io, req->sock);
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
        free(req->password);
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

static int request_valid(lcb_http_request_t req)
{
    switch (req->instance->type) {
    case LCB_TYPE_BUCKET:
        return hashset_is_member(req->server->http_requests, req);
    case LCB_TYPE_CLUSTER:
    default:
        return hashset_is_member(req->instance->http_requests, req);
    }
}

static int http_parser_body_cb(http_parser *p, const char *bytes, lcb_size_t nbytes)
{
    lcb_error_t rc;
    lcb_http_request_t req = p->data;

    if (!request_valid(req)) {
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
    if (!request_valid(req)) {
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

    nr = req->io->v.v0.recvv(req->io, req->sock, iov, 2);
    if (nr == -1) {
        switch (req->io->v.v0.error) {
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
        nw = req->io->v.v0.sendv(req->io, req->sock, iov, 2);
        if (nw == -1) {
            switch (req->io->v.v0.error) {
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
            instance->io->v.v0.update_event(instance->io, req->sock,
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
            lcb_cancel_http_request(instance, req);
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
            instance->io->v.v0.update_event(instance->io, req->sock,
                                            req->event, LCB_READ_EVENT,
                                            req, request_event_handler);
        } else {
            instance->io->v.v0.update_event(instance->io, req->sock,
                                            req->event, LCB_WRITE_EVENT,
                                            req, request_event_handler);
        }
    }
    if (instance->wait && hashset_num_items(instance->http_requests) == 0
            && (!server || hashset_num_items(server->http_requests) == 0)) {
        lcb_maybe_breakout(instance);
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
    req->io->v.v0.update_event(req->io, req->sock,
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
        if (req->io->v.v0.connect(req->io,
                                  req->sock,
                                  req->curr_ai->ai_addr,
                                  (unsigned int)req->curr_ai->ai_addrlen) == 0) {
            /* connected */
            request_connected(req);
            return LCB_SUCCESS;
        } else {
            switch (lcb_connect_status(req->io->v.v0.error)) {
            case LCB_CONNECT_EINTR:
                retry = 1;
                break;
            case LCB_CONNECT_EISCONN:
                request_connected(req);
                return LCB_SUCCESS;
            case LCB_CONNECT_EINPROGRESS: /*first call to connect*/
                req->io->v.v0.update_event(req->io,
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
                    req->io->v.v0.delete_event(req->io, req->sock, req->event);
                    req->io->v.v0.close(req->io, req->sock);
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
    const char *base = NULL, *username = NULL, *body, *path, *content_type;
    char *basebuf = NULL;
    lcb_size_t nn, nbase, nbody, npath;
    lcb_http_method_t method;
    int chunked;

    switch (cmd->version) {
    case 0:
        method = cmd->v.v0.method;
        chunked = cmd->v.v0.chunked;
        npath = cmd->v.v0.npath;
        path = cmd->v.v0.path;
        nbody = cmd->v.v0.nbody;
        body = cmd->v.v0.body;
        content_type = cmd->v.v0.content_type;
        if (type != LCB_HTTP_TYPE_VIEW && type != LCB_HTTP_TYPE_MANAGEMENT) {
            return lcb_synchandler_return(instance, LCB_EINVAL);
        }
        if (type == LCB_HTTP_TYPE_VIEW && instance->type != LCB_TYPE_BUCKET) {
            return lcb_synchandler_return(instance, LCB_EINVAL);
        }
        break;
    case 1:
        method = cmd->v.v1.method;
        chunked = cmd->v.v1.chunked;
        npath = cmd->v.v1.npath;
        path = cmd->v.v1.path;
        nbody = cmd->v.v1.nbody;
        body = cmd->v.v1.body;
        content_type = cmd->v.v1.content_type;
        if (type != LCB_HTTP_TYPE_RAW) {
            return lcb_synchandler_return(instance, LCB_EINVAL);
        }
        break;
    default:
        return lcb_synchandler_return(instance, LCB_EINVAL);
    }
    switch (instance->type) {
    case LCB_TYPE_CLUSTER:
        if (type == LCB_HTTP_TYPE_MANAGEMENT) {
            return lcb_synchandler_return(instance, LCB_EBADHANDLE);
        }
        break;
    case LCB_TYPE_BUCKET:
        /* we need a vbucket config before we can start getting data.. */
        if (instance->vbucket_config == NULL) {
            return lcb_synchandler_return(instance, LCB_CLIENT_ETMPFAIL);
        }
        break;
    }
    if (method >= LCB_HTTP_METHOD_MAX) {
        return lcb_synchandler_return(instance, LCB_EINVAL);
    }
    req = calloc(1, sizeof(struct lcb_http_request_st));
    if (!req) {
        return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
    }
    if (request) {
        *request = req;
    }
    req->on_complete = instance->callbacks.http_complete;
    req->on_data = instance->callbacks.http_data;
    switch (type) {
    case LCB_HTTP_TYPE_VIEW:
        {
            lcb_server_t *server;
            if (instance->type == LCB_TYPE_BUCKET) {
                /* pick random server */
                nn = (lcb_size_t)(gethrtime() >> 10) % instance->nservers;
                server = instance->servers + nn;
            }
            if (!server->couch_api_base) {
                lcb_http_request_destroy(req);
                return lcb_synchandler_return(instance, LCB_NOT_SUPPORTED);
            }
            req->server = server;
            base = server->couch_api_base;
            nbase = strlen(base);
            username = instance->sasl.name;
            if (instance->sasl.password.secret.len) {
                req->password = calloc(instance->sasl.password.secret.len + 1, sizeof(char));
                if (!req->password) {
                    lcb_http_request_destroy(req);
                    return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
                }
                memcpy(req->password, instance->sasl.password.secret.data, instance->sasl.password.secret.len);
            }
        }
        break;

    case LCB_HTTP_TYPE_MANAGEMENT:
        nbase = strlen(instance->host) + strlen(instance->port) + 2;
        base = basebuf = calloc(nbase, sizeof(char));
        if (!base) {
            lcb_http_request_destroy(req);
            return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
        }
        if (snprintf(basebuf, nbase, "%s:%s", instance->host, instance->port) < 0) {
            lcb_http_request_destroy(req);
            return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
        }
        nbase -= 1; /* skip '\0' */
        username = instance->username;
        if (instance->password) {
            req->password = strdup(instance->password);
        }
        break;

    case LCB_HTTP_TYPE_RAW:
        base = cmd->v.v1.host;
        nbase = strlen(base);
        username = cmd->v.v1.username;
        if (cmd->v.v1.password) {
            req->password = strdup(cmd->v.v1.password);
        }
        break;

    default:
        lcb_http_request_destroy(req);
        return lcb_synchandler_return(instance, LCB_EINVAL);
    }
    req->instance = instance;
    req->io = instance->io;
    req->command_cookie = command_cookie;
    req->chunked = chunked;
    req->method = method;
    req->npath = npath;
    if ((req->path = malloc(req->npath)) == NULL) {
        lcb_http_request_destroy(req);
        return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
    }
    memcpy(req->path, path, req->npath);

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
        if (type == LCB_HTTP_TYPE_MANAGEMENT) {
            free(basebuf);
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
        lcb_size_t nauth = 0;

        if (req->password) {
            if (username) {
                char cred[256];
                snprintf(cred, sizeof(cred), "%s:%s", username, req->password);
                if (lcb_base64_encode(cred, auth, sizeof(auth)) == -1) {
                    lcb_http_request_destroy(req);
                    return lcb_synchandler_return(instance, LCB_EINVAL);
                }
                nauth = strlen(auth);
            }
            /* we don't need password anymore */
            free(req->password);
            req->password = NULL;
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
            int ret = 0, rr;

            if (post_headers == NULL) {
                lcb_http_request_destroy(req);
                return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
            }
            if (content_type != NULL && *content_type != '\0') {
                ret = snprintf(post_headers, 512, "\r\nContent-Type: %s", content_type);
                if (ret < 0) {
                    lcb_http_request_destroy(req);
                    return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
                }
            }
            rr = snprintf(post_headers + ret, 512, "\r\nContent-Length: %ld\r\n\r\n", (long)nbody);
            if (rr < 0) {
                lcb_http_request_destroy(req);
                return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
            }
            ret += rr;
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
    if (instance->type == LCB_TYPE_BUCKET) {
        hashset_add(req->server->http_requests, req);
    } else {
        hashset_add(instance->http_requests, req);
    }

    {
        /* Get server socket address */
        int err;
        req->event = req->io->v.v0.create_event(req->io);
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
    if (instance->type == LCB_TYPE_BUCKET) {
        for (ii = 0; ii < instance->nservers; ++ii) {
            lcb_server_t *server = instance->servers + ii;
            if (hashset_is_member(server->http_requests, request)) {
                request->cancelled = 1;
                hashset_remove(server->http_requests, request);
            }
        }
    } else {
        if (hashset_is_member(instance->http_requests, request)) {
            request->cancelled = 1;
            hashset_remove(instance->http_requests, request);
        }
    }
}
