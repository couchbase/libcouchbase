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
#include "clconfig.h"
#include "bc_http.h"

#define LOGARGS(ht, lvlbase) \
    ht->base.parent->settings, "htconfig", LCB_LOG_##lvlbase, __FILE__, __LINE__

#define LOG(ht, lvlbase, msg) \
    lcb_log(LOGARGS(ht, lvlbase), msg)

static void io_error_handler(lcbio_CTX *, lcb_error_t);
static void on_connected(lcbio_SOCKET *, void *, lcb_error_t, lcbio_OSERR);

static lcb_error_t connect_next(http_provider *);
static void read_common(lcbio_CTX *, unsigned);
static lcb_error_t setup_request_header(http_provider *, const lcb_host_t *);
static lcb_error_t htvb_parse(struct htvb_st *vbs, lcb_type_t btype);

/**
 * Determine if we're in compatibility mode with the previous versions of the
 * library - where the idle timeout is disabled and a perpetual streaming
 * connection will always remain open (regardless of whether it was triggered
 * by start_refresh/get_refresh).
 */
static int is_v220_compat(http_provider *http)
{
    lcb_uint32_t setting =  PROVIDER_SETTING(&http->base, bc_http_stream_time);
    if (setting == (lcb_uint32_t)-1) {
        return 1;
    }
    return 0;
}

/**
 * Closes the current connection and removes the disconn timer along with it
 */
static void close_current(http_provider *http)
{
    lcbio_timer_disarm(http->disconn_timer);
    if (http->ioctx) {
        lcbio_ctx_close(http->ioctx, NULL, NULL);
    } else if (http->creq){
        lcbio_connect_cancel(http->creq);
    }
    http->creq = NULL;
    http->ioctx = NULL;
}

/**
 * Call when there is an error in I/O. This includes read, write, connect
 * and timeouts.
 */
static lcb_error_t
io_error(http_provider *http, lcb_error_t origerr)
{
    lcb_confmon *mon = http->base.parent;
    lcb_settings *settings = mon->settings;
    int can_retry = 0;

    close_current(http);

    if (http->base.parent->config) {
        can_retry = 1;
    } else if (origerr != LCB_AUTH_ERROR && origerr != LCB_BUCKET_ENOENT) {
        can_retry = 1;
    }

    if (can_retry) {
        http->creq = lcbio_connect_hl(
                mon->iot, settings, http->nodes, 0, settings->config_node_timeout,
                on_connected, http);
        if (http->creq) {
            return LCB_SUCCESS;
        }
    }

    lcb_confmon_provider_failed(&http->base, origerr);
    lcbio_timer_disarm(http->io_timer);
    if (is_v220_compat(http)) {
        lcb_log(LOGARGS(http, INFO),
                "HTTP node list finished. Looping again (disconn_tmo=-1)");
        connect_next(http);
    }
    return origerr;
}

/**
 * Call this if the configuration generation has changed.
 */
static void set_new_config(http_provider *http)
{
    if (http->current_config) {
        lcb_clconfig_decref(http->current_config);
    }

    http->current_config = http->stream.config;
    lcb_clconfig_incref(http->current_config);
    lcb_confmon_provider_success(&http->base, http->current_config);
    lcbio_timer_disarm(http->io_timer);
}

/**
 * Common function to handle parsing the HTTP stream for both v0 and v1 io
 * implementations.
 */
static void
read_common(lcbio_CTX *ctx, unsigned nr)
{
    lcb_error_t err;
    lcbio_CTXRDITER riter;
    http_provider *http = lcbio_ctx_data(ctx);
    int old_generation = http->stream.generation;

    lcb_log(LOGARGS(http, TRACE), "Received %d bytes on HTTP stream", nr);

    lcbio_timer_rearm(http->io_timer,
                      PROVIDER_SETTING(&http->base, config_node_timeout));

    LCBIO_CTX_ITERFOR(ctx, &riter, nr) {
        unsigned nbuf = lcbio_ctx_risize(&riter);
        void *buf = lcbio_ctx_ribuf(&riter);
        lcb_string_append(&http->stream.chunk, buf, nbuf);
    }

    err = htvb_parse(&http->stream, http->base.parent->settings->conntype);

    if (http->stream.generation != old_generation) {
        lcb_log(LOGARGS(http, DEBUG), "Generation %d -> %d", old_generation, http->stream.generation);
        set_new_config(http);
    } else {
        lcb_log(LOGARGS(http, TRACE), "HTTP not yet done. Err=0x%x", err);
    }

    if (err != LCB_BUSY && err != LCB_SUCCESS) {
        io_error(http, err);
        return;
    }

    lcbio_ctx_rwant(ctx, 1);
    lcbio_ctx_schedule(ctx);
}

static lcb_error_t
setup_request_header(http_provider *http, const lcb_host_t *host)
{
    lcb_settings *settings = http->base.parent->settings;

    char *buf = http->request_buf;
    lcb_size_t nbuf = sizeof(http->request_buf);

    lcb_size_t offset = 0;
    http->request_buf[0] = '\0';

    if (settings->conntype == LCB_TYPE_BUCKET) {
        offset = snprintf(buf, nbuf, REQBUCKET_FMT, settings->bucket);

    } else if (settings->conntype == LCB_TYPE_CLUSTER) {
        offset = snprintf(buf, nbuf, REQPOOLS_FMT);

    } else {
        return LCB_EINVAL;
    }

    if (settings->password) {
        char cred[256], b64[256];
        snprintf(cred, sizeof(cred), "%s:%s",
                 settings->username, settings->password);

        if (lcb_base64_encode(cred, b64, sizeof(b64)) == -1) {
            return LCB_EINTERNAL;
        }

        offset += snprintf(buf + offset, nbuf - offset, AUTHDR_FMT, b64);
    }

    offset += snprintf(buf + offset, nbuf - offset, HOSTHDR_FMT,
                       host->host, host->port);

    offset += snprintf(buf + offset, nbuf - offset, "%s\r\n", LAST_HTTP_HEADER);

    return LCB_SUCCESS;
}

static void reset_stream_state(http_provider *http)
{
    lcb_string_clear(&http->stream.chunk);
    lcb_string_clear(&http->stream.input);
    lcb_string_clear(&http->stream.header);

    if (http->stream.config) {
        lcb_clconfig_decref(http->stream.config);
    }

    http->stream.config = NULL;
}

static void
on_connected(lcbio_SOCKET *sock, void *arg, lcb_error_t err, lcbio_OSERR syserr)
{
    http_provider *http = arg;
    lcb_host_t *host;
    lcbio_EASYPROCS procs;
    http->creq = NULL;

    if (err != LCB_SUCCESS) {
        lcb_log(LOGARGS(http, ERR), "Connection to REST API failed with code=0x%x (%d)", err, syserr);
        io_error(http, err);
        return;
    }
    host = lcbio_get_host(sock);
    lcb_log(LOGARGS(http, DEBUG), "Successfuly connected to REST API %s:%s", host->host, host->port);


    if ((err = setup_request_header(http, host)) != LCB_SUCCESS) {
        lcb_log(LOGARGS(http, ERR), "Couldn't setup request header");
        io_error(http, err);
        return;
    }

    memset(&procs, 0, sizeof(procs));
    procs.cb_err = io_error_handler;
    procs.cb_read = read_common;
    http->ioctx = lcbio_ctx_new(sock, http, &procs);
    http->ioctx->subsys = "bc_http";

    lcbio_ctx_put(http->ioctx, http->request_buf, strlen(http->request_buf));
    lcbio_ctx_rwant(http->ioctx, 1);
    lcbio_ctx_schedule(http->ioctx);
    lcbio_timer_rearm(http->io_timer,
                      PROVIDER_SETTING(&http->base, config_node_timeout));
}

static void
timeout_handler(void *arg)
{
    http_provider *http = arg;

    lcb_log(LOGARGS(http, ERR), "HTTP Provider timed out waiting for I/O");

    /**
     * If we're not the current provider then ignore the timeout until we're
     * actively requested to do so
     */
    if (&http->base != http->base.parent->cur_provider ||
            lcb_confmon_is_refreshing(http->base.parent) == 0) {
        lcb_log(LOGARGS(http, DEBUG),
                "Ignoring timeout because we're either not in a refresh "
                "or not the current provider");
        return;
    }

    io_error(http, LCB_ETIMEDOUT);
}


static lcb_error_t
connect_next(http_provider *http)
{
    lcb_settings *settings = http->base.parent->settings;
    lcb_log(LOGARGS(http, TRACE), "Starting HTTP Configuration Provider %p", http);
    close_current(http);
    reset_stream_state(http);
    http->creq = lcbio_connect_hl(http->base.parent->iot, settings, http->nodes, 1,
                                  settings->config_node_timeout, on_connected, http);
    if (http->creq) {
        return LCB_SUCCESS;
    }

    lcb_log(LOGARGS(http, ERROR), "%p: Couldn't schedule connection", http);
    return LCB_CONNECT_ERROR;
}

static void delayed_disconn(void *arg)
{
    http_provider *http = arg;
    lcb_log(LOGARGS(http, DEBUG), "Stopping HTTP provider %p", http);

    /** closes the connection and cleans up the timer */
    close_current(http);
    lcbio_timer_disarm(http->io_timer);
    reset_stream_state(http);
}

static lcb_error_t pause_http(clconfig_provider *pb)
{
    http_provider *http = (http_provider *)pb;
    if (is_v220_compat(http)) {
        return LCB_SUCCESS;
    }

    if (!lcbio_timer_armed(http->disconn_timer)) {
        lcbio_timer_rearm(http->disconn_timer,
                          PROVIDER_SETTING(pb, bc_http_stream_time));
    }
    return LCB_SUCCESS;
}

static void delayed_schederr(void *arg)
{
    http_provider *http = arg;
    lcb_log(LOGARGS(http, ERR), "Http failed with async=0x%x", http->as_errcode);
    lcb_confmon_provider_failed(&http->base, http->as_errcode);
}

static lcb_error_t get_refresh(clconfig_provider *provider)
{
    http_provider *http = (http_provider *)provider;

    /**
     * We want a grace interval here because we might already be fetching a
     * connection. HOWEVER we don't want to indefinitely wait on a socket
     * so we issue a timer indicating how long we expect to wait for a
     * streaming update until we get something.
     */

    /** If we need a new socket, we do connect_next. */
    if (http->ioctx == NULL && http->creq == NULL) {
        lcb_error_t rc = connect_next(http);
        if (rc != LCB_SUCCESS) {
            http->as_errcode = rc;
            lcbio_async_signal(http->as_schederr);
        }
        return rc;
    }

    lcbio_timer_disarm(http->disconn_timer);
    if (http->ioctx) {
        lcbio_timer_rearm(http->io_timer,
                          PROVIDER_SETTING(provider, config_node_timeout));
    }
    return LCB_SUCCESS;
}

static clconfig_info* http_get_cached(clconfig_provider *provider)
{
    http_provider *http = (http_provider *)provider;
    return http->current_config;
}

static void refresh_nodes(clconfig_provider *pb,
                          const hostlist_t newnodes,
                          VBUCKET_CONFIG_HANDLE newconfig)
{
    unsigned int ii;
    http_provider *http = (http_provider *)pb;

    hostlist_clear(http->nodes);
    if (!newconfig) {
        for (ii = 0; ii < newnodes->nentries; ii++) {
            hostlist_add_host(http->nodes, newnodes->entries + ii);
        }
        goto GT_DONE;
    }

    for (ii = 0; (int)ii < vbucket_config_get_num_servers(newconfig); ii++) {
        lcb_error_t status;
        const char *ss = vbucket_config_get_rest_api_server(newconfig, ii);
        lcb_assert(ss != NULL);
        status = hostlist_add_stringz(http->nodes, ss, LCB_CONFIG_HTTP_PORT);
        lcb_assert(status ==  LCB_SUCCESS);
    }

    GT_DONE:
    if (PROVIDER_SETTING(pb, randomize_bootstrap_nodes)) {
        hostlist_randomize(http->nodes);
    }
}

static void
configure_nodes(clconfig_provider *pb, const hostlist_t newnodes)
{
    refresh_nodes(pb, newnodes, NULL);
}

static hostlist_t
get_nodes(const clconfig_provider *pb)
{
    return ((http_provider *)pb)->nodes;
}

static void shutdown_http(clconfig_provider *provider)
{
    http_provider *http = (http_provider *)provider;

    reset_stream_state(http);

    lcb_string_release(&http->stream.chunk);
    lcb_string_release(&http->stream.input);
    lcb_string_release(&http->stream.header);
    close_current(http);

    if (http->current_config) {
        lcb_clconfig_decref(http->current_config);
    }
    if (http->disconn_timer) {
        lcbio_timer_destroy(http->disconn_timer);
    }
    if (http->io_timer) {
        lcbio_timer_destroy(http->io_timer);
    }
    if (http->as_schederr) {
        lcbio_timer_destroy(http->as_schederr);
    }
    if (http->nodes) {
        hostlist_destroy(http->nodes);
    }
    free(http);
}

clconfig_provider * lcb_clconfig_create_http(lcb_confmon *parent)
{
    http_provider *http = calloc(1, sizeof(*http));

    if (!http) {
        return NULL;
    }

    if (! (http->nodes = hostlist_create())) {
        free(http);
        return NULL;
    }

    http->base.type = LCB_CLCONFIG_HTTP;
    http->base.refresh = get_refresh;
    http->base.pause = pause_http;
    http->base.get_cached = http_get_cached;
    http->base.shutdown = shutdown_http;
    http->base.nodes_updated = refresh_nodes;
    http->base.configure_nodes = configure_nodes;
    http->base.get_nodes = get_nodes;
    http->base.enabled = 0;
    http->io_timer = lcbio_timer_new(parent->iot, http, timeout_handler);
    http->disconn_timer = lcbio_timer_new(parent->iot, http, delayed_disconn);
    http->as_schederr = lcbio_timer_new(parent->iot, http, delayed_schederr);

    lcb_string_init(&http->stream.chunk);
    lcb_string_init(&http->stream.header);
    lcb_string_init(&http->stream.input);

    return &http->base;
}

static void
io_error_handler(lcbio_CTX *ctx, lcb_error_t err)
{
    io_error((http_provider *)lcbio_ctx_data(ctx), LCB_NETWORK_ERROR);
    (void)err;
}

static lcb_error_t set_next_config(struct htvb_st *vbs)
{
    VBUCKET_CONFIG_HANDLE new_config = NULL;

    new_config = vbucket_config_create();
    if (!new_config) {
        return LCB_CLIENT_ENOMEM;
    }

    if (vbucket_config_parse(new_config, LIBVBUCKET_SOURCE_MEMORY, vbs->input.base)) {
        vbucket_config_destroy(new_config);
        return LCB_PROTOCOL_ERROR;
    }

    if (vbs->config) {
        lcb_clconfig_decref(vbs->config);
    }

    vbs->config = lcb_clconfig_create(new_config, &vbs->input, LCB_CLCONFIG_HTTP);
    vbs->config->cmpclock = gethrtime();
    vbs->generation++;
    return LCB_SUCCESS;
}

/**
 * Try to parse the piece of data we've got available to see if we got all
 * the data for this "chunk"
 * @param instance the instance containing the data
 * @return 1 if we got all the data we need, 0 otherwise
 */
static lcb_error_t parse_chunk(struct htvb_st *vbs)
{
    lcb_string *chunk = &vbs->chunk;
    lcb_assert(vbs->chunk_size != 0);

    if (vbs->chunk_size == (lcb_size_t) - 1) {
        char *ptr = strstr(chunk->base, "\r\n");
        long val;
        if (ptr == NULL) {
            /* We need more data! */
            return LCB_BUSY;
        }

        ptr += 2;
        val = strtol(chunk->base, NULL, 16);
        val += 2;
        vbs->chunk_size = (lcb_size_t)val;

        lcb_string_erase_beginning(chunk, ptr - chunk->base);
    }

    if (chunk->nused < vbs->chunk_size) {
        /* need more data! */
        return LCB_BUSY;
    }

    return LCB_SUCCESS;
}

/**
 * Try to parse the headers in the input chunk.
 *
 * @param instance the instance containing the data
 * @return 0 success, 1 we need more data, -1 incorrect response
 */
static lcb_error_t parse_header(struct htvb_st *vbs, lcb_type_t btype)
{
    int response_code;
    lcb_string *chunk = &vbs->chunk;
    char *ptr = strstr(chunk->base, "\r\n\r\n");

    if (ptr != NULL) {
        *ptr = '\0';
        ptr += 4;
    } else if ((ptr = strstr(chunk->base, "\n\n")) != NULL) {
        *ptr = '\0';
        ptr += 2;
    } else {
        /* We need more data! */
        return LCB_BUSY;
    }

    /* parse the headers I care about... */
    if (sscanf(chunk->base, "HTTP/1.1 %d", &response_code) != 1) {
        return LCB_PROTOCOL_ERROR;

    } else if (response_code != 200) {
        switch (response_code) {
        case 401:
            return LCB_AUTH_ERROR;
        case 404:
            return LCB_BUCKET_ENOENT;
        default:
            return LCB_PROTOCOL_ERROR;
            break;
        }
    }

    /** TODO: Isn't a vBucket config only for BUCKET types? */
    if (btype == LCB_TYPE_BUCKET &&
            strstr(chunk->base, "Transfer-Encoding: chunked") == NULL &&
            strstr(chunk->base, "Transfer-encoding: chunked") == NULL) {
        return LCB_PROTOCOL_ERROR;
    }

    lcb_string_appendz(&vbs->header, chunk->base);


    /* realign remaining data.. */
    lcb_string_erase_beginning(chunk, ptr-chunk->base);
    vbs->chunk_size = (lcb_size_t) - 1;

    return LCB_SUCCESS;
}

static lcb_error_t parse_body(struct htvb_st *vbs, int *done)
{
    lcb_error_t err = LCB_BUSY;
    char *term;


    if ((err = parse_chunk(vbs)) != LCB_SUCCESS) {
        *done = 1; /* no data */
        lcb_assert(err == LCB_BUSY);
        return err;
    }

    if (lcb_string_append(&vbs->input, vbs->chunk.base, vbs->chunk_size)) {
        return LCB_CLIENT_ENOMEM;
    }


    lcb_string_erase_end(&vbs->input, 2);
    lcb_string_erase_beginning(&vbs->chunk, vbs->chunk_size);

    vbs->chunk_size = (lcb_size_t) - 1;

    if (vbs->chunk.nused > 0) {
        *done = 0;
    }

    term = strstr(vbs->input.base, "\n\n\n\n");

    if (term != NULL) {
        lcb_string tmp;
        lcb_error_t ret;

        /** Next input */
        lcb_string_init(&tmp);
        lcb_string_appendz(&tmp, term + 4);

        *term = '\0';
        ret = set_next_config(vbs);

        /** Now, erase everything until the end of the 'term' */
        if (vbs->input.base) {
            lcb_string_release(&vbs->input);
        }

        lcb_string_transfer(&tmp, &vbs->input);
        return ret;
    }


    return err;
}

static lcb_error_t htvb_parse(struct htvb_st *vbs, lcb_type_t btype)
{
    lcb_error_t status = LCB_ERROR;
    int done = 0;

    if (vbs->header.nused == 0) {
        status = parse_header(vbs, btype);
        if (status != LCB_SUCCESS) {
            return status; /* BUSY or otherwise */
        }
    }

    lcb_assert(vbs->header.nused);
    if (btype == LCB_TYPE_CLUSTER) {
        /* Do not parse payload for cluster connection type */
        return LCB_SUCCESS;
    }

    do {
        status = parse_body(vbs, &done);
    } while (!done);
    return status;
}

void lcb_clconfig_http_enable(clconfig_provider *http)
{
    http->enabled = 1;
}

lcbio_SOCKET *
lcb_confmon_get_rest_connection(lcb_confmon *mon)
{
    http_provider *http = (http_provider *)mon->all_providers[LCB_CLCONFIG_HTTP];
    if (!http->ioctx) {
        return NULL;
    }
    return lcbio_ctx_sock(http->ioctx);

}

lcb_host_t *
lcb_confmon_get_rest_host(lcb_confmon *mon)
{
    lcbio_SOCKET *sock = lcb_confmon_get_rest_connection(mon);
    if (sock) {
        return lcbio_get_host(sock);
    }
    return NULL;
}
