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

static void io_read_handler(lcb_connection_t);
static void io_error_handler(lcb_connection_t);

static lcb_error_t connect_next(http_provider *);
static void read_common(http_provider *);
static void connect_done_handler(lcb_connection_t conn, lcb_error_t err);
static lcb_error_t setup_request_header(http_provider *http);
static lcb_error_t htvb_parse(struct htvb_st *vbs, lcb_type_t btype);


/**
 * Closes the current connection and removes the disconn timer along with it
 */
static void close_current(http_provider *http)
{
    if (http->disconn_timer) {
        lcb_timer_destroy(NULL, http->disconn_timer);
        http->disconn_timer = NULL;
    }
    lcb_connection_close(&http->connection);
}

/**
 * Call when there is an error in I/O. This includes read, write, connect
 * and timeouts.
 */
static lcb_error_t io_error(http_provider *http)
{
    lcb_error_t err;
    char *errinfo;

    LOG(http, ERR, "Got I/O Error");
    close_current(http);

    err = lcb_connection_next_node(&http->connection, http->nodes, &errinfo);

    if (err != LCB_SUCCESS) {
        lcb_confmon_provider_failed(&http->base, err);
        return err;
    } else {
        setup_request_header(http);
        http->connection.on_connect_complete = connect_done_handler;
    }
    return LCB_SUCCESS;
}

static void protocol_error(http_provider *http, lcb_error_t err)
{
    int can_retry = 1;

    lcb_log(LOGARGS(http, ERROR), "Got protocol-level error 0x%x", err);
    /**
     * XXX: We only want to retry on some errors. Things which signify an
     * obvious user error should be left out here; we only care about
     * actual "network" errors
     */

    if (err == LCB_AUTH_ERROR ||
            err == LCB_PROTOCOL_ERROR ||
            err == LCB_BUCKET_ENOENT) {
        can_retry = 0;
    }

    if (http->retry_on_missing &&
            (err == LCB_BUCKET_ENOENT || err == LCB_AUTH_ERROR)) {
        LOG(http, INFO, "Retrying on AUTH||BUCKET_ENOENT");
        can_retry = 1;
    }

    if (!can_retry) {
        close_current(http);
        lcb_confmon_provider_failed(&http->base, err);

    } else {
        io_error(http);
    }
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
    lcb_confmon_set_next(http->base.parent, http->current_config, 0);
    lcb_connection_cancel_timer(&http->connection);
    http->connection.timeout.usec = 0;
}

/**
 * Common function to handle parsing the HTTP stream for both v0 and v1 io
 * implementations.
 */
static void read_common(http_provider *http)
{
    lcb_error_t err;
    lcb_connection_t conn = &http->connection;
    int old_generation = http->stream.generation;

    lcb_log(LOGARGS(http, TRACE), "Received %d bytes on HTTP stream",
            conn->input->nbytes);

    lcb_string_rbappend(&http->stream.chunk, conn->input, 1);

    err = htvb_parse(&http->stream, http->base.parent->settings->conntype);

    if (http->stream.generation != old_generation) {
        lcb_log(LOGARGS(http, DEBUG),
                "Generation %d -> %d", old_generation, http->stream.generation);

        set_new_config(http);
    } else {
        lcb_log(LOGARGS(http, TRACE), "HTTP not yet done. Err=0x%x", err);
    }

    if (err != LCB_BUSY && err != LCB_SUCCESS) {
        protocol_error(http, err);
        return;
    }

    lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
    lcb_sockrw_apply_want(conn);
}

static lcb_error_t setup_request_header(http_provider *http)
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
                       http->connection.host, http->connection.port);

    offset += snprintf(buf + offset, nbuf - offset, "%s\r\n",
                       LAST_HTTP_HEADER);

    lcb_log(LOGARGS(http, DEBUG), "Request header: %s", buf);

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

    lcb_assert(LCB_SUCCESS == lcb_connection_reset_buffers(&http->connection));
}

static void connect_done_handler(lcb_connection_t conn, lcb_error_t err)
{
    http_provider *http = (http_provider *)conn->data;
    LOG(http, DEBUG, "Connected to REST API");

    if (err != LCB_SUCCESS) {
        LOG(http, ERR, "HTTP Connection failed");
        io_error(http);
        return;
    }

    lcb_connection_reset_buffers(conn);
    ringbuffer_strcat(conn->output, http->request_buf);
    lcb_assert(conn->output->nbytes > 0);

    lcb_sockrw_set_want(conn, LCB_RW_EVENT, 0);
    lcb_sockrw_apply_want(conn);
    lcb_connection_activate_timer(conn);
}

static void timeout_handler(lcb_connection_t conn, lcb_error_t err)
{
    http_provider *http = (http_provider *)conn->data;
    LOG(http, WARN, "Stream timed out");
    io_error(http);

    (void)err;
}


static lcb_error_t connect_next(http_provider *http)
{
    char *errinfo = NULL;
    lcb_error_t err;
    lcb_connection_t conn = &http->connection;

    close_current(http);
    reset_stream_state(http);

    conn->on_connect_complete = connect_done_handler;
    conn->timeout.usec = http->base.parent->settings->config_timeout;

    LOG(http, TRACE, "Starting HTTP Configuration Provider");

    err = lcb_connection_cycle_nodes(conn, http->nodes, &errinfo);

    if (err == LCB_SUCCESS) {
        lcb_connection_delay_timer(conn);
        err = setup_request_header(http);
    }

    if (err != LCB_SUCCESS) {
        lcb_log(LOGARGS(http, ERROR), "Couldn't schedule connection (%d)", err);
    }


    return err;
}

static void delayed_disconn(lcb_timer_t tm,
                            lcb_t instance, const void *cookie)
{
    http_provider *http = (http_provider *)cookie;

    LOG(http, DEBUG, "Stopping HTTP provider");

    /** closes the connection and cleans up the timer */
    close_current(http);
    lcb_connection_cancel_timer(&http->connection);
    reset_stream_state(http);

    (void)tm;
    (void)instance;
}

static lcb_error_t pause_http(clconfig_provider *pb)
{
    http_provider *http = (http_provider *)pb;
    if (http->disconn_timer) {
        return LCB_SUCCESS;
    }

    http->disconn_timer =
            lcb_timer_create_simple(pb->parent->settings->io,
                                    http,
                                    pb->parent->settings->bc_http_stream_time,
                                    delayed_disconn);
    return LCB_SUCCESS;
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
    if (http->disconn_timer) {
        lcb_timer_destroy(NULL, http->disconn_timer);
        http->disconn_timer = NULL;
        /** Assume we're already connected */
        http->connection.timeout.usec = provider->parent->settings->config_timeout;
        lcb_connection_delay_timer(&http->connection);
        return LCB_SUCCESS;
    }

    return connect_next(http);
}

static clconfig_info* http_get_cached(clconfig_provider *provider)
{
    http_provider *http = (http_provider *)provider;
    return http->current_config;
}

static void refresh_nodes(clconfig_provider *pb,
                          hostlist_t newnodes,
                          VBUCKET_CONFIG_HANDLE newconfig)
{
    unsigned int ii;
    http_provider *http = (http_provider *)pb;

    hostlist_clear(http->nodes);
    if (!newconfig) {
        for (ii = 0; ii < newnodes->nentries; ii++) {
            hostlist_add_host(http->nodes, newnodes->entries + ii);
        }
        return;
    }

    for (ii = 0; (int)ii < vbucket_config_get_num_servers(newconfig); ii++) {
        lcb_error_t status;
        const char *ss = vbucket_config_get_rest_api_server(newconfig, ii);
        lcb_assert(ss != NULL);
        status = hostlist_add_stringz(http->nodes, ss, 8091);
        lcb_assert(status ==  LCB_SUCCESS);
    }
}

static void shutdown_http(clconfig_provider *provider)
{
    http_provider *http = (http_provider *)provider;

    reset_stream_state(http);

    lcb_string_release(&http->stream.chunk);
    lcb_string_release(&http->stream.input);
    lcb_string_release(&http->stream.header);

    lcb_connection_close(&http->connection);
    lcb_connection_cleanup(&http->connection);

    if (http->current_config) {
        lcb_clconfig_decref(http->current_config);
    }
    if (http->disconn_timer) {
        lcb_timer_destroy(NULL, http->disconn_timer);
    }
    if (http->nodes) {
        hostlist_destroy(http->nodes);
    }
    free(http);
}

clconfig_provider * lcb_clconfig_create_http(lcb_confmon *parent)
{
    lcb_error_t status;

    http_provider *http = calloc(1, sizeof(*http));
    lcb_connection_t conn = &http->connection;
    if (!http) {
        return NULL;
    }

    status = lcb_connection_init(&http->connection,
                                 parent->settings->io,
                                 parent->settings);

    if (status != LCB_SUCCESS) {
        free(http);
        return NULL;
    }

    if (! (http->nodes = hostlist_create())) {
        lcb_connection_cleanup(&http->connection);
        free(http);
        return NULL;
    }

    http->base.type = LCB_CLCONFIG_HTTP;
    http->base.refresh = get_refresh;
    http->base.pause = pause_http;
    http->base.get_cached = http_get_cached;
    http->base.shutdown = shutdown_http;
    http->base.nodes_updated = refresh_nodes;
    http->base.enabled = 1;
    http->connection.timeout.usec = parent->settings->config_timeout;
    conn->easy.error = io_error_handler;
    conn->easy.read = io_read_handler;
    conn->on_timeout = timeout_handler;
    conn->data = http;

    lcb_connection_setup_generic(conn);

    lcb_string_init(&http->stream.chunk);
    lcb_string_init(&http->stream.header);
    lcb_string_init(&http->stream.input);

    return &http->base;
}

static void io_error_handler(lcb_connection_t conn)
{
    io_error((http_provider *)conn->data);
}

static void io_read_handler(lcb_connection_t conn)
{
    http_provider *http = conn->data;
    read_common(http);
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
        /** We have a previous configuration... */
        VBUCKET_CONFIG_DIFF *diff = NULL;
        VBUCKET_CONFIG_HANDLE old_config = vbs->config->vbc;
        diff = vbucket_compare(old_config, new_config);

        if (diff == NULL) {
            vbs->config->cmpclock = gethrtime();
            vbucket_config_destroy(new_config);
            return LCB_SUCCESS;

        } else {
            vbucket_free_diff(diff);
        }
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

lcb_connection_t lcb_confmon_get_rest_connection(lcb_confmon *mon)
{
    http_provider *http;
    http = (http_provider *)mon->all_providers[LCB_CLCONFIG_HTTP];

    if (!http) {
        return NULL;
    }
    return &http->connection;
}
