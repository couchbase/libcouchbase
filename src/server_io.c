/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2013 Couchbase, Inc.
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
 * This file contains abstracted IO routines for a memcached server
 *
 * @author Mark Nunberg
 */

#include "internal.h"

#define LOGARGS(c, lvl) \
    &(c)->instance->settings, "server", LCB_LOG_##lvl, __FILE__, __LINE__
#define LOG(c, lvl, msg) lcb_log(LOGARGS(c, lvl), msg)

static int do_read_data(lcb_server_t *c, int allow_read)
{
    lcb_sockrw_status_t status;
    lcb_size_t processed = 0;
    int rv = 0;

    /*
    ** The timers isn't supposed to be _that_ accurate.. it's better
    ** to shave off system calls :)
    */
    hrtime_t stop = gethrtime();

    if (allow_read) {
        status = lcb_sockrw_v0_slurp(&c->connection, c->connection.input);

    } else {
        status = LCB_SOCKRW_WOULDBLOCK;
    }

    while ((rv = lcb_proto_parse_single(c, stop)) > 0) {
        processed++;
    }

    if (rv == -1) {
        return -1;
    }

    if (processed) {
        lcb_connection_delay_timer(&c->connection);
    }

    if (status == LCB_SOCKRW_WOULDBLOCK || status == LCB_SOCKRW_READ) {
        return 0;
    }

    return -1;
}

static void event_complete_common(lcb_server_t *c, lcb_error_t rc)
{
    lcb_t instance = c->instance;

    if (rc != LCB_SUCCESS) {
        LOG(c, ERR, "Server failed");
        lcb_failout_server(c, rc);
        lcb_bootstrap_errcount_incr(instance);

    } else {
        lcb_sockrw_apply_want(&c->connection);
        c->inside_handler = 0;
    }

    lcb_maybe_breakout(instance);
    lcb_error_handler(instance, rc, NULL);
}

static void v0_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_connection_t conn = arg;
    lcb_server_t *c = conn->data;
    (void)sock;

    if (which & LCB_WRITE_EVENT) {
        lcb_sockrw_status_t status;

        status = lcb_sockrw_v0_write(conn, conn->output);
        if (status != LCB_SOCKRW_WROTE && status != LCB_SOCKRW_WOULDBLOCK) {
            event_complete_common(c, LCB_NETWORK_ERROR);
            return;
        }
    }

    if (which & LCB_READ_EVENT || conn->input->nbytes) {
        if (do_read_data(c, which & LCB_READ_EVENT) != 0) {
            /* TODO stash error message somewhere
             * "Failed to read from connection to \"%s:%s\"", c->hostname, c->port */
            event_complete_common(c, LCB_NETWORK_ERROR);
            return;
        }
    }

    /**
     * Because of the operations-per-call limit, we might still need to read
     * a bit more once the event loop calls us again. We can't assume a
     * non-blocking read if we don't expect any data, but we can usually rely
     * on a non-blocking write.
     */
    if (conn->output->nbytes || conn->input->nbytes) {
        which = LCB_RW_EVENT;
    } else {
        which = LCB_READ_EVENT;
    }

    lcb_sockrw_set_want(conn, which, 1);
    event_complete_common(c, LCB_SUCCESS);
}

static void v1_error(lcb_sockdata_t *sockptr)
{
    lcb_server_t *c;

    if (!lcb_sockrw_v1_cb_common(sockptr, NULL, (void **)&c)) {
        return;
    }
    event_complete_common(c, LCB_NETWORK_ERROR);
}


static void v1_read(lcb_sockdata_t *sockptr, lcb_ssize_t nr)
{
    lcb_server_t *c;
    int rv;
    hrtime_t stop;

    if (!lcb_sockrw_v1_cb_common(sockptr, NULL, (void **)&c)) {
        return;
    }

    lcb_sockrw_v1_onread_common(sockptr, &c->connection.input, nr);

    c->inside_handler = 1;

    if (nr < 1) {
        event_complete_common(c, LCB_NETWORK_ERROR);
        return;
    }

    lcb_connection_delay_timer(&c->connection);

    stop = gethrtime();

    while ((rv = lcb_proto_parse_single(c, stop)) > 0) {
        /* do nothing */
    }

    if (rv >= 0) {
        /* Schedule the read request again */
        lcb_sockrw_set_want(&c->connection, LCB_READ_EVENT, 0);
    }
    event_complete_common(c, LCB_SUCCESS);
}

static void v1_write(lcb_sockdata_t *sockptr, lcb_io_writebuf_t *wbuf, int status)
{
    lcb_server_t *c;
    if (!lcb_sockrw_v1_cb_common(sockptr, wbuf, (void **)&c)) {
        return;
    }

    lcb_sockrw_v1_onwrite_common(sockptr, wbuf, &c->connection.output);

    c->inside_handler = 1;

    if (status) {
        event_complete_common(c, LCB_NETWORK_ERROR);
    } else {
        lcb_sockrw_set_want(&c->connection, LCB_READ_EVENT, 0);
        event_complete_common(c, LCB_SUCCESS);
    }
}

static void wire_io(lcb_server_t *server)
{
    lcb_connection_t conn = &server->connection;
    conn->evinfo.handler = v0_handler;
    conn->completion.read = v1_read;
    conn->completion.write = v1_write;
    conn->completion.error = v1_error;
}

LIBCOUCHBASE_API
void lcb_flush_buffers(lcb_t instance, const void *cookie)
{
    lcb_size_t ii;
    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t *c = instance->servers + ii;
        if (c->connection_ready) {
            v0_handler(c->connection.sockfd,
                                        LCB_READ_EVENT | LCB_WRITE_EVENT,
                                        c);
        }
    }
    (void)cookie;
}

int lcb_server_has_pending(lcb_server_t *server)
{
    lcb_connection_t conn = &server->connection;

    if ((conn->output && conn->output->nbytes) ||
            (conn->input && conn->input->nbytes)) {
        return 1;
    }

    if (server->cmd_log.nbytes || server->pending.nbytes) {
        return 1;
    }

    return 0;
}

int lcb_flushing_buffers(lcb_t instance)
{
    lcb_size_t ii;

    if (hashset_num_items(instance->http_requests)) {
        return 1;
    }
    for (ii = 0; ii < instance->nservers; ++ii) {
        if (lcb_server_has_pending(instance->servers + ii)) {
            return 1;
        }
    }
    return 0;
}


LCB_INTERNAL_API
void lcb_maybe_breakout(lcb_t instance)
{
    /**
     * So we're done with normal operations. See if we need a refresh
     */
    if (instance->wait) {
        if (!lcb_flushing_buffers(instance)
                && hashset_num_items(instance->timers) == 0
                && hashset_num_items(instance->durability_polls) == 0) {
            instance->wait = 0;
            instance->settings.io->v.v0.stop_event_loop(instance->settings.io);
        }
    }
}



struct nameinfo_common {
    char remote[NI_MAXHOST + NI_MAXSERV + 2];
    char local[NI_MAXHOST + NI_MAXSERV + 2];
};

static int saddr_to_string(struct sockaddr *saddr, int len,
                           char *buf, lcb_size_t nbuf)
{
    char h[NI_MAXHOST + 1];
    char p[NI_MAXSERV + 1];
    int rv;

    rv = getnameinfo(saddr, len, h, sizeof(h), p, sizeof(p),
                     NI_NUMERICHOST | NI_NUMERICSERV);
    if (rv < 0) {
        return 0;
    }

    if (snprintf(buf, nbuf, "%s;%s", h, p) < 0) {
        return 0;
    }

    return 1;
}

static int get_nameinfo(lcb_connection_t conn,
                        struct nameinfo_common *nistrs)
{
    struct sockaddr_storage sa_local;
    struct sockaddr_storage sa_remote;
    int n_salocal, n_saremote;
    struct lcb_nameinfo_st ni;
    int rv;

    n_salocal = sizeof(sa_local);
    n_saremote = sizeof(sa_remote);

    ni.local.name = (struct sockaddr *)&sa_local;
    ni.local.len = &n_salocal;

    ni.remote.name = (struct sockaddr *)&sa_remote;
    ni.remote.len = &n_saremote;

    if (conn->io->version == 1) {
        rv = conn->io->v.v1.get_nameinfo(conn->io, conn->sockptr, &ni);

        if (ni.local.len == 0 || ni.remote.len == 0 || rv < 0) {
            return 0;
        }

    } else {
        socklen_t sl_tmp = sizeof(sa_local);

        rv = getsockname(conn->sockfd, ni.local.name, &sl_tmp);
        n_salocal = sl_tmp;
        if (rv < 0) {
            return 0;
        }
        rv = getpeername(conn->sockfd, ni.remote.name, &sl_tmp);
        n_saremote = sl_tmp;
        if (rv < 0) {
            return 0;
        }
    }

    if (!saddr_to_string(ni.remote.name, *ni.remote.len,
                         nistrs->remote, sizeof(nistrs->remote))) {
        return 0;
    }

    if (!saddr_to_string(ni.local.name, *ni.local.len,
                         nistrs->local, sizeof(nistrs->local))) {
        return 0;
    }
    return 1;
}


static void connection_error(lcb_server_t *server, lcb_error_t err)
{
    lcb_failout_server(server, err);
    lcb_bootstrap_errcount_incr(server->instance);
}

static void negotiation_done(struct negotiation_context *ctx, lcb_error_t err)
{
    if (err != LCB_SUCCESS) {
        connection_error(ctx->server, err);
    } else {
        wire_io(ctx->server);
        lcb_connection_reset_buffers(&ctx->server->connection);
        lcb_server_connected(ctx->server);
    }
}


static void socket_connected(lcb_connection_t conn, lcb_error_t err)
{
    lcb_server_t *server = (lcb_server_t *)conn->data;
    int sasl_needed;

    if (err != LCB_SUCCESS) {
        connection_error(server, err);
        return;
    }

    server->inside_handler = 1;
    sasl_needed = vbucket_config_get_user(
            server->instance->vbucket_config) != NULL;

    if (sasl_needed) {
        struct nameinfo_common nistrs;
        if (!get_nameinfo(conn, &nistrs)) {
            /** This normally shouldn't happen! */
            connection_error(server, LCB_NETWORK_ERROR);
            return;
        }

        err = lcb_negotiation_init(server, nistrs.remote, nistrs.local,
                                   negotiation_done);
        if (err != LCB_SUCCESS) {
            connection_error(server, err);
        }

    } else {
        wire_io(server);
        lcb_server_connected(server);
        lcb_connection_cancel_timer(conn);
        lcb_sockrw_apply_want(conn);
    }

    server->inside_handler = 0;
}

static void server_timeout_handler(lcb_connection_t conn, lcb_error_t err)
{
    lcb_server_t *server = (lcb_server_t *)conn->data;
    LOG(server, ERR, "Server timed out");
    lcb_timeout_server(server);
    lcb_bootstrap_errcount_incr(server->instance);
    lcb_maybe_breakout(server->instance);
    (void)err;
}

/**
 * Schedule a connection to the server
 */
void lcb_server_connect(lcb_server_t *server)
{
    lcb_connection_t conn = &server->connection;

    conn->on_connect_complete = socket_connected;
    conn->on_timeout = server_timeout_handler;
    conn->timeout.usec = server->instance->settings.operation_timeout;

    if (lcb_connection_reset_buffers(&server->connection) != LCB_SUCCESS) {
        lcb_error_handler(server->instance, LCB_CLIENT_ENOMEM, NULL);
    }

    lcb_connection_start(conn, LCB_CONNSTART_NOCB | LCB_CONNSTART_ASYNCERR);
}
