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

static int do_read_data(lcb_server_t *c, int allow_read)
{
    /*
    ** Loop and try to parse the data... We don't want to lock up the
    ** event loop completely, so set a max number of packets to process
    ** before backing off..
    */
    lcb_size_t processed = 0;
    /* @todo Make the backoff number tunable from the instance */
    const lcb_size_t operations_per_call = 1000;
    int rv = 0;
    /*
    ** The timers isn't supposed to be _that_ accurate.. it's better
    ** to shave off system calls :)
    */
    hrtime_t stop = gethrtime();

    while (processed < operations_per_call) {
        rv = lcb_proto_parse_single(c, stop);
        if (rv == -1) {
            return -1;

        } else if (rv == 0 && allow_read) {
            /* need more data */
            lcb_sockrw_status_t status;

            status = lcb_sockrw_read(&c->connection, c->connection.input);

            switch (status) {

            case LCB_SOCKRW_READ:
                lcb_update_server_timer(c);
                break;

            case LCB_SOCKRW_WOULDBLOCK:
                processed = operations_per_call + 1;
                break;

            case LCB_SOCKRW_IO_ERROR:
                if (c->instance->compat.type == LCB_CACHED_CONFIG) {
                    lcb_schedule_config_cache_refresh(c->instance);
                    processed = operations_per_call + 1;
                    break;
                }

                lcb_failout_server(c, LCB_NETWORK_ERROR);
                return -1;

            default:
                return -1;

            } /* switch (status) */

            break;

        } else {
            ++processed;
        }
    }

    return 0;
}

static void event_complete_common(lcb_server_t *c)
{
    if (c->instance->compat.type == LCB_CACHED_CONFIG &&
            c->instance->compat.value.cached.needs_update) {
        lcb_refresh_config_cache(c->instance);
    }

    lcb_sockrw_apply_want(&c->connection);

    lcb_maybe_breakout(c->instance);

    /* Make it known that this was a success. */
    lcb_error_handler(c->instance, LCB_SUCCESS, NULL);
}



void lcb_server_event_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_server_t *c = arg;
    lcb_connection_t conn = &c->connection;
    (void)sock;

    if (which & LCB_WRITE_EVENT) {
        lcb_sockrw_status_t status;

        status = lcb_sockrw_write(conn, conn->output);
        if (status != LCB_SOCKRW_WROTE && status != LCB_SOCKRW_WOULDBLOCK) {
            event_complete_common(c);
            return;
        }
    }

    if (which & LCB_READ_EVENT || conn->input->nbytes) {
        if (do_read_data(c, which & LCB_READ_EVENT) != 0) {
            /* TODO stash error message somewhere
             * "Failed to read from connection to \"%s:%s\"", c->hostname, c->port */
            lcb_failout_server(c, LCB_NETWORK_ERROR);
            event_complete_common(c);
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
    event_complete_common(c);
}

LIBCOUCHBASE_API
void lcb_flush_buffers(lcb_t instance, const void *cookie)
{
    lcb_size_t ii;
    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t *c = instance->servers + ii;
        if (c->connection_ready) {
            lcb_server_event_handler(c->connection.sockfd,
                                     LCB_READ_EVENT | LCB_WRITE_EVENT,
                                     c);
        }
    }
    (void)cookie;
}

int lcb_flushing_buffers(lcb_t instance)
{
    lcb_size_t ii;

    if (hashset_num_items(instance->http_requests)) {
        return 1;
    }
    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t *c = instance->servers + ii;
        lcb_connection_t conn = &c->connection;

        if (c->cmd_log.nbytes ||
                c->pending.nbytes ||
                hashset_num_items(c->http_requests)) {
            return 1;
        }

        if (!lcb_sockrw_flushed(conn)) {
            return 1;
        }

    }
    return 0;
}


void lcb_maybe_breakout(lcb_t instance)
{
    /**
     * So we're done with normal operations. See if we need a refresh
     */
    if (instance->wait) {
        if (!lcb_flushing_buffers(instance)
                && hashset_num_items(instance->timers) == 0) {
            instance->wait = 0;
            instance->io->v.v0.stop_event_loop(instance->io);
        }
    }
}
