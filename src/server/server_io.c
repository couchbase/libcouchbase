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

            status = lcb_sockrw_read(&c->connection, &c->input);

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

static void event_complete_common(lcb_t instance)
{
    if (instance->compat.type == LCB_CACHED_CONFIG &&
            instance->compat.value.cached.needs_update) {
        lcb_refresh_config_cache(instance);
    }

    lcb_maybe_breakout(instance);

    /* Make it known that this was a success. */
    lcb_error_handler(instance, LCB_SUCCESS, NULL);
}



void lcb_server_event_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_server_t *c = arg;
    lcb_t instance = c->instance;
    (void)sock;

    if (which & LCB_WRITE_EVENT) {
        lcb_sockrw_status_t status;
        status = lcb_sockrw_write(&c->connection, &c->output);
        if (status != LCB_SOCKRW_WROTE && status != LCB_SOCKRW_WOULDBLOCK) {
            event_complete_common(instance);
            return;
        }
    }

    if (which & LCB_READ_EVENT || c->input.nbytes) {
        if (do_read_data(c, which & LCB_READ_EVENT) != 0) {
            /* TODO stash error message somewhere
             * "Failed to read from connection to \"%s:%s\"", c->hostname, c->port */
            lcb_failout_server(c, LCB_NETWORK_ERROR);
            event_complete_common(instance);
            return;
        }
    }

    which = LCB_READ_EVENT;
    if (c->output.nbytes || c->input.nbytes) {
        /**
         * If we have data in the read buffer, we need to make sure the event
         * still gets delivered despite nothing being in the actual TCP read
         * buffer. Since writes will typically not block, we hinge the next
         * read operation on write-ability
         */
        which |= LCB_WRITE_EVENT;
    }

    lcb_server_io_start(c, which);
    event_complete_common(instance);

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

int lcb_has_data_in_buffers(lcb_t instance)
{
    lcb_size_t ii;

    if (hashset_num_items(instance->http_requests)) {
        return 1;
    }
    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t *c = instance->servers + ii;
        if (c->cmd_log.nbytes || c->output.nbytes || c->input.nbytes ||
                c->pending.nbytes || hashset_num_items(c->http_requests)) {
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
        if (!lcb_has_data_in_buffers(instance)
                && hashset_num_items(instance->timers) == 0) {
            instance->wait = 0;
            instance->io->v.v0.stop_event_loop(instance->io);
        }
    }
}
