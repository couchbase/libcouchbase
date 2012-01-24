/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012 Couchbase, Inc.
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

LIBCOUCHBASE_API
void libcouchbase_set_timeout(libcouchbase_t instance, uint32_t usec)
{
    instance->timeout.usec = usec;
    libcouchbase_update_timer(instance);
}

LIBCOUCHBASE_API
uint32_t libcouchbase_get_timeout(libcouchbase_t instance)
{
    return instance->timeout.usec;
}

static void libcouchbase_timeout_handler(evutil_socket_t sock,
                                         short which,
                                         void *arg)
{
    libcouchbase_t instance = arg;
    /* Remove the timer */
    instance->io->delete_timer(instance->io, instance->timeout.event);
    instance->timeout.next = 0;
    libcouchbase_purge_timedout(instance);
    libcouchbase_update_timer(instance);

    libcouchbase_maybe_breakout(instance);

    (void)sock;
    (void)which;
}

void libcouchbase_update_timer(libcouchbase_t instance)
{
    /* Run through all of the server instances and figure out the first */
    /* operation there. */
    hrtime_t next = 0;
    size_t idx;

    for (idx = 0; idx < instance->nservers; ++idx) {
        libcouchbase_server_t *server = instance->servers + (size_t)idx;

        if (next == 0) {
            next = server->next_timeout;
        } else if (server->next_timeout < next) {
            next = server->next_timeout;
        }
    }

    if (next != instance->timeout.next) {
        if (next == 0) {
            instance->io->delete_timer(instance->io,
                                       instance->timeout.event);
        } else {
            /* update the timer */
            instance->io->update_timer(instance->io,
                                       instance->timeout.event,
                                       instance->timeout.usec,
                                       instance,
                                       libcouchbase_timeout_handler);
            instance->timeout.next = next;
        }
    }
}

void libcouchbase_purge_timedout(libcouchbase_t instance)
{
    hrtime_t now = gethrtime();
    size_t idx;
    hrtime_t tmo = instance->timeout.usec;
    tmo *= 1000;

    for (idx = 0; idx < instance->nservers; ++idx) {
        libcouchbase_server_t *server = instance->servers + (size_t)idx;
        if (server->next_timeout != 0 && (now > (tmo + server->next_timeout))) {
            if (server->connected) {
                libcouchbase_purge_single_server(server,
                                                 &server->cmd_log,
                                                 &server->output_cookies,
                                                 tmo, now,
                                                 LIBCOUCHBASE_ETIMEDOUT);
            } else {
                libcouchbase_purge_single_server(server,
                                                 &server->pending,
                                                 &server->pending_cookies,
                                                 tmo, now,
                                                 LIBCOUCHBASE_ETIMEDOUT);
            }
        }
    }
}
