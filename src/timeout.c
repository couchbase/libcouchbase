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
void lcb_set_timeout(lcb_t instance, lcb_uint32_t usec)
{
    instance->timeout.usec = usec;
}

LIBCOUCHBASE_API
lcb_uint32_t lcb_get_timeout(lcb_t instance)
{
    return instance->timeout.usec;
}

static void lcb_server_timeout_handler(lcb_socket_t sock,
                                       short which,
                                       void *arg)
{
    lcb_server_t *server = arg;

    lcb_purge_single_server(server, LCB_ETIMEDOUT);
    lcb_update_server_timer(server);
    lcb_maybe_breakout(server->instance);

    (void)sock;
    (void)which;
}

void lcb_update_server_timer(lcb_server_t *server)
{
    lcb_t instance = server->instance;

    if (server->timer) {
        instance->io->delete_timer(instance->io, server->timer);
    }
    instance->io->update_timer(instance->io, server->timer,
                               instance->timeout.usec, server,
                               lcb_server_timeout_handler);
}
