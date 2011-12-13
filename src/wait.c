/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc.
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

static void breakout_vbucket_state_listener(libcouchbase_server_t *server)
{
    server->instance->io->stop_event_loop(server->instance->io);
}

/**
 * Run the event loop until we've got a response for all of our spooled
 * commands. You should not call this function from within your callbacks.
 *
 * @param instance the instance to run the event loop for.
 *
 * @author Trond Norbye
 */
LIBCOUCHBASE_API
void libcouchbase_wait(libcouchbase_t instance)
{
    /*
     * The API is designed for you to run your own event loop,
     * but should also work if you don't do that.. In order to be
     * able to know when to break out of the event loop, we're setting
     * the wait flag to 1
     */
    instance->wait = 1;
    if (instance->vbucket_config == NULL) {
        vbucket_state_listener_t old = instance->vbucket_state_listener;
        instance->vbucket_state_listener = breakout_vbucket_state_listener;
        instance->io->run_event_loop(instance->io);
        instance->vbucket_state_listener = old;
    } else {
        instance->io->run_event_loop(instance->io);
    }
    instance->wait = 0;
}
