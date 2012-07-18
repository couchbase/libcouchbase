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

static void timer_callback(libcouchbase_socket_t sock,
                           short which,
                           void *arg)
{
    libcouchbase_timer_t timer = arg;
    libcouchbase_t instance = timer->instance;
    timer->callback(timer, instance, timer->cookie);
    if (hashset_is_member(instance->timers, timer) && !timer->periodic) {
        instance->io->delete_timer(instance->io, timer->event);
        libcouchbase_timer_destroy(instance, timer);
    }
    libcouchbase_maybe_breakout(timer->instance);

    (void)sock;
    (void)which;
}

LIBCOUCHBASE_API
libcouchbase_timer_t libcouchbase_timer_create(libcouchbase_t instance,
                                               const void *command_cookie,
                                               libcouchbase_uint32_t usec,
                                               int periodic,
                                               libcouchbase_timer_callback callback,
                                               libcouchbase_error_t *error)

{
    libcouchbase_timer_t tmr = calloc(1, sizeof(struct libcouchbase_timer_st));
    if (!tmr) {
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_CLIENT_ENOMEM);
        return NULL;
    }
    if (!callback) {
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_EINVAL);
        return NULL;
    }

    tmr->instance = instance;
    tmr->callback = callback;
    tmr->cookie = command_cookie;
    tmr->usec = usec;
    tmr->periodic = periodic;
    tmr->event = instance->io->create_timer(instance->io);
    if (tmr->event == NULL) {
        free(tmr);
        *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_CLIENT_ENOMEM);
        return NULL;
    }
    instance->io->update_timer(instance->io, tmr->event, tmr->usec,
                               tmr, timer_callback);


    hashset_add(instance->timers, tmr);
    *error = libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
    return tmr;
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_timer_destroy(libcouchbase_t instance,
                                                libcouchbase_timer_t timer)
{
    if (hashset_is_member(instance->timers, timer)) {
        hashset_remove(instance->timers, timer);
        instance->io->delete_timer(instance->io, timer->event);
        instance->io->destroy_timer(instance->io, timer->event);
        free(timer);
    }
    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}
