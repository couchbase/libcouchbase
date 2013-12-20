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

enum {
    TIMER_S_ENTERED = 1,
    TIMER_S_DESTROYED = 2
};


static void destroy_timer(lcb_timer_t timer)
{
    timer->io->v.v0.destroy_timer(timer->io, timer->event);
    free(timer);
}

static void timer_callback(lcb_socket_t sock, short which, void *arg)
{
    lcb_timer_t timer = arg;
    lcb_t instance = timer->instance;
    timer->state = TIMER_S_ENTERED;

    timer->callback(timer, instance, timer->cookie);

    if (! (timer->options & LCB_TIMER_PERIODIC)) {
        timer->io->v.v0.delete_timer(timer->io, timer->event);

    } else if (! (timer->state & TIMER_S_DESTROYED)) {
        timer->io->v.v0.update_timer(timer->io, timer->event,
                                     timer->usec, timer, timer_callback);
        return;
    }

    if ( (timer->options & LCB_TIMER_STANDALONE) == 0) {
        if (hashset_is_member(instance->timers, timer)) {
            hashset_remove(instance->timers, timer);
        }
        lcb_maybe_breakout(instance);
    }

    if (timer->state & TIMER_S_DESTROYED) {
        destroy_timer(timer);
    } else {
        timer->state = 0;
    }

    (void)sock;
    (void)which;
}

LIBCOUCHBASE_API
lcb_timer_t lcb_timer_create(lcb_t instance,
                             const void *command_cookie,
                             lcb_uint32_t usec,
                             int periodic,
                             lcb_timer_callback callback,
                             lcb_error_t *error)

{
    return lcb_timer_create2(instance->io,
                             command_cookie,
                             usec,
                             periodic ? LCB_TIMER_PERIODIC : 0,
                             callback,
                             instance,
                             error);
}

LCB_INTERNAL_API
lcb_async_t lcb_async_create(lcb_io_opt_t io,
                             const void *command_cookie,
                             lcb_timer_callback callback,
                             lcb_error_t *error)
{
    return lcb_timer_create2(io,
                             command_cookie, 0,
                             LCB_TIMER_STANDALONE,
                             callback,
                             NULL,
                             error);
}

lcb_timer_t lcb_timer_create_simple(lcb_io_opt_t io,
                                    const void *cookie,
                                    lcb_uint32_t usec,
                                    lcb_timer_callback callback)
{
    lcb_error_t err;
    lcb_timer_t ret;
    ret = lcb_timer_create2(io,
                            cookie,
                            usec,
                            LCB_TIMER_STANDALONE, callback, NULL, &err);
    if (err != LCB_SUCCESS) {
        return NULL;
    }
    return ret;
}

LCB_INTERNAL_API
lcb_timer_t lcb_timer_create2(lcb_io_opt_t io,
                              const void *cookie,
                              lcb_uint32_t usec,
                              lcb_timer_options options,
                              lcb_timer_callback callback,
                              lcb_t instance,
                              lcb_error_t *error)
{
    lcb_timer_t tmr = calloc(1, sizeof(struct lcb_timer_st));
    tmr->io = io;

    if (!tmr) {
        *error = LCB_CLIENT_ENOMEM;
        return NULL;
    }
    if (!callback) {
        *error = LCB_EINVAL;
        return NULL;
    }

    if (! (options & LCB_TIMER_STANDALONE)) {
        lcb_assert(instance);
    }

    tmr->instance = instance;
    tmr->callback = callback;
    tmr->cookie = cookie;
    tmr->usec = usec;
    tmr->options = options;

    tmr->event = io->v.v0.create_timer(io);

    if (tmr->event == NULL) {
        free(tmr);
        *error = LCB_CLIENT_ENOMEM;
        return NULL;
    }

    io->v.v0.update_timer(io, tmr->event, tmr->usec, tmr, timer_callback);

    if ( (options & LCB_TIMER_STANDALONE) == 0) {
        hashset_add(instance->timers, tmr);
    }

    *error = LCB_SUCCESS;
    return tmr;
}

LIBCOUCHBASE_API
lcb_error_t lcb_timer_destroy(lcb_t instance, lcb_timer_t timer)
{
    lcb_io_opt_t io = timer->io;
    int standalone = timer->options & LCB_TIMER_STANDALONE;

    if (standalone == 0 && hashset_is_member(instance->timers, timer)) {
        hashset_remove(instance->timers, timer);
    }

    io->v.v0.delete_timer(io, timer->event);

    if (timer->state & TIMER_S_ENTERED) {
        timer->state |= TIMER_S_DESTROYED;
    } else {
        destroy_timer(timer);
    }
    if (!standalone) {
        return lcb_synchandler_return(instance, LCB_SUCCESS);
    } else {
        return LCB_SUCCESS;
    }
}
