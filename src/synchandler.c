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

struct user_cookie {
    void *cookie;
    libcouchbase_error_callback error;
    libcouchbase_error_t retcode;
};


static void error_callback(libcouchbase_t instance,
                           libcouchbase_error_t error,
                           const char *errinfo)
{
    struct user_cookie *cookie = (void*)instance->cookie;
    if (error == LIBCOUCHBASE_SUCCESS) {
        return ;
    }

    /* Restore the users environment */
    instance->cookie = cookie->cookie;
    instance->callbacks.error = cookie->error;

    /* Call the user's callback */
    cookie->error(instance, error, errinfo);

    /* Restore the wrapping environment */
    cookie->error = instance->callbacks.error; /* User might have changed this */
    instance->cookie = cookie;

    /* Save the error code */
    cookie->retcode = error;

    /* Ok, stop the event loop */
    instance->io->stop_event_loop(instance->io);
}

libcouchbase_error_t libcouchbase_synchandler_return(libcouchbase_t instance, libcouchbase_error_t retcode)
{
    struct user_cookie cookie;

    if (instance->syncmode == LIBCOUCHBASE_ASYNCHRONOUS ||
        retcode != LIBCOUCHBASE_SUCCESS) {
        return retcode;
    }

    cookie.retcode = LIBCOUCHBASE_SUCCESS;

    /* Save the users environment */
    cookie.error = instance->callbacks.error;
    cookie.cookie = (void*)instance->cookie;
    instance->cookie = &cookie;
    instance->callbacks.error = error_callback;

    libcouchbase_wait(instance);
    /* Restore the environment */
    instance->callbacks.error = cookie.error;
    instance->cookie = cookie.cookie;

    return cookie.retcode;
}
