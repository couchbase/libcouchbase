/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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

/**
 * Project-wide error handling.
 *
 * @author William Bowers
 */

/**
 * Returns the last error that was seen within libcoubhase.
 *
 * @param instance the connection whose last error should be returned.
 */
LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_get_last_error(libcouchbase_t instance)
{
    return instance->last_error;
}

/**
 * Called when an error occurs.
 *
 * This returns the error it was given so you can return it from a function
 * in 1 line:
 *
 *     return libcouchbase_error_handler(instance, LIBCOUCHBASE_ERROR);
 *
 * rather than 3:
 *
 *     libcouchbase_error_t error = LIBCOUCHBASE_ERROR;
 *     libcouchbase_error_handler(instance, error);
 *     return error;
 *
 * @param instance the connection the error occurred on.
 * @param error the error that occurred.
 * @return the error that occurred.
 */
libcouchbase_error_t libcouchbase_error_handler(libcouchbase_t instance, libcouchbase_error_t error, const char *errinfo)
{
    // Set the last error value so it can be access without needing an error callback.
    instance->last_error = error;

    // TODO: Should we call the callback anyway, even if it's a SUCCESS?
    if (error != LIBCOUCHBASE_SUCCESS) {
        // Call the user's error callback.
        instance->callbacks.error(instance, error, errinfo);
    }

    return error;
}
