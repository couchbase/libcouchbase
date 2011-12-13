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

/**
 * Definition of functions used to set up the tap filter
 */
#ifndef LIBCOUCHBASE_TAP_FILTER_H
#define LIBCOUCHBASE_TAP_FILTER_H 1

#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "Include libcouchbase/couchbase.h instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Create an instance of a libcouchbase tap filter (libcouchbase_tap_filter_t).
     */
    LIBCOUCHBASE_API
    libcouchbase_tap_filter_t libcouchbase_tap_filter_create(void);

    /**
     * Destroy (and release all allocated resources) an instance of a libcouchbase
     * tap filter (libcouchbase_tap_filter_t). Using the instance after calling
     * destroy will most likely cause your application to crash.
     * @param instance the instance to destroy.
     */
    LIBCOUCHBASE_API
    void libcouchbase_tap_filter_destroy(libcouchbase_tap_filter_t instance);

    /**
     * Set the backfill value for your tap stream.
     * @param instance the tap filter instance to modify.
     * @param backfill the oldest entry (from epoch) you're interested in.
     */
    LIBCOUCHBASE_API
    void libcouchbase_tap_filter_set_backfill(libcouchbase_tap_filter_t instance,
                                              uint64_t backfill);

    /**
     * Get the backfill value for your tap stream.
     * @param instance the tap filter instance to retrieve the value from.
     */
    LIBCOUCHBASE_API
    uint64_t libcouchbase_tap_filter_get_backfill(libcouchbase_tap_filter_t instance);

    /**
     * Set whether you are interested in keys and values, or only keys in your
     * tap stream.
     * @param instance the tap filter instance to modify.
     * @param keys_only true if you are only interested in keys, false if
     *                  you also want values.
     */
    LIBCOUCHBASE_API
    void libcouchbase_tap_filter_set_keys_only(libcouchbase_tap_filter_t instance,
                                               int keys_only);

    /**
     * Get whether you are interested in keys and values, or only keys in your
     * tap stream.
     * @param instance the tap filter instance to retrieve the value from.
     */
    LIBCOUCHBASE_API
    int libcouchbase_tap_filter_get_keys_only(libcouchbase_tap_filter_t instance);

#ifdef __cplusplus
}
#endif

#endif
