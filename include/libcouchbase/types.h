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
 * Public types and datatypes exported through the libcouchbase API.
 * Please note that libcouchbase should be binary compatible across versions
 * so remember to update the library version numbers if you change any
 * of the values.
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_TYPES_H
#define LIBCOUCHBASE_TYPES_H 1

#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "Include libcouchbase/couchbase.h instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Clients of the library should not know the size or the internal
     * layout of the per instance handle. Sharing knowledge about the
     * internal layout makes it a lot harder to keep binary compatibility
     * (if people tries to use it's size etc).
     */
    struct libcouchbase_st;
    typedef struct libcouchbase_st* libcouchbase_t;

    /**
     * Define the error codes in use by the library
     */
    typedef enum {
        LIBCOUCHBASE_SUCCESS,
        LIBCOUCHBASE_ENOMEM,
        LIBCOUCHBASE_E2BIG,
        LIBCOUCHBASE_UNKNOWN_HOST,
        LIBCOUCHBASE_NETWORK_ERROR,
        LIBCOUCHBASE_LIBEVENT_ERROR,
        LIBCOUCHBASE_KEY_ENOENT,
        LIBCOUCHBASE_ERROR
    } libcouchbase_error_t;

    /**
     * Storing an item in couchbase is only one operation with a different
     * set of attributes / constraints.
     */
    typedef enum {
        /** Add the item to the cache, but fail if the object exists alread */
        LIBCOUCHBASE_ADD,
        /** Replace the existing object in the cache */
        LIBCOUCHBASE_REPLACE,
        /** Unconditionally set the object in the cache */
        LIBCOUCHBASE_SET,
        /** Append this object to the existing object */
        LIBCOUCHBASE_APPEND,
        /** Prepend this  object to the existing object */
        LIBCOUCHBASE_PREPEND
    } libcouchbase_storage_t;

    /**
     * We might want to tap just a subset of the bucket. Right now
     * it's not supported...
     * @todo come up with how I want the filters to look like
     */
    typedef void* libcouchbase_tap_filter_t;

    typedef bool (*libcouchbase_packet_filter_t)(libcouchbase_t instance,
                                                 const void *packet);


#ifdef __cplusplus
}
#endif

#endif
