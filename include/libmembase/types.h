/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Membase, Inc.
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
 * Public types and datatypes exported through the libmembase API.
 * Please note that libmembase should be binary compatible across versions
 * so remember to update the library version numbers if you change any
 * of the values.
 *
 * @author Trond Norbye
 */
#ifndef LIBMEMBASE_TYPES_H
#define LIBMEMBASE_TYPES_H 1

#ifndef LIBMEMBASE_MEMBASE_H
#error "Include libmembase/membase.h instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Clients of the library should not know the size or the internal
     * layout of the per instance handle. Sharing knowledge about the
     * internal layout makes it a lot harder to keep binary compatibility
     * (if people tries to use it's sice etc).
     */
#ifdef LIBMEMBASE_INTERNAL
    struct libmembase_st;
    typedef struct libmembase_st* libmembase_t;
#else
    typedef void* libmembase_t;
#endif

    /**
     * Define the error codes in use by the library
     */
    typedef enum {
        LIBMEMBASE_SUCCESS,
        LIBMEMBASE_ENOMEM,
        LIBMEMBASE_E2BIG,
        LIBMEMBASE_UNKNOWN_HOST,
        LIBMEMBASE_NETWORK_ERROR,
        LIBMEMBASE_LIBEVENT_ERROR,
        LIBMEMBASE_KEY_ENOENT,
        LIBMEMBASE_ERROR
    } libmembase_error_t;

    /**
     * Storing an item in membase is only one operation with a different
     * set of attributes / constraints.
     */
    typedef enum {
        /** Add the item to the cache, but fail if the object exists alread */
        LIBMEMBASE_ADD,
        /** Replace the existing object in the cache */
        LIBMEMBASE_REPLACE,
        /** Unconditionally set the object in the cache */
        LIBMEMBASE_SET,
        /** Append this object to the existing object */
        LIBMEMBASE_APPEND,
        /** Prepend this  object to the existing object */
        LIBMEMBASE_PREPEND
    } libmembase_storage_t;

    /**
     * We might want to tap just a subset of the bucket. Right now
     * it's not supported...
     * @todo come up with how I want the filters to look like
     */
    typedef void* libmembase_tap_filter_t;

    typedef bool (*libmembase_packet_filter_t)(libmembase_t instance,
                                               const void *packet);


#ifdef __cplusplus
}
#endif

#endif
