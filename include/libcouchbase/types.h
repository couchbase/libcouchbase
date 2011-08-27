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

    struct libcouchbase_callback_st;
    typedef struct libcouchbase_callback_st* libcouchbase_callback_t;

    /**
     * Define the error codes in use by the library
     */
    typedef enum {
        LIBCOUCHBASE_SUCCESS = 0x00,
        LIBCOUCHBASE_AUTH_CONTINUE = 0x01,
        LIBCOUCHBASE_AUTH_ERROR = 0x02,
        LIBCOUCHBASE_DELTA_BADVAL = 0x03,
        LIBCOUCHBASE_E2BIG = 0x04,
        LIBCOUCHBASE_EBUSY = 0x05,
        LIBCOUCHBASE_EINTERNAL = 0x06,
        LIBCOUCHBASE_EINVAL = 0x07,
        LIBCOUCHBASE_ENOMEM = 0x08,
        LIBCOUCHBASE_ERANGE = 0x09,
        LIBCOUCHBASE_ERROR = 0x0a,
        LIBCOUCHBASE_ETMPFAIL = 0x0b,
        LIBCOUCHBASE_KEY_EEXISTS = 0x0c,
        LIBCOUCHBASE_KEY_ENOENT = 0x0d,
        LIBCOUCHBASE_LIBEVENT_ERROR = 0x0e,
        LIBCOUCHBASE_NETWORK_ERROR = 0x0f,
        LIBCOUCHBASE_NOT_MY_VBUCKET = 0x10,
        LIBCOUCHBASE_NOT_STORED = 0x11,
        LIBCOUCHBASE_NOT_SUPPORTED = 0x12,
        LIBCOUCHBASE_UNKNOWN_COMMAND = 0x13,
        LIBCOUCHBASE_UNKNOWN_HOST = 0x14
    } libcouchbase_error_t;

    /**
     * Storing an item in couchbase is only one operation with a different
     * set of attributes / constraints.
     */
    typedef enum {
        /** Add the item to the cache, but fail if the object exists alread */
        LIBCOUCHBASE_ADD = 0x01,
        /** Replace the existing object in the cache */
        LIBCOUCHBASE_REPLACE = 0x02,
        /** Unconditionally set the object in the cache */
        LIBCOUCHBASE_SET = 0x03,
        /** Append this object to the existing object */
        LIBCOUCHBASE_APPEND = 0x04,
        /** Prepend this  object to the existing object */
        LIBCOUCHBASE_PREPEND = 0x05
    } libcouchbase_storage_t;

    struct  libcouchbase_tap_filter_st;
    typedef struct libcouchbase_tap_filter_st* libcouchbase_tap_filter_t;

    typedef bool (*libcouchbase_packet_filter_t)(libcouchbase_t instance,
                                                 const void *packet);

#ifdef __cplusplus
}
#endif

#endif
