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

/**
 * This file contains definitions of all of the command and response
 * structures. It is a "versioned" struct, so that we may change it
 * without breaking binary compatibility. You as a user must specify
 * the version field when you create command, and you <b>must</b>
 * check the version field to figure out the layout when you want
 * to access the fields.
 */

#ifndef LIBCOUCHBASE_ARGUMENTS_H
#define LIBCOUCHBASE_ARGUMENTS_H 1

#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "Include libcouchbase/couchbase.h instead"
#endif


#ifdef __cplusplus
#include <cstring>
extern "C" {
#endif

    typedef struct lcb_get_cmd_st {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                lcb_time_t exptime;
            } v0;
        } v;
#ifdef __cplusplus
        lcb_get_cmd_st() {
            std::memset(this, 0, sizeof(*this));
        }

        lcb_get_cmd_st(const void *key,
                       lcb_size_t nkey = 0,
                       lcb_time_t exptime = 0) {
            version = 0;
            v.v0.key = key;
            if (key != NULL && nkey == 0) {
                v.v0.nkey = std::strlen((const char*)key);
            } else {
                v.v0.nkey = nkey;
            }
            v.v0.exptime = exptime;
        }
#endif
    } lcb_get_cmd_t;

    typedef struct lcb_get_replica_cmd_st {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
            } v0;
        } v;
#ifdef __cplusplus
        lcb_get_replica_cmd_st() {
            std::memset(this, 0, sizeof(*this));
        }

        lcb_get_replica_cmd_st(const void *key, lcb_size_t nkey) {
            version = 0;
            v.v0.key = key;
            v.v0.nkey = nkey;
        }
#endif
     } lcb_get_replica_cmd_t;

    /**
     * Get locked use the same structure as get (the exptime is the
     * lock expiration time
     */
    typedef lcb_get_cmd_t lcb_get_locked_cmd_t;

    typedef struct lcb_unlock_cmd_st {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                lcb_cas_t cas;
            } v0;
        } v;
#ifdef __cplusplus
        lcb_unlock_cmd_st() {
            std::memset(this, 0, sizeof(*this));
        }

        lcb_unlock_cmd_st(const void *key, lcb_size_t nkey, lcb_cas_t cas) {
            version = 0;
            v.v0.key = key;
            v.v0.nkey = nkey;
            v.v0.cas = cas;
        }
#endif
    } lcb_unlock_cmd_t;

    /**
     * Touch use the same sturcture as get
     */
    typedef lcb_get_cmd_t lcb_touch_cmd_t;

    typedef struct lcb_store_cmd_st {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                const void *bytes;
                lcb_size_t nbytes;
                lcb_uint32_t flags;
                lcb_cas_t cas;
                lcb_datatype_t datatype;
                lcb_time_t exptime;
                lcb_storage_t operation;
            } v0;
        } v;
#ifdef __cplusplus
        lcb_store_cmd_st() {
            std::memset(this, 0, sizeof(*this));
        }

        lcb_store_cmd_st(lcb_storage_t operation,
                         const void *key,
                         lcb_size_t nkey,
                         const void *bytes = NULL,
                         lcb_size_t nbytes = 0,
                         lcb_uint32_t flags = 0,
                         lcb_time_t exptime = 0,
                         lcb_cas_t cas = 0,
                         lcb_datatype_t datatype = 0) {
            version = 0;
            v.v0.operation = operation;
            v.v0.key = key;
            v.v0.nkey = nkey;
            v.v0.cas = cas;
            v.v0.bytes = bytes;
            v.v0.nbytes = nbytes;
            v.v0.flags = flags;
            v.v0.datatype = datatype;
            v.v0.exptime = exptime;
        }
#endif
    } lcb_store_cmd_t;

    typedef struct lcb_arithmetic_cmd_st {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                lcb_time_t exptime;
                int create;
                lcb_int64_t delta;
                lcb_uint64_t initial;
            } v0;
        } v;

#ifdef __cplusplus
        lcb_arithmetic_cmd_st() {
            std::memset(this, 0, sizeof(*this));
        }

        lcb_arithmetic_cmd_st(const void *key,
                              lcb_size_t nkey,
                              lcb_int64_t delta,
                              int create = 0,
                              lcb_uint64_t initial = 0,
                              lcb_time_t exptime = 0) {
            version = 0;
            v.v0.key = key;
            v.v0.nkey = nkey;
            v.v0.exptime = exptime;
            v.v0.delta = delta;
            v.v0.create = create;
            v.v0.initial = initial;
        }
#endif
    } lcb_arithmetic_cmd_t;

    typedef struct lcb_observe_cmd_st {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
            } v0;
        } v;
#ifdef __cplusplus
        lcb_observe_cmd_st() {
            std::memset(this, 0, sizeof(*this));
        }

        lcb_observe_cmd_st(const void *key, lcb_size_t nkey) {
            version = 0;
            v.v0.key = key;
            v.v0.nkey = nkey;
        }
#endif
    } lcb_observe_cmd_t;

    typedef struct lcb_remove_cmd_st {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                lcb_cas_t cas;
            } v0;
        } v;
#ifdef __cplusplus
        lcb_remove_cmd_st() {
            std::memset(this, 0, sizeof(*this));
        }

        lcb_remove_cmd_st(const void *key, lcb_size_t nkey, lcb_cas_t cas) {
            version = 0;
            v.v0.key = key;
            v.v0.nkey = nkey;
            v.v0.cas = cas;
        }
#endif
    } lcb_remove_cmd_t;

    typedef struct lcb_http_cmd_st {
        int version;
        union {
            struct {
                /* A view path string with optional query params
                   (e.g. skip, limit etc.) */
                const char *path;
                lcb_size_t npath;
                /* The POST body for HTTP request */
                const void *body;
                lcb_size_t nbody;
                /* HTTP message type to be sent to server */
                lcb_http_method_t method;
                /* If true the client will use lcb_http_data_callback to
                 * notify about response and will call lcb_http_complete
                 * with empty data eventually. */
                int chunked;
                /* The 'Content-Type' header for request. For view requests
                 * it is usually "application/json", for management --
                 * "application/x-www-form-urlencoded". */
                const char *content_type;
            } v0;
        } v;
#ifdef __cplusplus
        lcb_http_cmd_st() {
            std::memset(this, 0, sizeof(*this));
        }

        lcb_http_cmd_st(const char *path, lcb_size_t npath, const void *body,
                        lcb_size_t nbody, lcb_http_method_t method,
                        int chunked, const char *content_type) {
            version = 0;
            v.v0.path = path;
            v.v0.npath = npath;
            v.v0.body = body;
            v.v0.nbody = nbody;
            v.v0.method = method;
            v.v0.chunked = chunked;
            v.v0.content_type = content_type;
        }
#endif
    } lcb_http_cmd_t;

    typedef struct {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                const void *bytes;
                lcb_size_t nbytes;
                lcb_uint32_t flags;
                lcb_cas_t cas;
                lcb_datatype_t datatype;
            } v0;
        } v;
    } lcb_get_resp_t;

    typedef struct {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                lcb_cas_t cas;
            } v0;
        } v;
    } lcb_store_resp_t;

    typedef struct {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
            } v0;
        } v;
    } lcb_remove_resp_t;

    typedef struct {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                lcb_cas_t cas;
            } v0;
        } v;
    } lcb_touch_resp_t;

    typedef struct {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
            } v0;
        } v;
    } lcb_unlock_resp_t;

    typedef struct {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                lcb_uint64_t value;
                lcb_cas_t cas;
            } v0;
        } v;
    } lcb_arithmetic_resp_t;

    typedef struct {
        int version;
        union {
            struct {
                const void *key;
                lcb_size_t nkey;
                lcb_cas_t cas;
                lcb_observe_t status;
                int from_master;          /* zero if key came from replica */
                lcb_time_t ttp;           /* time to persist */
                lcb_time_t ttr;           /* time to replicate */
            } v0;
        } v;
    } lcb_observe_resp_t;

    typedef struct {
        int version;
        union {
            struct {
                lcb_http_status_t status;
                const char *path;
                lcb_size_t npath;
                const char *const *headers;
                const void *bytes;
                lcb_size_t nbytes;
            } v0;
        } v;
    } lcb_http_resp_t;

#ifdef __cplusplus
}
#endif

#endif
