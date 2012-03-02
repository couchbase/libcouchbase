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
 * Code used for compatibility with other types of clusters
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_COMPAT_H
#define LIBCOUCHBASE_COMPAT_H 1

#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "Include libcouchbase/couchbase.h instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum {
        LIBCOUCHBASE_MEMCACHED_CLUSTER = 0x00
    } libcouchbase_cluster_t;

    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_create_compat(libcouchbase_cluster_t type,
                                                    const void *specific,
                                                    libcouchbase_t *instance,
                                                    struct libcouchbase_io_opt_st *io);

    struct libcouchbase_memcached_st {
        const char *serverlist;
        const char *username;
        const char *password;
    };

#ifdef __cplusplus
}
#endif

#endif
