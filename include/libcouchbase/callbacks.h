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
 * Definition of the callbacks structure.
 * @todo Document each function
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_CALLBACKS_H
#define LIBCOUCHBASE_CALLBACKS_H 1

#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "Include libcouchbase/couchbase.h instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef void (*libcouchbase_get_callback)(libcouchbase_t instance,
                                              const void *cookie,
                                              libcouchbase_error_t error,
                                              const void *key, size_t nkey,
                                              const void *bytes, size_t nbytes,
                                              uint32_t flags, uint64_t cas);
    typedef void (*libcouchbase_storage_callback)(libcouchbase_t instance,
                                                  const void *cookie,
                                                  libcouchbase_storage_t operation,
                                                  libcouchbase_error_t error,
                                                  const void *key, size_t nkey,
                                                  uint64_t cas);
    typedef void (*libcouchbase_arithmetic_callback)(libcouchbase_t instance,
                                                     const void *cookie,
                                                     libcouchbase_error_t error,
                                                     const void *key, size_t nkey,
                                                     uint64_t value, uint64_t cas);
    typedef void (*libcouchbase_remove_callback)(libcouchbase_t instance,
                                                 const void *cookie,
                                                 libcouchbase_error_t error,
                                                 const void *key, size_t nkey);
    typedef void (*libcouchbase_touch_callback)(libcouchbase_t instance,
                                                const void *cookie,
                                                libcouchbase_error_t error,
                                                const void *key, size_t nkey);
    typedef void (*libcouchbase_tap_mutation_callback)(libcouchbase_t instance,
                                                       const void *cookie,
                                                       const void *key,
                                                       size_t nkey,
                                                       const void *data,
                                                       size_t nbytes,
                                                       uint32_t flags,
                                                       uint32_t exp,
                                                       const void *es,
                                                       size_t nes);
    typedef void (*libcouchbase_tap_deletion_callback)(libcouchbase_t instance,
                                                       const void *cookie,
                                                       const void *key,
                                                       size_t nkey,
                                                       const void *es,
                                                       size_t nes);
    typedef void (*libcouchbase_tap_flush_callback)(libcouchbase_t instance,
                                                    const void *cookie,
                                                    const void *es,
                                                    size_t nes);
    typedef void (*libcouchbase_tap_opaque_callback)(libcouchbase_t instance,
                                                     const void *cookie,
                                                     const void *es,
                                                     size_t nes);
    typedef void (*libcouchbase_tap_vbucket_set_callback)(libcouchbase_t instance,
                                                          const void *cookie,
                                                          uint16_t vbid,
                                                          vbucket_state_t state,
                                                          const void *es,
                                                          size_t nes);

    LIBCOUCHBASE_API
    libcouchbase_get_callback libcouchbase_set_get_callback(libcouchbase_t,
                                                            libcouchbase_get_callback);
    LIBCOUCHBASE_API
    libcouchbase_storage_callback libcouchbase_set_storage_callback(libcouchbase_t,
                                                                    libcouchbase_storage_callback);
    LIBCOUCHBASE_API
    libcouchbase_arithmetic_callback libcouchbase_set_arithmetic_callback(libcouchbase_t,
                                                                          libcouchbase_arithmetic_callback);

    LIBCOUCHBASE_API
    libcouchbase_remove_callback libcouchbase_set_remove_callback(libcouchbase_t,
                                                                  libcouchbase_remove_callback);

    LIBCOUCHBASE_API
    libcouchbase_touch_callback libcouchbase_set_touch_callback(libcouchbase_t,
                                                                libcouchbase_touch_callback);

    LIBCOUCHBASE_API
    libcouchbase_tap_mutation_callback libcouchbase_set_tap_mutation_callback(libcouchbase_t,
                                                                              libcouchbase_tap_mutation_callback);

    LIBCOUCHBASE_API
    libcouchbase_tap_deletion_callback libcouchbase_set_tap_deletion_callback(libcouchbase_t,
                                                                              libcouchbase_tap_deletion_callback);

    LIBCOUCHBASE_API
    libcouchbase_tap_flush_callback libcouchbase_set_tap_flush_callback(libcouchbase_t,
                                                                    libcouchbase_tap_flush_callback);

    LIBCOUCHBASE_API
    libcouchbase_tap_opaque_callback libcouchbase_set_tap_opaque_callback(libcouchbase_t,
                                                                          libcouchbase_tap_opaque_callback);

    LIBCOUCHBASE_API
    libcouchbase_tap_vbucket_set_callback libcouchbase_set_tap_vbucket_set_callback(libcouchbase_t,
                                                                                    libcouchbase_tap_vbucket_set_callback);

#ifdef __cplusplus
}
#endif

#endif
