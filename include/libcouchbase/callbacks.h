/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011 Couchbase, Inc.
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

    typedef void (*libcouchbase_extended_get_callback)(libcouchbase_t instance,
                                                       const void *cookie,
                                                       libcouchbase_error_t error,
                                                       struct libcouchbase_item_st *item);

    typedef void (*libcouchbase_get_callback)(libcouchbase_t instance,
                                              const void *cookie,
                                              libcouchbase_error_t error,
                                              const void *key,
                                              libcouchbase_size_t nkey,
                                              const void *bytes,
                                              libcouchbase_size_t nbytes,
                                              libcouchbase_uint32_t flags,
                                              libcouchbase_cas_t cas);
    typedef void (*libcouchbase_storage_callback)(libcouchbase_t instance,
                                                  const void *cookie,
                                                  libcouchbase_storage_t operation,
                                                  libcouchbase_error_t error,
                                                  const void *key,
                                                  libcouchbase_size_t nkey,
                                                  libcouchbase_cas_t cas);
    typedef void (*libcouchbase_arithmetic_callback)(libcouchbase_t instance,
                                                     const void *cookie,
                                                     libcouchbase_error_t error,
                                                     const void *key,
                                                     libcouchbase_size_t nkey,
                                                     libcouchbase_uint64_t value,
                                                     libcouchbase_cas_t cas);
    typedef void (*libcouchbase_observe_callback)(libcouchbase_t instance,
                                                  const void *cookie,
                                                  libcouchbase_error_t error,
                                                  libcouchbase_observe_t status,
                                                  const void *key,
                                                  libcouchbase_size_t nkey,
                                                  libcouchbase_cas_t cas,
                                                  int from_master,          /* zero if key came from replica */
                                                  libcouchbase_time_t ttp,  /* time to persist */
                                                  libcouchbase_time_t ttr); /* time to replicate */
    typedef void (*libcouchbase_remove_callback)(libcouchbase_t instance,
                                                 const void *cookie,
                                                 libcouchbase_error_t error,
                                                 const void *key,
                                                 libcouchbase_size_t nkey);
    typedef void (*libcouchbase_stat_callback)(libcouchbase_t instance,
                                               const void *cookie,
                                               const char *server_endpoint,
                                               libcouchbase_error_t error,
                                               const void *key,
                                               libcouchbase_size_t nkey,
                                               const void *bytes,
                                               libcouchbase_size_t nbytes);
    typedef void (*libcouchbase_version_callback)(libcouchbase_t instance,
                                                  const void *cookie,
                                                  const char *server_endpoint,
                                                  libcouchbase_error_t error,
                                                  const char *vstring,
                                                  libcouchbase_size_t nvstring);
    typedef void (*libcouchbase_touch_callback)(libcouchbase_t instance,
                                                const void *cookie,
                                                libcouchbase_error_t error,
                                                const void *key,
                                                libcouchbase_size_t nkey);
    typedef void (*libcouchbase_tap_mutation_callback)(libcouchbase_t instance,
                                                       const void *cookie,
                                                       const void *key,
                                                       libcouchbase_size_t nkey,
                                                       const void *data,
                                                       libcouchbase_size_t nbytes,
                                                       libcouchbase_uint32_t flags,
                                                       libcouchbase_time_t exp,
                                                       libcouchbase_cas_t cas,
                                                       libcouchbase_vbucket_t vbucket,
                                                       const void *es,
                                                       libcouchbase_size_t nes);
    typedef void (*libcouchbase_tap_deletion_callback)(libcouchbase_t instance,
                                                       const void *cookie,
                                                       const void *key,
                                                       libcouchbase_size_t nkey,
                                                       libcouchbase_cas_t cas,
                                                       libcouchbase_vbucket_t vbucket,
                                                       const void *es,
                                                       libcouchbase_size_t nes);
    typedef void (*libcouchbase_tap_flush_callback)(libcouchbase_t instance,
                                                    const void *cookie,
                                                    const void *es,
                                                    libcouchbase_size_t nes);
    typedef void (*libcouchbase_tap_opaque_callback)(libcouchbase_t instance,
                                                     const void *cookie,
                                                     const void *es,
                                                     libcouchbase_size_t nes);
    typedef void (*libcouchbase_tap_vbucket_set_callback)(libcouchbase_t instance,
                                                          const void *cookie,
                                                          libcouchbase_vbucket_t vbid,
                                                          libcouchbase_vbucket_state_t state,
                                                          const void *es,
                                                          libcouchbase_size_t nes);
    typedef void (*libcouchbase_error_callback)(libcouchbase_t instance,
                                                libcouchbase_error_t error,
                                                const char *errinfo);

    typedef void (*libcouchbase_flush_callback)(libcouchbase_t instance,
                                                const void *cookie,
                                                const char *server_endpoint,
                                                libcouchbase_error_t error);

    typedef void (*libcouchbase_timer_callback)(libcouchbase_timer_t timer,
                                                libcouchbase_t instance,
                                                const void *cookie);

    /**
     * couch_complete_callback will notify that view execution was completed
     * and libcouchbase will pass response body to this callback unless
     * couch_data_callback set up.
     */
    typedef void (*libcouchbase_http_complete_callback)(libcouchbase_http_request_t request,
                                                        libcouchbase_t instance,
                                                        const void *cookie,
                                                        libcouchbase_error_t error,
                                                        libcouchbase_http_status_t status,
                                                        const char *path,
                                                        libcouchbase_size_t npath,
                                                        const char * const *headers,
                                                        const void *bytes,
                                                        libcouchbase_size_t nbytes);

    /**
     * couch_data_callback switch the view operation into the 'chunked' mode
     * and it will call this callback each time the data received from the
     * socket. *note* it doesn't collect whole response anymore. It returns
     * NULL for bytes and zero for nbytes to signal that request was
     * completed.
     */
    typedef void (*libcouchbase_http_data_callback)(libcouchbase_http_request_t request,
                                                    libcouchbase_t instance,
                                                    const void *cookie,
                                                    libcouchbase_error_t error,
                                                    libcouchbase_http_status_t status,
                                                    const char *path,
                                                    libcouchbase_size_t npath,
                                                    const char * const *headers,
                                                    const void *bytes,
                                                    libcouchbase_size_t nbytes);

    typedef void (*libcouchbase_unlock_callback)(libcouchbase_t instance,
                                                 const void *cookie,
                                                 libcouchbase_error_t error,
                                                 const void *key,
                                                 libcouchbase_size_t nkey);

    typedef void (*libcouchbase_configuration_callback)(libcouchbase_t instance,
                                                        libcouchbase_configuration_t val);

    typedef void (*libcouchbase_verbosity_callback)(libcouchbase_t instance,
                                                    const void *cookie,
                                                    const char *server_endpoint,
                                                    libcouchbase_error_t error);

    LIBCOUCHBASE_API
    libcouchbase_extended_get_callback libcouchbase_set_extended_get_callback(libcouchbase_t,
                                                                              libcouchbase_extended_get_callback);
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
    libcouchbase_observe_callback libcouchbase_set_observe_callback(libcouchbase_t,
                                                                    libcouchbase_observe_callback);

    LIBCOUCHBASE_API
    libcouchbase_remove_callback libcouchbase_set_remove_callback(libcouchbase_t,
                                                                  libcouchbase_remove_callback);

    LIBCOUCHBASE_API
    libcouchbase_stat_callback libcouchbase_set_stat_callback(libcouchbase_t instance,
                                                              libcouchbase_stat_callback cb);

    LIBCOUCHBASE_API
    libcouchbase_version_callback libcouchbase_set_version_callback(libcouchbase_t instance,
                                                                    libcouchbase_version_callback cb);

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

    LIBCOUCHBASE_API
    libcouchbase_error_callback libcouchbase_set_error_callback(libcouchbase_t,
                                                                libcouchbase_error_callback);

    LIBCOUCHBASE_API
    libcouchbase_flush_callback libcouchbase_set_flush_callback(libcouchbase_t,
                                                                libcouchbase_flush_callback);

    LIBCOUCHBASE_API
    libcouchbase_http_complete_callback libcouchbase_set_view_complete_callback(libcouchbase_t instance,
                                                                                libcouchbase_http_complete_callback cb);

    LIBCOUCHBASE_API
    libcouchbase_http_data_callback libcouchbase_set_view_data_callback(libcouchbase_t instance,
                                                                        libcouchbase_http_data_callback cb);

    LIBCOUCHBASE_API
    libcouchbase_http_complete_callback libcouchbase_set_management_complete_callback(libcouchbase_t instance,
                                                                                      libcouchbase_http_complete_callback cb);

    LIBCOUCHBASE_API
    libcouchbase_http_data_callback libcouchbase_set_management_data_callback(libcouchbase_t instance,
                                                                              libcouchbase_http_data_callback cb);

    LIBCOUCHBASE_API
    libcouchbase_unlock_callback libcouchbase_set_unlock_callback(libcouchbase_t,
                                                                  libcouchbase_unlock_callback);

    LIBCOUCHBASE_API
    libcouchbase_configuration_callback libcouchbase_set_configuration_callback(libcouchbase_t,
                                                                                libcouchbase_configuration_callback);

    LIBCOUCHBASE_API
    libcouchbase_verbosity_callback libcouchbase_set_verbosity_callback(libcouchbase_t,
                                                                        libcouchbase_verbosity_callback);

#ifdef __cplusplus
}
#endif

#endif
