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
 * Definition of the callbacks structure.
 * @todo Document each function
 *
 * @author Trond Norbye
 */
#ifndef LIBMEMBASE_CALLBACKS_H
#define LIBMEMBASE_CALLBACKS_H 1

#ifndef LIBMEMBASE_MEMBASE_H
#error "Include libmembase/membase.h instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        void (*get)(libmembase_t instance,
                    libmembase_error_t error,
                    const void *key, size_t nkey,
                    const void *bytes, size_t nbytes,
                    uint32_t flags, uint64_t cas);
        void (*storage)(libmembase_t instance,
                        libmembase_error_t error,
                        const void *key, size_t nkey,
                        uint64_t cas);
        void (*arithmetic)(libmembase_t instance,
                           libmembase_error_t error,
                           const void *key, size_t nkey,
                           uint64_t value, uint64_t cas);
        void (*remove)(libmembase_t instance,
                       libmembase_error_t error,
                       const void *key, size_t nkey);
        void (*tap_mutation)(libmembase_t instance,
                             const void *key,
                             size_t nkey,
                             const void *data,
                             size_t nbytes,
                             uint32_t flags,
                             uint32_t exp,
                             const void *es,
                             size_t nes);
        void (*tap_deletion)(libmembase_t instance,
                             const void *key,
                             size_t nkey,
                             const void *es,
                             size_t nes);
        void (*tap_flush)(libmembase_t instance,
                          const void *es,
                          size_t nes);
        void (*tap_opaque)(libmembase_t instance,
                           const void *es,
                           size_t nes);
        void (*tap_vbucket_set)(libmembase_t instance,
                                uint16_t vbid,
                                vbucket_state_t state,
                                const void *es,
                                size_t nes);
    } libmembase_callback_t;

#ifdef __cplusplus
}
#endif

#endif
