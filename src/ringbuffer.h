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
#ifndef RINGBUFFER_H
#define RINGBUFFER_H 1

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        char *root;
        char *read_head;
        char *write_head;
        libcouchbase_size_t size;
        libcouchbase_size_t nbytes;
    } ringbuffer_t;

    typedef enum {
        RINGBUFFER_READ = 0x01,
        RINGBUFFER_WRITE = 0x02
    } ringbuffer_direction_t;

    int ringbuffer_initialize(ringbuffer_t *buffer,
                              libcouchbase_size_t size);
    void ringbuffer_reset(ringbuffer_t *buffer);
    void ringbuffer_destruct(ringbuffer_t *buffer);
    int ringbuffer_ensure_capacity(ringbuffer_t *buffer,
                                   libcouchbase_size_t size);
    libcouchbase_size_t ringbuffer_get_size(ringbuffer_t *buffer);
    void *ringbuffer_get_start(ringbuffer_t *buffer);
    void *ringbuffer_get_read_head(ringbuffer_t *buffer);
    void *ringbuffer_get_write_head(ringbuffer_t *buffer);
    libcouchbase_size_t ringbuffer_write(ringbuffer_t *buffer,
                                         const void *src,
                                         libcouchbase_size_t nb);
    libcouchbase_size_t ringbuffer_strcat(ringbuffer_t *buffer,
                                          const char *str);
    libcouchbase_size_t ringbuffer_read(ringbuffer_t *buffer,
                                        void *dest,
                                        libcouchbase_size_t nb);
    libcouchbase_size_t ringbuffer_peek(ringbuffer_t *buffer,
                                        void *dest,
                                        libcouchbase_size_t nb);
    void ringbuffer_get_iov(ringbuffer_t *buffer,
                            ringbuffer_direction_t direction,
                            struct libcouchbase_iovec_st *iov);
    void ringbuffer_produced(ringbuffer_t *buffer, libcouchbase_size_t nb);
    void ringbuffer_consumed(ringbuffer_t *buffer, libcouchbase_size_t nb);
    libcouchbase_size_t ringbuffer_get_nbytes(ringbuffer_t *buffer);
    int ringbuffer_is_continous(ringbuffer_t *buffer,
                                ringbuffer_direction_t direction,
                                libcouchbase_size_t nb);

    int ringbuffer_append(ringbuffer_t *src, ringbuffer_t *dest);
    int ringbuffer_memcpy(ringbuffer_t *dst, ringbuffer_t *src,
                          libcouchbase_size_t nbytes);

#ifdef __cplusplus
}
#endif

#endif
