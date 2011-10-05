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
        size_t size;
        size_t nbytes;
    } ringbuffer_t;

    typedef enum {
        RINGBUFFER_READ = 0x01,
        RINGBUFFER_WRITE = 0x02
    } libcouchbase_ringbuffer_direction_t;

    bool libcouchbase_ringbuffer_initialize(ringbuffer_t *buffer, size_t size);
    void libcouchbase_ringbuffer_destruct(ringbuffer_t *buffer);
    bool libcouchbase_ringbuffer_ensure_capacity(ringbuffer_t *buffer, size_t size);
    size_t libcouchbase_ringbuffer_get_size(ringbuffer_t *buffer);
    void *libcouchbase_ringbuffer_get_start(ringbuffer_t *buffer);
    void *libcouchbase_ringbuffer_get_read_head(ringbuffer_t *buffer);
    void *libcouchbase_ringbuffer_get_write_head(ringbuffer_t *buffer);
    size_t libcouchbase_ringbuffer_write(ringbuffer_t *buffer,
                                     const void *src,
                                     size_t nb);
    size_t libcouchbase_ringbuffer_read(ringbuffer_t *buffer, void *dest, size_t nb);
    size_t libcouchbase_ringbuffer_peek(ringbuffer_t *buffer, void *dest, size_t nb);
    void libcouchbase_ringbuffer_get_iov(ringbuffer_t *buffer,
                                         libcouchbase_ringbuffer_direction_t direction,
                                         struct libcouchbase_iovec_st *iov);
    void libcouchbase_ringbuffer_produced(ringbuffer_t *buffer, size_t nb);
    void libcouchbase_ringbuffer_consumed(ringbuffer_t *buffer, size_t nb);
    size_t libcouchbase_ringbuffer_get_nbytes(ringbuffer_t *buffer);
    bool libcouchbase_ringbuffer_is_continous(ringbuffer_t *buffer,
                                              libcouchbase_ringbuffer_direction_t direction,
                                              size_t nb);

    bool libcouchbase_ringbuffer_append(ringbuffer_t *src, ringbuffer_t *dest);

#ifdef __cplusplus
}
#endif



#endif
