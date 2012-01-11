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

#include "internal.h"

static size_t minimum(size_t a, size_t b)
{
    return (a < b) ? a : b;
}

int libcouchbase_ringbuffer_initialize(ringbuffer_t *buffer, size_t size)
{
    memset(buffer, 0, sizeof(ringbuffer_t));
    buffer->root = malloc(size);
    if (buffer->root == NULL) {
        return 0;
    }
    buffer->size = size;
    buffer->write_head = buffer->root;
    buffer->read_head = buffer->root;
    return 1;
}

void libcouchbase_ringbuffer_destruct(ringbuffer_t *buffer)
{
    free(buffer->root);
    buffer->root = buffer->read_head = buffer->write_head = NULL;
    buffer->size = buffer->nbytes = 0;
}

int libcouchbase_ringbuffer_ensure_capacity(ringbuffer_t *buffer, size_t size)
{
    char *new_root;
    size_t new_size = buffer->size << 1;
    if (new_size == 0) {
        new_size = 128;
    }

    if (size < (buffer->size - buffer->nbytes)) {
        /* we've got capacity! */
        return 1;
    }

    /* determine the new buffer size... */
    while ((new_size - buffer->nbytes) < size) {
        new_size <<= 1;
    }

    /* go ahead and allocate a bigger block */
    if ((new_root = malloc(new_size)) == NULL) {
        /* Allocation failed! */
        return 0;
    } else {
        /* copy the data over :) */
        char *old;
        size_t nbytes = buffer->nbytes;
        size_t nr = libcouchbase_ringbuffer_read(buffer, new_root, nbytes);
        if (nr != nbytes) {
            abort();
        }
        old = buffer->root;
        buffer->size = new_size;
        buffer->root = new_root;
        buffer->nbytes = nbytes;
        buffer->read_head = buffer->root;
        buffer->write_head = buffer->root + nbytes;
        free(old);
        return 1;
    }
}

size_t libcouchbase_ringbuffer_get_size(ringbuffer_t *buffer)
{
    return buffer->size;
}

void *libcouchbase_ringbuffer_get_start(ringbuffer_t *buffer)
{
    return buffer->root;
}

void *libcouchbase_ringbuffer_get_read_head(ringbuffer_t *buffer)
{
    return buffer->read_head;
}

void *libcouchbase_ringbuffer_get_write_head(ringbuffer_t *buffer)
{
    return buffer->write_head;
}

size_t libcouchbase_ringbuffer_write(ringbuffer_t *buffer,
                                     const void *src,
                                     size_t nb)
{
    const char *s = src;
    size_t nw = 0;
    size_t space;
    size_t toWrite;

    if (buffer->write_head >= buffer->read_head) {
        /* write up to the end with data.. */
        space = buffer->size - (size_t)(buffer->write_head - buffer->root);
        toWrite = minimum(space, nb);

        if (src != NULL) {
            memcpy(buffer->write_head, s, toWrite);
        }
        buffer->nbytes += toWrite;
        buffer->write_head += toWrite;
        nw = toWrite;

        if (buffer->write_head == (buffer->root + buffer->size)) {
            buffer->write_head = buffer->root;
        }

        if (nw == nb) {
            /* everything is written to the buffer.. */
            return nw;
        }

        nb -= toWrite;
        s += toWrite;
    }

    /* Copy data up until we catch up with the read head */
    space = (size_t)(buffer->read_head - buffer->write_head);
    toWrite = minimum(space, nb);
    if (src != NULL) {
        memcpy(buffer->write_head, s, toWrite);
    }
    buffer->nbytes += toWrite;
    buffer->write_head += toWrite;
    nw += toWrite;

    if (buffer->write_head == (buffer->root + buffer->size)) {
        buffer->write_head = buffer->root;
    }

    return nw;
}

static void maybe_reset(ringbuffer_t *buffer) {
    if (buffer->nbytes == 0) {
        buffer->write_head = buffer->root;
        buffer->read_head = buffer->root;
    }
}


size_t libcouchbase_ringbuffer_read(ringbuffer_t *buffer, void *dest, size_t nb)
{
    char *d = dest;
    size_t nr = 0;
    size_t space;
    size_t toRead;

    if (buffer->nbytes == 0) {
        return 0;
    }
    if (buffer->read_head >= buffer->write_head) {
        /* read up to the wrap point */
        space = buffer->size - (size_t)(buffer->read_head - buffer->root);
        toRead = minimum(space, nb);

        if (dest != NULL) {
            memcpy(d, buffer->read_head, toRead);
        }
        buffer->nbytes -= toRead;
        buffer->read_head += toRead;
        nr = toRead;

        if (buffer->read_head == (buffer->root + buffer->size)) {
            buffer->read_head = buffer->root;
        }

        if (nr == nb) {
            maybe_reset(buffer);
            return nr;
        }

        nb -= toRead;
        d += toRead;
    }

    space = (size_t)(buffer->write_head - buffer->read_head);
    toRead = minimum(space, nb);

    if (dest != NULL) {
        memcpy(d, buffer->read_head, toRead);
    }
    buffer->nbytes -= toRead;
    buffer->read_head += toRead;
    nr += toRead;

    if (buffer->read_head == (buffer->root + buffer->size)) {
        buffer->read_head = buffer->root;
    }

    maybe_reset(buffer);
    return nr;
}

size_t libcouchbase_ringbuffer_peek(ringbuffer_t *buffer, void *dest, size_t nb)
{
    ringbuffer_t copy = *buffer;
    return libcouchbase_ringbuffer_read(&copy, dest, nb);
}

void libcouchbase_ringbuffer_produced(ringbuffer_t *buffer, size_t nb)
{
    size_t n = libcouchbase_ringbuffer_write(buffer, NULL, nb);
    if (n != nb) {
        abort();
    }
}

void libcouchbase_ringbuffer_consumed(ringbuffer_t *buffer, size_t nb)
{
    size_t n = libcouchbase_ringbuffer_read(buffer, NULL, nb);
    if (n != nb) {
        abort();
    }
}

size_t libcouchbase_ringbuffer_get_nbytes(ringbuffer_t *buffer)
{
    return buffer->nbytes;
}



void libcouchbase_ringbuffer_get_iov(ringbuffer_t *buffer,
                                     libcouchbase_ringbuffer_direction_t direction,
                                     struct libcouchbase_iovec_st *iov)
{
    iov[1].iov_base = buffer->root;
    iov[1].iov_len = 0;

    if (direction == RINGBUFFER_READ) {
        iov[0].iov_base = buffer->read_head;
        iov[0].iov_len = buffer->nbytes;
        if (buffer->read_head >= buffer->write_head) {
            ptrdiff_t chunk = buffer->root + buffer->size - buffer->read_head;
            if (buffer->nbytes > (size_t)chunk) {
                iov[0].iov_len = (size_t)chunk;
                iov[1].iov_len = buffer->nbytes - (size_t)chunk;
            }
        }
    } else {
        assert(direction == RINGBUFFER_WRITE);
        iov[0].iov_base = buffer->write_head;
        iov[0].iov_len = buffer->size - buffer->nbytes;
        if (buffer->write_head >= buffer->read_head) {
            // I may write all the way to the end!
            iov[0].iov_len = (buffer->root + buffer->size) - buffer->write_head;
            // And all the way up to the read head
            iov[1].iov_len = buffer->read_head - buffer->root;
        }
    }
}

int libcouchbase_ringbuffer_is_continous(ringbuffer_t *buffer,
                                          libcouchbase_ringbuffer_direction_t direction,
                                          size_t nb)
{
    int ret;

    if (direction == RINGBUFFER_READ) {
        ret = (nb <= buffer->nbytes);

        if (buffer->read_head >= buffer->write_head) {
            ptrdiff_t chunk = buffer->root + buffer->size - buffer->read_head;
            if (buffer->nbytes > (size_t)chunk) {
                ret = 0;
            }
        }
    } else {
        ret = (nb <= buffer->size - buffer->nbytes);
        if (buffer->write_head >= buffer->read_head) {
            ptrdiff_t chunk = buffer->root + buffer->size - buffer->write_head;
            if (buffer->nbytes > (size_t)chunk) {
                ret = 0;
            }
        }
    }
    return ret;
}

int libcouchbase_ringbuffer_append(ringbuffer_t *src, ringbuffer_t *dest)
{
    char buffer[1024];
    size_t nr, nw;

    while ((nr = libcouchbase_ringbuffer_read(src, buffer,
                                              sizeof(buffer))) != 0) {
        if (!libcouchbase_ringbuffer_ensure_capacity(dest, nr)) {
            abort();
            return 0;
        }

        nw = libcouchbase_ringbuffer_write(dest, buffer, nr);
        if (nw != nr) {
            abort();
            return 0;
        }
    }

    return 1;
}
