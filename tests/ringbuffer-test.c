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

#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libcouchbase/couchbase.h>
#include "ringbuffer.h"

#ifdef DO_ABORT
#  define fail abort()
#else
#  define fail exit(EXIT_FAILURE)
#endif

#define QUOTE_(x) #x
#define QUOTE(x) QUOTE_(x)
#define AT "[" __FILE__ ":" QUOTE(__LINE__) "] "
#define err_exit(...)  \
    fprintf(stderr, AT __VA_ARGS__);  \
    fprintf(stderr, "\n");  \
    fail;

static void dump_buffer(ringbuffer_t *ring)
{
    char *begin = ringbuffer_get_start(ring);
    char *end = begin + ringbuffer_get_size(ring);
    char *rd = ringbuffer_get_read_head(ring);
    char *wr = ringbuffer_get_write_head(ring);
    char *cur;

    /* write head */
    fprintf(stderr, " ");
    for(cur = begin; cur < end; cur++) {
        if (cur == wr) {
            fprintf(stderr, "w");
        } else {
            fprintf(stderr, " ");
        }
    }
    fprintf(stderr, "\n");

    /* the buffer contents */
    fprintf(stderr, "|");
    for(cur = begin; cur < end; cur++) {
        fprintf(stderr, "%c", *cur ? *cur : '-');
    }
    fprintf(stderr, "|\n");

    /* the read head */
    fprintf(stderr, " ");
    for(cur = begin; cur < end; cur++) {
        if (cur == rd) {
            fprintf(stderr, "r");
        } else {
            fprintf(stderr, " ");
        }
    }
    fprintf(stderr, "\n");
}

static void wrapped_buffer_test(void)
{
    ringbuffer_t ring;
    char buffer[128];

    if (!ringbuffer_initialize(&ring, 10)) {
        err_exit("Failed to create a 10 byte ringbuffer");
    }
    memset(ringbuffer_get_start(&ring), 0, 10);
    /*  w
     * |----------|
     *  r
     */

    /* put 8 chars into the buffer */
    if (ringbuffer_write(&ring, "01234567", 8) != 8) {
        err_exit("Failed to write 10 characters to buffer");
    }
    /*          w
     * |01234567--|
     *  r
     */

    /* consume first 5 chars */
    if (ringbuffer_read(&ring, buffer, 5) != 5 ||
        memcmp(buffer, "01234", 5) != 0) {
        err_exit("Failed to consume first 5 characters");
    }
    /*          w
     * |-----567--|
     *       r
     */

    /* wrapped write: write 5 more chars */
    if (ringbuffer_write(&ring, "abcde", 5) != 5) {
        err_exit("Failed to write to wrapped buffer");
    }
    /*     w
     * |cde--567ab|
     *       r
     */

    /* wrapped read: read 6 chars */
    if (ringbuffer_read(&ring, buffer, 6) != 6 ||
        memcmp(buffer, "567abc", 6) != 0) {
        err_exit("Failed to read wrapped buffer");
    }
    /*     w
     * |-de-------|
     *   r
     */
}

// This is a crash I noticed while I was debugging the tap code
static void my_regression_1_test(void)
{
    ringbuffer_t ring;
    struct libcouchbase_iovec_st iov[2];
    ring.root = (void*)0x477a80;
    ring.read_head = (void*)0x47b0a3;
    ring.write_head =(void*)0x47b555;
    ring.size = 16384;
    ring.nbytes = 1202;

    ringbuffer_get_iov(&ring, RINGBUFFER_WRITE, iov);
    // up to the end
    assert(iov[0].iov_base == ring.write_head);
    assert(iov[0].iov_len == 1323);
    // then from the beginning
    assert(iov[1].iov_base == ring.root);
    assert(iov[1].iov_len == 13859);
}

int main(int argc, char **argv)
{
    ringbuffer_t ring;
    char buffer[1024];
    int ii;

    /* use dump_buffer() to display buffer contents */
    (void)dump_buffer;
    (void)argc; (void)argv;

    if (!ringbuffer_initialize(&ring, 16)) {
        err_exit("Failed to create a 16 byte ringbuffer");
    }

    if (ringbuffer_read(&ring, buffer, 1) != 0) {
        err_exit("Read from an empty buffer should return 0");
    }

    if (ringbuffer_write(&ring, "01234567891234567", 17) != 16) {
        err_exit("Buffer overflow!!!");
    }

    for (ii = 0; ii < 2; ++ii) {
        memset(buffer, 0, sizeof(buffer));
        if (ringbuffer_peek(&ring, buffer, 16) != 16 ||
            memcmp(buffer, "01234567891234567", 16) != 0) {
            err_exit("We just filled the buffer with 16 bytes.. peek failed");
        }
    }

    if (ringbuffer_read(&ring, buffer, 16) != 16) {
        err_exit("We just filled the buffer with 16 bytes");
    }

    if (ringbuffer_read(&ring, buffer, 1) != 0) {
        err_exit("Read from an empty buffer should return 0");
    }

    if (ringbuffer_write(&ring, "01234567891234567", 17) != 16) {
        err_exit("Buffer overflow!!!");
    }

    if (ringbuffer_read(&ring, buffer, 8) != 8) {
        err_exit("We just filled the buffer with 16 bytes");
    }

    if (!ringbuffer_ensure_capacity(&ring, 9)) {
        err_exit("I failed to grow the buffer");
    }

    if (ring.size != 32) {
        err_exit("The buffers should double in size");
    }

    if (ring.read_head != ring.root) {
        err_exit("I expected the data to be realigned");
    }

    if (ringbuffer_read(&ring, buffer, 8) != 8) {
        err_exit("We should still have 8 bytes left");
    }

    if (memcmp(buffer, "89123456", 8) != 0) {
        err_exit("I'm not getting the data I'm expecting...");
    }

    wrapped_buffer_test();

    my_regression_1_test();

    return 0;
}
