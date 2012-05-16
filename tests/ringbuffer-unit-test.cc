/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#include "ringbuffer.h"

extern "C" {
    extern int libcouchbase_base64_encode(const char *src, char *dst,
                                          size_t sz);
}

class Ringbuffer : public ::testing::Test
{
protected:
    // Helper function used for debugging ;)
    void dump_buffer(ringbuffer_t *ring)
    {
        const char *begin = (const char*)ringbuffer_get_start(ring);
        const char *end = begin + ringbuffer_get_size(ring);
        const char *rd = (const char*)ringbuffer_get_read_head(ring);
        const char *wr = (const char*)ringbuffer_get_write_head(ring);
        const char *cur;

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
};

TEST_F(Ringbuffer, basicTests)
{
    ringbuffer_t ring;
    char buffer[1024];
    int ii;

    EXPECT_NE(0, ringbuffer_initialize(&ring, 16));
    EXPECT_EQ(0, ringbuffer_read(&ring, buffer, 1));
    EXPECT_EQ(16, ringbuffer_write(&ring, "01234567891234567", 17));

    for (ii = 0; ii < 2; ++ii) {
        memset(buffer, 0, sizeof(buffer));
        EXPECT_EQ(16, ringbuffer_peek(&ring, buffer, 16));
        EXPECT_EQ(0, memcmp(buffer, "01234567891234567", 16));
    }

    EXPECT_EQ(16, ringbuffer_read(&ring, buffer, 16));
    EXPECT_EQ(0, ringbuffer_read(&ring, buffer, 1));
    EXPECT_EQ(16, ringbuffer_write(&ring, "01234567891234567", 17));
    EXPECT_EQ(8, ringbuffer_read(&ring, buffer, 8));
    EXPECT_NE(0, ringbuffer_ensure_capacity(&ring, 9));
    EXPECT_EQ(32, ring.size);
    EXPECT_EQ(ring.root, ring.read_head);
    EXPECT_EQ(8, ringbuffer_read(&ring, buffer, 9));
    EXPECT_EQ(0, memcmp(buffer, "89123456", 8));

    // wrapped_buffer_test();
    // my_regression_1_test();

}

TEST_F(Ringbuffer, wrappedBufferTest)
{
    ringbuffer_t ring;
    char buffer[128];

    EXPECT_NE(0, ringbuffer_initialize(&ring, 10));

    memset(ringbuffer_get_start(&ring), 0, 10);
    /*  w
     * |----------|
     *  r
     */

    /* put 8 chars into the buffer */
    EXPECT_EQ(8, ringbuffer_write(&ring, "01234567", 8));

    /*          w
     * |01234567--|
     *  r
     */

    /* consume first 5 chars */
    EXPECT_EQ(5, ringbuffer_read(&ring, buffer, 5));
    EXPECT_EQ(0, memcmp(buffer, "01234", 5));

    /*          w
     * |-----567--|
     *       r
     */
    EXPECT_EQ(0, ringbuffer_is_continous(&ring, RINGBUFFER_WRITE, 5));
    EXPECT_NE(0, ringbuffer_is_continous(&ring, RINGBUFFER_WRITE, 2));

    /* wrapped write: write 5 more chars */
    EXPECT_EQ(5, ringbuffer_write(&ring, "abcde", 5));

    /*     w
     * |cde--567ab|
     *       r
     */

    EXPECT_EQ(0, ringbuffer_is_continous(&ring, RINGBUFFER_READ, 7));
    EXPECT_NE(0, ringbuffer_is_continous(&ring, RINGBUFFER_READ, 2));

    /* wrapped read: read 6 chars */
    EXPECT_EQ(6, ringbuffer_read(&ring, buffer, 6));
    EXPECT_EQ(0, memcmp(buffer, "567abc", 6));
    /*     w
     * |-de-------|
     *   r
     */
}

// This is a crash I noticed while I was debugging the tap code
TEST_F(Ringbuffer, regression1)
{
    ringbuffer_t ring;
    struct libcouchbase_iovec_st iov[2];
    ring.root = (char*)0x477a80;
    ring.read_head = (char*)0x47b0a3;
    ring.write_head =(char*)0x47b555;
    ring.size = 16384;
    ring.nbytes = 1202;

    ringbuffer_get_iov(&ring, RINGBUFFER_WRITE, iov);
    // up to the end
    EXPECT_EQ(ring.write_head, iov[0].iov_base);
    EXPECT_EQ(1323, iov[0].iov_len);

    // then from the beginning
    EXPECT_EQ(ring.root, iov[1].iov_base);
    EXPECT_EQ(13859, iov[1].iov_len);
}
