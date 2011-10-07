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
#include <stdbool.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcouchbase/couchbase.h>
#include "ringbuffer.h"

static void err_exit(const char *msg) {
    fprintf(stderr, "%s\n", msg);
#ifdef DO_ABORT
    abort();
#else
    exit(EXIT_FAILURE);
#endif
}

int main(int argc, char **argv)
{
    ringbuffer_t ring;
    char buffer[1024];
    int ii;

    if (!libcouchbase_ringbuffer_initialize(&ring, 16)) {
        err_exit("Failed to create a 16 byte ringbuffer");
    }

    if (libcouchbase_ringbuffer_read(&ring, buffer, 1) != 0) {
        err_exit("Read from an empty buffer should return 0");
    }

    if (libcouchbase_ringbuffer_write(&ring, "01234567891234567", 17) != 16) {
        err_exit("Buffer overflow!!!");
    }

    for (ii = 0; ii < 2; ++ii) {
        memset(buffer, 0, sizeof(buffer));
        if (libcouchbase_ringbuffer_peek(&ring, buffer, 16) != 16 ||
            memcmp(buffer, "01234567891234567", 16) != 0) {
            err_exit("We just filled the buffer with 16 bytes.. peek failed");
        }
    }

    if (libcouchbase_ringbuffer_read(&ring, buffer, 16) != 16) {
        err_exit("We just filled the buffer with 16 bytes");
    }

    if (libcouchbase_ringbuffer_read(&ring, buffer, 1) != 0) {
        err_exit("Read from an empty buffer should return 0");
    }

    if (libcouchbase_ringbuffer_write(&ring, "01234567891234567", 17) != 16) {
        err_exit("Buffer overflow!!!");
    }

    if (libcouchbase_ringbuffer_read(&ring, buffer, 8) != 8) {
        err_exit("We just filled the buffer with 16 bytes");
    }

    if (!libcouchbase_ringbuffer_ensure_capacity(&ring, 9)) {
        err_exit("I failed to grow the buffer");
    }

    if (ring.size != 32) {
        err_exit("The buffers should double in size");
    }

    if (ring.read_head != ring.root) {
        err_exit("I expected the data to be realigned");
    }

    if (libcouchbase_ringbuffer_read(&ring, buffer, 8) != 8) {
        err_exit("We should still have 8 bytes left");
    }

    if (memcmp(buffer, "89123456", 8) != 0) {
        err_exit("I'm not getting the data I'm expecting...");
    }


    return 0;
}
