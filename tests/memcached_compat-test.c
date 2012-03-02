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
 * Example program showing how to use libcouchbase towards a pure
 * memcached cluster
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcouchbase/couchbase.h>

int main(void)
{
    struct libcouchbase_memcached_st memcached;
    libcouchbase_t instance;
    libcouchbase_error_t err;

    memset(&memcached, 0, sizeof(memcached));
    memcached.serverlist = "localhost:11211;localhost:11212";

    err = libcouchbase_create_compat(LIBCOUCHBASE_MEMCACHED_CLUSTER, &memcached,
                                     &instance, NULL);

    if (err != LIBCOUCHBASE_SUCCESS) {
        fprintf(stderr,
                "Failed to create an instance for a memcached cluster\n");
        exit(EXIT_FAILURE);
    }

    libcouchbase_destroy(instance);
    exit(EXIT_SUCCESS);
}
