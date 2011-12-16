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
#ifndef LIBCOUCHBASE_TEST_SERVER_H
#define LIBCOUCHBASE_TEST_SERVER_H 1

#include <stdbool.h>

const void *start_mock_server(char **cmdline);
const char *get_mock_http_server(const void *);
void shutdown_mock_server(const void *);

void failover_node(const void *handle, int idx, const char *bucket);
void respawn_node(const void *handle, int idx, const char *bucket);

#endif
