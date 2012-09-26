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
#define LCB_TEST_REALCLUSTER_ENV "LCB_TEST_CLUSTER_CONF"

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

    struct test_server_info {
        pid_t pid;
        char *http;
        char *bucket;
        char *username;
        char *password;
        in_port_t port;
        struct sockaddr_storage storage;
        int sock;
        int client;
        int is_mock;
    };


    const void *start_test_server(char **cmdline);
    const char *get_mock_http_server(const void *);
    void get_mock_std_creds(const void *handle, const char **userp, const char **passp);
    int is_using_real_cluster(void);

    void shutdown_mock_server(const void *);

    void failover_node(const void *handle, int idx, const char *bucket);
    void respawn_node(const void *handle, int idx, const char *bucket);

    struct lcb_io_opt_st *get_test_io_opts(void);

#ifdef __cplusplus
}
#endif

#endif
