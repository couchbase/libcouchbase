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
#include "server.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <ctype.h>

#include <event.h>

#ifdef linux
#undef ntohs
#undef ntohl
#undef htons
#undef htonl
#endif

struct mock_server_info {
    pid_t pid;
    char *http;
    in_port_t port;
    struct sockaddr_storage storage;
    int sock;
    int client;
};

static bool create_monitor(struct mock_server_info *info) {
    struct addrinfo hints = { .ai_flags = AI_PASSIVE,
                              .ai_family = AF_UNSPEC,
                              .ai_socktype = SOCK_STREAM };
    info->sock = -1;

    struct addrinfo *ai;
    int error = getaddrinfo(NULL, "0", &hints, &ai);
    if (error != 0) {
        if (error != EAI_SYSTEM) {
            fprintf(stderr, "getaddrinfo failed: %s\n",
                    gai_strerror(error));
        } else {
            perror("getaddrinfo failed:");
        }
        return false;
    }

    for (struct addrinfo *next = ai; next; next = next->ai_next) {
        if ((info->sock = socket(next->ai_family,
                                 next->ai_socktype,
                                 next->ai_protocol)) == -1) {
            continue;
        }

        int flags = 1;
        setsockopt(info->sock, SOL_SOCKET, SO_REUSEADDR,
                   (void *)&flags, sizeof(flags));

        if (bind(info->sock, next->ai_addr, next->ai_addrlen) == -1) {
            close(info->sock);
            info->sock = -1;
            continue;
        } else if (listen(info->sock, 10) == -1) {
            close(info->sock);
            info->sock = -1;
            continue;
        }

        // Ok, I've got a working socket :)
        socklen_t len = sizeof(info->storage);
        if (getsockname(info->sock, (struct sockaddr*)&info->storage, &len) == -1) {
            close(info->sock);
            info->sock = -1;
            continue;
        }
        if (next->ai_addr->sa_family == AF_INET) {
            info->port = ntohs((*(struct sockaddr_in *)&info->storage).sin_port);
        } else {
            info->port = ntohs((*(struct sockaddr_in6 *)&info->storage).sin6_port);
        }
    }

    freeaddrinfo(ai);
    return info->sock != -1;
}


static void wait_for_server(const char *port) {
    struct addrinfo hints = { .ai_flags = AI_PASSIVE,
                              .ai_family = AF_UNSPEC,
                              .ai_socktype = SOCK_STREAM };
    int sock = -1;

    struct addrinfo *ai;
    int error = getaddrinfo("localhost", port, &hints, &ai);
    if (error != 0) {
        if (error != EAI_SYSTEM) {
            fprintf(stderr, "getaddrinfo failed: %s\n",
                    gai_strerror(error));
        } else {
            perror("getaddrinfo failed:");
        }
        abort();
    }

    while (true) {
        for (struct addrinfo *next = ai; next; next = next->ai_next) {
            if ((sock = socket(next->ai_family,
                               next->ai_socktype,
                               next->ai_protocol)) == -1) {
                continue;
            }

            if (connect(sock, next->ai_addr, next->ai_addrlen) == 0) {
                close(sock);
                freeaddrinfo(ai);
                return;
            }

            close(sock);
        }
        usleep(250);
    }
}

const void *start_mock_server(char **cmdline) {
    struct mock_server_info *info = calloc(1, sizeof(*info));
    if (info == NULL) {
        return NULL;
    }

    if (!create_monitor(info)) {
        free(info);
        return NULL;
    }

    info->pid = fork();
    assert(info->pid != -1);

    if (info->pid == 0) {
        /* Child */
        char *argv[1024];
        int arg = 0;
        argv[arg++] = (char*)"./tests/start_mock.sh";
        char monitor[1024];
        sprintf(monitor, "--harakiri-monitor=localhost:%d", info->port);
        argv[arg++] = monitor;

        if (cmdline != NULL) {
            int ii = 0;
            while (cmdline[ii] != NULL && arg < 1022) {
                argv[arg++] = cmdline[ii++];
            }
        }

        argv[arg++] = NULL;
        assert(execv(argv[0], argv) != -1);
    }

    // wait until the server connects
    info->client = accept(info->sock, NULL, NULL);
    assert(info->client != -1);
    // Get the port number of the http server
    char buffer[1024];
    ssize_t offset = snprintf(buffer, sizeof(buffer), "localhost:");
    ssize_t nr = recv(info->client, buffer + offset, sizeof(buffer) - (size_t)offset - 1, 0);
    assert(nr > 0);
    buffer[nr + offset] = '\0';
    info->http = strdup(buffer);
    wait_for_server(buffer + offset);
    return info;
}

void shutdown_mock_server(const void *handle) {
    struct mock_server_info *info = (void*)handle;
    free(info->http);
    close(info->client);
    close(info->sock);
    kill(info->pid, SIGTERM);
    free((void*)handle);
}

const char* get_mock_http_server(const void *handle) {
    struct mock_server_info *info = (void*)handle;
    return info->http;
}
