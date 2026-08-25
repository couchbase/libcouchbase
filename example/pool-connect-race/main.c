/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2020 Couchbase, Inc.
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
 * Drives a connection pool entry while name resolution is slower than the
 * connect timeout, in the shape that first exposed it: an event base owned by
 * the caller, a polling thread started before the instance and running
 * event_base_loop(EVLOOP_NONBLOCK) throughout, and a bootstrap that resolves
 * through a stalled resolver.
 *
 * getaddrinfo() is defined here rather than preloaded; a definition in the
 * executable satisfies the library's calls too. The address is unroutable, so
 * no server is required and the connect can only end in a timeout.
 *
 * Exit status:
 *   0  the connect timed out and the process survived
 *   1  the process faulted (the defect)
 *   2  the run proved nothing -- the stall or the timeout never happened
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>
#include <libcouchbase/couchbase.h>
#include "libevent_io_opts.h"

#define CONNECT_TIMEOUT_SEC "0.3"
#define RESOLVER_STALL_US 1000000

static struct event_base *base;
static volatile sig_atomic_t polling = 1;

/* Counters. A clean run that did not reach the path is not a clean run. */
static volatile sig_atomic_t n_stalls;
static volatile sig_atomic_t n_config_timeouts;
static volatile sig_atomic_t n_connect_failures;

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    static int (*real)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
    if (real == NULL) {
        *(void **)(&real) = dlsym(RTLD_NEXT, "getaddrinfo");
    }
    if (node != NULL && strcmp(node, "192.0.2.1") == 0) {
        n_stalls++;
        usleep(RESOLVER_STALL_US);
    }
    return real(node, service, hints, res);
}

static void on_fault(int sig, siginfo_t *si, void *uctx)
{
    (void)sig;
    (void)uctx;
    /* Async-signal-safe enough for a reproducer; the address is the finding. */
    fprintf(stderr, "FAULT si_code=%d si_addr=%p\n", si->si_code, si->si_addr);
    _exit(1);
}

static void logger_cb(const lcb_LOGGER *logger, uint64_t iid, const char *subsys, lcb_LOG_SEVERITY severity,
                      const char *srcfile, int srcline, const char *fmt, va_list ap)
{
    char buf[1024];
    (void)logger;
    (void)iid;
    (void)subsys;
    (void)srcfile;
    (void)srcline;
    if (severity < LCB_LOG_ERROR) {
        return;
    }
    vsnprintf(buf, sizeof(buf), fmt, ap);
    if (strstr(buf, "Could not get configuration") != NULL) {
        n_config_timeouts++;
    }
    if (strstr(buf, "Failed to establish connection") != NULL) {
        n_connect_failures++;
    }
    fprintf(stderr, "[lcb] %s\n", buf);
}

static void *poll_loop(void *arg)
{
    (void)arg;
    while (polling) {
        event_base_loop(base, EVLOOP_NONBLOCK);
        usleep(2000);
    }
    return NULL;
}

int main(void)
{
    struct lcb_create_io_ops_st io_opts;
    struct lcb_io_opt_st *io = NULL;
    lcb_CREATEOPTS *opts = NULL;
    lcb_LOGGER *logger = NULL;
    lcb_INSTANCE *instance = NULL;
    struct sigaction sa;
    pthread_t poller;
    const char *connstr = "couchbase://192.0.2.1/default?config_node_timeout=" CONNECT_TIMEOUT_SEC;
    lcb_STATUS rc;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    base = event_base_new();
    memset(&io_opts, 0, sizeof(io_opts));
    io_opts.version = 0;
    io_opts.v.v0.type = LCB_IO_OPS_LIBEVENT;
    io_opts.v.v0.cookie = base;
    rc = lcb_create_io_ops(&io, &io_opts);
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "lcb_create_io_ops: %s\n", lcb_strerror_short(rc));
        return 2;
    }

    /* Started before the instance exists, as the reporting application does. */
    pthread_create(&poller, NULL, poll_loop, NULL);

    lcb_logger_create(&logger, NULL);
    lcb_logger_callback(logger, logger_cb);

    lcb_createopts_create(&opts, LCB_TYPE_BUCKET);
    lcb_createopts_connstr(opts, connstr, strlen(connstr));
    lcb_createopts_credentials(opts, "Administrator", 13, "password", 8);
    lcb_createopts_logger(opts, logger);
    lcb_createopts_io(opts, io);
    rc = lcb_create(&instance, opts);
    lcb_createopts_destroy(opts);
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "lcb_create: %s\n", lcb_strerror_short(rc));
        return 2;
    }

    lcb_connect(instance);
    usleep(500000);

    polling = 0;
    pthread_join(poller, NULL);
    lcb_destroy(instance);
    event_base_free(base);

    fprintf(stderr, "stalls=%d config_timeouts=%d connect_failures=%d\n", (int)n_stalls, (int)n_config_timeouts,
            (int)n_connect_failures);
    if (n_stalls == 0 || n_config_timeouts == 0) {
        fprintf(stderr, "inconclusive: the stalled resolve or the config timeout did not happen\n");
        return 2;
    }
    return 0;
}
