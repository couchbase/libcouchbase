/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2012 Couchbase, Inc.
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
 * libcouchbase_create_winsock_io_opts() allows you to create an instance
 * of the ioopts that will utilize windows sockets (and use windows events
 * as a notification). It is currently not possible to plug it into another
 * event loop.
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_WINSOCK_IO_OPTS_H
#define LIBCOUCHBASE_WINSOCK_IO_OPTS_H 1

#include <libcouchbase/couchbase.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Create an instance of an event handler that utilize winsock for
     * event notification.
     *
     * @return a pointer to a newly created and initialized event handler
     */
    LIBCOUCHBASE_API
    struct lcb_io_opt_st *lcb_create_winsock_io_opts(void);

#ifdef __cplusplus
}
#endif

#endif
