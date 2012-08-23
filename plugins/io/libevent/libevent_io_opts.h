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

/**
 * libcouchbase_create_libevent_io_opts() allows you to create an instance
 * of the ioopts that will utilize libevent. You may either supply an event
 * base (if you'd like to add your own events into the loop), or it will
 * create it's own.
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_LIBEVENT_IO_OPTS_H
#define LIBCOUCHBASE_LIBEVENT_IO_OPTS_H 1

#include <libcouchbase/couchbase.h>
#include <event.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Create an instance of an event handler that utilize libevent for
     * event notification.
     *
     * @param base the event base to hook use (please note that you shouldn't
     *             reference the event base from multiple threads)
     * @return a pointer to a newly created and initialized event handler
     */
    LIBCOUCHBASE_API
    struct lcb_io_opt_st *lcb_create_libevent_io_opts(struct event_base *base);

#ifdef __cplusplus
}
#endif

#endif
