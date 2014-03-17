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
 * Public types and datatypes exported through the libcouchbase API.
 * Please note that libcouchbase should be binary compatible across versions
 * so remember to update the library version numbers if you change any
 * of the values.
 *
 * @author Trond Norbye
 */
#ifndef LIBCOUCHBASE_TYPES_H
#define LIBCOUCHBASE_TYPES_H 1

#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "Include libcouchbase/couchbase.h instead"
#endif

#include <stdarg.h>
#include <libcouchbase/iops.h>

#ifdef __cplusplus
extern "C" {
#endif
    /**
     * Clients of the library should not know the size or the internal
     * layout of the per instance handle. Sharing knowledge about the
     * internal layout makes it a lot harder to keep binary compatibility
     * (if people tries to use it's size etc).
     */
    struct lcb_st;
    typedef struct lcb_st *lcb_t;

    struct lcb_http_request_st;
    typedef struct lcb_http_request_st *lcb_http_request_t;

    struct lcb_timer_st;
    typedef struct lcb_timer_st *lcb_timer_t;


    typedef lcb_uint8_t lcb_datatype_t;

    typedef enum {
        LCB_CONFIGURATION_NEW = 0x00,
        LCB_CONFIGURATION_CHANGED = 0x01,
        LCB_CONFIGURATION_UNCHANGED = 0x02
    } lcb_configuration_t;

    /**
     * Storing an item in couchbase is only one operation with a different
     * set of attributes / constraints.
     */
    typedef enum {
        /** Add the item to the cache, but fail if the object exists alread */
        LCB_ADD = 0x01,
        /** Replace the existing object in the cache */
        LCB_REPLACE = 0x02,
        /** Unconditionally set the object in the cache */
        LCB_SET = 0x03,
        /** Append this object to the existing object */
        LCB_APPEND = 0x04,
        /** Prepend this  object to the existing object */
        LCB_PREPEND = 0x05
    } lcb_storage_t;

    /**
     * Possible statuses for keys in OBSERVE response
     */
    typedef enum {
        /** The item found in the memory, but not yet on the disk */
        LCB_OBSERVE_FOUND = 0x00,
        /** The item hit the disk */
        LCB_OBSERVE_PERSISTED = 0x01,
        /** The item missing on the disk and the memory */
        LCB_OBSERVE_NOT_FOUND = 0x80,
        /** No knowledge of the key :) */
        LCB_OBSERVE_LOGICALLY_DELETED = 0x81,

        LCB_OBSERVE_MAX = 0x82
    } lcb_observe_t;

    typedef enum {
        /** Use bucket name and setup config listener */
        LCB_TYPE_BUCKET = 0x00,
        /** Ignore bucket name. All data calls will return LCB_NOT_SUPPORTED */
        LCB_TYPE_CLUSTER = 0x01
    } lcb_type_t;


    typedef enum {
        LCB_IO_OPS_INVALID = 0x00,
        LCB_IO_OPS_DEFAULT = 0x01,
        LCB_IO_OPS_LIBEVENT = 0x02,
        LCB_IO_OPS_WINSOCK = 0x03,
        LCB_IO_OPS_LIBEV = 0x04,
        LCB_IO_OPS_SELECT = 0x05,
        LCB_IO_OPS_WINIOCP = 0x06,
        LCB_IO_OPS_LIBUV = 0x07
    } lcb_io_ops_type_t;

    typedef enum {
        LCB_VBUCKET_STATE_ACTIVE = 1,   /* Actively servicing a vbucket. */
        LCB_VBUCKET_STATE_REPLICA = 2,  /* Servicing a vbucket as a replica only. */
        LCB_VBUCKET_STATE_PENDING = 3,  /* Pending active. */
        LCB_VBUCKET_STATE_DEAD = 4      /* Not in use, pending deletion. */
    } lcb_vbucket_state_t;

    typedef enum {
        LCB_VERBOSITY_DETAIL = 0x00,
        LCB_VERBOSITY_DEBUG = 0x01,
        LCB_VERBOSITY_INFO = 0x02,
        LCB_VERBOSITY_WARNING = 0x03
    } lcb_verbosity_level_t;

    typedef enum {
        LCB_IPV6_DISABLED = 0x00,
        LCB_IPV6_ONLY = 0x1,
        LCB_IPV6_ALLOW = 0x02
    } lcb_ipv6_t;


    /**
     * LOGGING:
     * Verbose logging may be enabled by default using the environment variable
     * LCB_LOGLEVEL and setting it to a number > 1; higher values produce more
     * verbose output.
     * You may also install your own logger using lcb_cntl and the
     * LCB_CNTL_LOGGER constant. Note that
     * the logger functions will not be called rapidly from within hot paths.
     */

    typedef enum {
        LCB_LOG_TRACE = 0,
        LCB_LOG_DEBUG,
        LCB_LOG_INFO,
        LCB_LOG_WARN,
        LCB_LOG_ERROR,
        LCB_LOG_FATAL,
        LCB_LOG_MAX
    } lcb_log_severity_t;

    struct lcb_logprocs_st;

    /**
     * VOLATILE!
     *
     * This callback is invoked for each logging message emitted
     * @param procs the logging structure provided
     * @param subsys a string describing the module which emitted the message
     * @param severity one of the LCB_LOG_* severity constants.
     * @param srcfile the source file which emitted this message
     * @param srcline the line of the file for the message
     * @param fmt a printf format string
     * @param ap a va_list for vprintf
     */
    typedef void (*lcb_logging_callback)(struct lcb_logprocs_st *procs,
                                          const char *subsys,
                                          int severity,
                                          const char *srcfile,
                                          int srcline,
                                          const char *fmt,
                                          va_list ap);

    /**
     * VOLATILE!
     * This structure defines the logging handlers. Currently there is only
     * a single field defined which is the default callback for the loggers.
     * This API may change.
     */
    typedef struct lcb_logprocs_st {
        int version;
        union {
            struct {
                lcb_logging_callback callback;
            } v0;
        } v;
    } lcb_logprocs;

    typedef enum {
        /** End of list for the config_transports array */
        LCB_CONFIG_TRANSPORT_LIST_END = 0,

        /** Use the HTTP (aka "REST API") connection for configuration */
        LCB_CONFIG_TRANSPORT_HTTP = 1,

        /** Use the memcached bootstrap protocol (Servers 2.5+ only) */
        LCB_CONFIG_TRANSPORT_CCCP

    } lcb_config_transport_t;


#ifdef __cplusplus
}
#endif

#endif
