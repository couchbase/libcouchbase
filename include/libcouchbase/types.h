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
        LCB_OBSERVE_MAX = 0x81
    } lcb_observe_t;

    typedef enum {
        /** Use bucket name and setup config listener */
        LCB_TYPE_BUCKET = 0x00,
        /** Ignore bucket name. All data calls will return LCB_NOT_SUPPORTED */
        LCB_TYPE_CLUSTER = 0x01
    } lcb_type_t;

#if defined(_WIN32) && defined(SOCKET)
    typedef SOCKET lcb_socket_t;
#else
    typedef int lcb_socket_t;
#endif

    typedef enum {
        LCB_IO_OPS_DEFAULT = 0x01,
        LCB_IO_OPS_LIBEVENT = 0x02,
        LCB_IO_OPS_WINSOCK = 0x03,
        LCB_IO_OPS_LIBEV = 0x04
    } lcb_io_ops_type_t;

#define LCB_READ_EVENT 0x02
#define LCB_WRITE_EVENT 0x04
#define LCB_RW_EVENT (LCB_READ_EVENT|LCB_WRITE_EVENT)

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

    struct sockaddr;

    struct lcb_iovec_st {
        char *iov_base;
        lcb_size_t iov_len;
    };

    struct lcb_io_opt_st {
        int version;
        void *dlhandle;
        void (*destructor)(struct lcb_io_opt_st *iops);
        union {
            struct {
                void *cookie;
                int error;
                int need_cleanup;

                /**
                 * Create a non-blocking socket.
                 */
                lcb_socket_t (*socket)(struct lcb_io_opt_st *iops,
                                       int domain,
                                       int type,
                                       int protocol);
                int (*connect)(struct lcb_io_opt_st *iops,
                               lcb_socket_t sock,
                               const struct sockaddr *name,
                               unsigned int namelen);
                lcb_ssize_t (*recv)(struct lcb_io_opt_st *iops,
                                    lcb_socket_t sock,
                                    void *buffer,
                                    lcb_size_t len,
                                    int flags);
                lcb_ssize_t (*send)(struct lcb_io_opt_st *iops,
                                    lcb_socket_t sock,
                                    const void *msg,
                                    lcb_size_t len,
                                    int flags);
                lcb_ssize_t (*recvv)(struct lcb_io_opt_st *iops,
                                     lcb_socket_t sock,
                                     struct lcb_iovec_st *iov,
                                     lcb_size_t niov);
                lcb_ssize_t (*sendv)(struct lcb_io_opt_st *iops,
                                     lcb_socket_t sock,
                                     struct lcb_iovec_st *iov,
                                     lcb_size_t niov);
                void (*close)(struct lcb_io_opt_st *iops,
                              lcb_socket_t sock);
                void *(*create_timer)(struct lcb_io_opt_st *iops);
                void (*destroy_timer)(struct lcb_io_opt_st *iops,
                                      void *timer);
                void (*delete_timer)(struct lcb_io_opt_st *iops,
                                     void *timer);
                int (*update_timer)(struct lcb_io_opt_st *iops,
                                    void *timer,
                                    lcb_uint32_t usec,
                                    void *cb_data,
                                    void (*handler)(lcb_socket_t sock,
                                                    short which,
                                                    void *cb_data));
                void *(*create_event)(struct lcb_io_opt_st *iops);
                void (*destroy_event)(struct lcb_io_opt_st *iops,
                                      void *event);
                int (*update_event)(struct lcb_io_opt_st *iops,
                                    lcb_socket_t sock,
                                    void *event,
                                    short flags,
                                    void *cb_data,
                                    void (*handler)(lcb_socket_t sock,
                                                    short which,
                                                    void *cb_data));
                void (*delete_event)(struct lcb_io_opt_st *iops,
                                     lcb_socket_t sock,
                                     void *event);
                void (*stop_event_loop)(struct lcb_io_opt_st *iops);
                void (*run_event_loop)(struct lcb_io_opt_st *iops);
            } v0;
        } v;
    };
    typedef struct lcb_io_opt_st *lcb_io_opt_t;

    typedef enum {
        LCB_ASYNCHRONOUS = 0x00,
        LCB_SYNCHRONOUS = 0xff
    } lcb_syncmode_t;

    typedef enum {
        LCB_IPV6_DISABLED = 0x00,
        LCB_IPV6_ONLY = 0x1,
        LCB_IPV6_ALLOW = 0x02
    } lcb_ipv6_t;

#ifdef __cplusplus
}
#endif

#endif
