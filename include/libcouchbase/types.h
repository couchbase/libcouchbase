/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011 Couchbase, Inc.
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


    typedef uint8_t lcb_datatype_t;

    /**
     * Define the error codes in use by the library
     */
    typedef enum {
        LCB_SUCCESS = 0x00,
        LCB_AUTH_CONTINUE = 0x01,
        LCB_AUTH_ERROR = 0x02,
        LCB_DELTA_BADVAL = 0x03,
        LCB_E2BIG = 0x04,
        LCB_EBUSY = 0x05,
        LCB_EINTERNAL = 0x06,
        LCB_EINVAL = 0x07,
        LCB_ENOMEM = 0x08,
        LCB_ERANGE = 0x09,
        LCB_ERROR = 0x0a,
        LCB_ETMPFAIL = 0x0b,
        LCB_KEY_EEXISTS = 0x0c,
        LCB_KEY_ENOENT = 0x0d,
        LCB_LIBEVENT_ERROR = 0x0e,
        LCB_NETWORK_ERROR = 0x0f,
        LCB_NOT_MY_VBUCKET = 0x10,
        LCB_NOT_STORED = 0x11,
        LCB_NOT_SUPPORTED = 0x12,
        LCB_UNKNOWN_COMMAND = 0x13,
        LCB_UNKNOWN_HOST = 0x14,
        LCB_PROTOCOL_ERROR = 0x15,
        LCB_ETIMEDOUT = 0x16,
        LCB_CONNECT_ERROR = 0x17,
        LCB_BUCKET_ENOENT = 0x18,
        LCB_CLIENT_ENOMEM = 0x19
    } lcb_error_t;

#define lcb_is_error_enomem(a) ((a == LCB_CLIENT_ENOMEM) || \
                                (a == LCB_ENOMEM))

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

    struct  lcb_tap_filter_st;
    typedef struct lcb_tap_filter_st *lcb_tap_filter_t;

#ifdef _WIN32
    typedef SOCKET lcb_socket_t;
#else
    typedef int lcb_socket_t;
#endif

    typedef enum {
        LCB_IO_OPS_DEFAULT = 0x01,
        LCB_IO_OPS_LIBEVENT = 0x02,
        LCB_IO_OPS_WINSOCK = 0x03
    } lcb_io_ops_type_t;

#define LCB_READ_EVENT 0x02
#define LCB_WRITE_EVENT 0x04
#define LCB_RW_EVENT (LCB_READ_EVENT|LCB_WRITE_EVENT)

    typedef enum {
        LCB_HTTP_TYPE_VIEW = 0,
        LCB_HTTP_TYPE_MANAGEMENT,
        LCB_HTTP_TYPE_MAX
    } lcb_http_type_t;

    typedef enum {
        LCB_HTTP_METHOD_GET = 0,
        LCB_HTTP_METHOD_POST,
        LCB_HTTP_METHOD_PUT,
        LCB_HTTP_METHOD_DELETE,
        LCB_HTTP_METHOD_MAX
    } lcb_http_method_t;

    typedef enum {
        LCB_HTTP_STATUS_CONTINUE = 100,
        LCB_HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
        LCB_HTTP_STATUS_PROCESSING = 102,
        LCB_HTTP_STATUS_OK = 200,
        LCB_HTTP_STATUS_CREATED = 201,
        LCB_HTTP_STATUS_ACCEPTED = 202,
        LCB_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
        LCB_HTTP_STATUS_NO_CONTENT = 204,
        LCB_HTTP_STATUS_RESET_CONTENT = 205,
        LCB_HTTP_STATUS_PARTIAL_CONTENT = 206,
        LCB_HTTP_STATUS_MULTI_STATUS = 207,
        LCB_HTTP_STATUS_MULTIPLE_CHOICES = 300,
        LCB_HTTP_STATUS_MOVED_PERMANENTLY = 301,
        LCB_HTTP_STATUS_FOUND = 302,
        LCB_HTTP_STATUS_SEE_OTHER = 303,
        LCB_HTTP_STATUS_NOT_MODIFIED = 304,
        LCB_HTTP_STATUS_USE_PROXY = 305,
        LCB_HTTP_STATUS_UNUSED = 306,
        LCB_HTTP_STATUS_TEMPORARY_REDIRECT = 307,
        LCB_HTTP_STATUS_BAD_REQUEST = 400,
        LCB_HTTP_STATUS_UNAUTHORIZED = 401,
        LCB_HTTP_STATUS_PAYMENT_REQUIRED = 402,
        LCB_HTTP_STATUS_FORBIDDEN = 403,
        LCB_HTTP_STATUS_NOT_FOUND = 404,
        LCB_HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
        LCB_HTTP_STATUS_NOT_ACCEPTABLE = 406,
        LCB_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
        LCB_HTTP_STATUS_REQUEST_TIMEOUT = 408,
        LCB_HTTP_STATUS_CONFLICT = 409,
        LCB_HTTP_STATUS_GONE = 410,
        LCB_HTTP_STATUS_LENGTH_REQUIRED = 411,
        LCB_HTTP_STATUS_PRECONDITION_FAILED = 412,
        LCB_HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE = 413,
        LCB_HTTP_STATUS_REQUEST_URI_TOO_LONG = 414,
        LCB_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
        LCB_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
        LCB_HTTP_STATUS_EXPECTATION_FAILED = 417,
        LCB_HTTP_STATUS_UNPROCESSABLE_ENTITY = 422,
        LCB_HTTP_STATUS_LOCKED = 423,
        LCB_HTTP_STATUS_FAILED_DEPENDENCY = 424,
        LCB_HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
        LCB_HTTP_STATUS_NOT_IMPLEMENTED = 501,
        LCB_HTTP_STATUS_BAD_GATEWAY = 502,
        LCB_HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
        LCB_HTTP_STATUS_GATEWAY_TIMEOUT = 504,
        LCB_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
        LCB_HTTP_STATUS_INSUFFICIENT_STORAGE = 507
    } lcb_http_status_t;

    typedef enum {
        LCB_VBUCKET_STATE_ACTIVE = 1,   /* Actively servicing a vbucket. */
        LCB_VBUCKET_STATE_REPLICA,      /* Servicing a vbucket as a replica only. */
        LCB_VBUCKET_STATE_PENDING,      /* Pending active. */
        LCB_VBUCKET_STATE_DEAD          /* Not in use, pending deletion. */
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
        lcb_uint64_t version;
        void *cookie;
        int error;

        void (*destructor)(struct lcb_io_opt_st *iops);

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

        /* Version 1 of the struct also includes the following members */
        void *dlhandle;
    };
    typedef struct lcb_io_opt_st* lcb_io_opt_t;

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
