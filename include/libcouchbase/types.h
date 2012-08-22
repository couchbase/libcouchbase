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
    struct libcouchbase_st;
    typedef struct libcouchbase_st *libcouchbase_t;

    struct libcouchbase_http_request_st;
    typedef struct libcouchbase_http_request_st *libcouchbase_http_request_t;

    struct libcouchbase_timer_st;
    typedef struct libcouchbase_timer_st *libcouchbase_timer_t;


    typedef uint8_t libcouchbase_datatype_t;

    struct libcouchbase_item_st {
        int version; /* struct layout version */
        union {
            struct {
                const void *key;
                libcouchbase_size_t nkey;
                const void *bytes;
                libcouchbase_size_t nbytes;
                libcouchbase_uint32_t flags;
                libcouchbase_cas_t cas;
                libcouchbase_datatype_t datatype;
            } v0;
        };
    };

    /**
     * Define the error codes in use by the library
     */
    typedef enum {
        LIBCOUCHBASE_SUCCESS = 0x00,
        LIBCOUCHBASE_AUTH_CONTINUE = 0x01,
        LIBCOUCHBASE_AUTH_ERROR = 0x02,
        LIBCOUCHBASE_DELTA_BADVAL = 0x03,
        LIBCOUCHBASE_E2BIG = 0x04,
        LIBCOUCHBASE_EBUSY = 0x05,
        LIBCOUCHBASE_EINTERNAL = 0x06,
        LIBCOUCHBASE_EINVAL = 0x07,
        LIBCOUCHBASE_ENOMEM = 0x08,
        LIBCOUCHBASE_ERANGE = 0x09,
        LIBCOUCHBASE_ERROR = 0x0a,
        LIBCOUCHBASE_ETMPFAIL = 0x0b,
        LIBCOUCHBASE_KEY_EEXISTS = 0x0c,
        LIBCOUCHBASE_KEY_ENOENT = 0x0d,
        LIBCOUCHBASE_LIBEVENT_ERROR = 0x0e,
        LIBCOUCHBASE_NETWORK_ERROR = 0x0f,
        LIBCOUCHBASE_NOT_MY_VBUCKET = 0x10,
        LIBCOUCHBASE_NOT_STORED = 0x11,
        LIBCOUCHBASE_NOT_SUPPORTED = 0x12,
        LIBCOUCHBASE_UNKNOWN_COMMAND = 0x13,
        LIBCOUCHBASE_UNKNOWN_HOST = 0x14,
        LIBCOUCHBASE_PROTOCOL_ERROR = 0x15,
        LIBCOUCHBASE_ETIMEDOUT = 0x16,
        LIBCOUCHBASE_CONNECT_ERROR = 0x17,
        LIBCOUCHBASE_BUCKET_ENOENT = 0x18,
        LIBCOUCHBASE_CLIENT_ENOMEM = 0x19
    } libcouchbase_error_t;

#define libcouchbase_is_error_enomem(a) ((a == LIBCOUCHBASE_CLIENT_ENOMEM) || \
                                         (a == LIBCOUCHBASE_ENOMEM))

    typedef enum {
        LIBCOUCHBASE_CONFIGURATION_NEW = 0x00,
        LIBCOUCHBASE_CONFIGURATION_CHANGED = 0x01,
        LIBCOUCHBASE_CONFIGURATION_UNCHANGED = 0x02
    } libcouchbase_configuration_t;

    /**
     * Storing an item in couchbase is only one operation with a different
     * set of attributes / constraints.
     */
    typedef enum {
        /** Add the item to the cache, but fail if the object exists alread */
        LIBCOUCHBASE_ADD = 0x01,
        /** Replace the existing object in the cache */
        LIBCOUCHBASE_REPLACE = 0x02,
        /** Unconditionally set the object in the cache */
        LIBCOUCHBASE_SET = 0x03,
        /** Append this object to the existing object */
        LIBCOUCHBASE_APPEND = 0x04,
        /** Prepend this  object to the existing object */
        LIBCOUCHBASE_PREPEND = 0x05
    } libcouchbase_storage_t;

    /**
     * Possible statuses for keys in OBSERVE response
     */
    typedef enum {
        /** The item found in the memory, but not yet on the disk */
        LIBCOUCHBASE_OBSERVE_FOUND = 0x00,
        /** The item hit the disk */
        LIBCOUCHBASE_OBSERVE_PERSISTED = 0x01,
        /** The item missing on the disk and the memory */
        LIBCOUCHBASE_OBSERVE_NOT_FOUND = 0x80,
        LIBCOUCHBASE_OBSERVE_MAX = 0x81
    } libcouchbase_observe_t;

    struct  libcouchbase_tap_filter_st;
    typedef struct libcouchbase_tap_filter_st *libcouchbase_tap_filter_t;

#ifdef _WIN32
    typedef SOCKET libcouchbase_socket_t;
#else
    typedef int libcouchbase_socket_t;
#endif

    typedef enum {
        LIBCOUCHBASE_IO_OPS_DEFAULT = 0x01,
        LIBCOUCHBASE_IO_OPS_LIBEVENT = 0x02,
        LIBCOUCHBASE_IO_OPS_WINSOCK = 0x03
    } libcouchbase_io_ops_type_t;

#define LIBCOUCHBASE_READ_EVENT 0x02
#define LIBCOUCHBASE_WRITE_EVENT 0x04
#define LIBCOUCHBASE_RW_EVENT (LIBCOUCHBASE_READ_EVENT|LIBCOUCHBASE_WRITE_EVENT)

    typedef enum {
        LIBCOUCHBASE_HTTP_TYPE_VIEW = 0,
        LIBCOUCHBASE_HTTP_TYPE_MANAGEMENT,
        LIBCOUCHBASE_HTTP_TYPE_MAX
    } libcouchbase_http_type_t;

    typedef enum {
        LIBCOUCHBASE_HTTP_METHOD_GET = 0,
        LIBCOUCHBASE_HTTP_METHOD_POST,
        LIBCOUCHBASE_HTTP_METHOD_PUT,
        LIBCOUCHBASE_HTTP_METHOD_DELETE,
        LIBCOUCHBASE_HTTP_METHOD_MAX
    } libcouchbase_http_method_t;

    typedef enum {
        LIBCOUCHBASE_HTTP_STATUS_CONTINUE = 100,
        LIBCOUCHBASE_HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
        LIBCOUCHBASE_HTTP_STATUS_PROCESSING = 102,
        LIBCOUCHBASE_HTTP_STATUS_OK = 200,
        LIBCOUCHBASE_HTTP_STATUS_CREATED = 201,
        LIBCOUCHBASE_HTTP_STATUS_ACCEPTED = 202,
        LIBCOUCHBASE_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
        LIBCOUCHBASE_HTTP_STATUS_NO_CONTENT = 204,
        LIBCOUCHBASE_HTTP_STATUS_RESET_CONTENT = 205,
        LIBCOUCHBASE_HTTP_STATUS_PARTIAL_CONTENT = 206,
        LIBCOUCHBASE_HTTP_STATUS_MULTI_STATUS = 207,
        LIBCOUCHBASE_HTTP_STATUS_MULTIPLE_CHOICES = 300,
        LIBCOUCHBASE_HTTP_STATUS_MOVED_PERMANENTLY = 301,
        LIBCOUCHBASE_HTTP_STATUS_FOUND = 302,
        LIBCOUCHBASE_HTTP_STATUS_SEE_OTHER = 303,
        LIBCOUCHBASE_HTTP_STATUS_NOT_MODIFIED = 304,
        LIBCOUCHBASE_HTTP_STATUS_USE_PROXY = 305,
        LIBCOUCHBASE_HTTP_STATUS_UNUSED = 306,
        LIBCOUCHBASE_HTTP_STATUS_TEMPORARY_REDIRECT = 307,
        LIBCOUCHBASE_HTTP_STATUS_BAD_REQUEST = 400,
        LIBCOUCHBASE_HTTP_STATUS_UNAUTHORIZED = 401,
        LIBCOUCHBASE_HTTP_STATUS_PAYMENT_REQUIRED = 402,
        LIBCOUCHBASE_HTTP_STATUS_FORBIDDEN = 403,
        LIBCOUCHBASE_HTTP_STATUS_NOT_FOUND = 404,
        LIBCOUCHBASE_HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
        LIBCOUCHBASE_HTTP_STATUS_NOT_ACCEPTABLE = 406,
        LIBCOUCHBASE_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
        LIBCOUCHBASE_HTTP_STATUS_REQUEST_TIMEOUT = 408,
        LIBCOUCHBASE_HTTP_STATUS_CONFLICT = 409,
        LIBCOUCHBASE_HTTP_STATUS_GONE = 410,
        LIBCOUCHBASE_HTTP_STATUS_LENGTH_REQUIRED = 411,
        LIBCOUCHBASE_HTTP_STATUS_PRECONDITION_FAILED = 412,
        LIBCOUCHBASE_HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE = 413,
        LIBCOUCHBASE_HTTP_STATUS_REQUEST_URI_TOO_LONG = 414,
        LIBCOUCHBASE_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
        LIBCOUCHBASE_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
        LIBCOUCHBASE_HTTP_STATUS_EXPECTATION_FAILED = 417,
        LIBCOUCHBASE_HTTP_STATUS_UNPROCESSABLE_ENTITY = 422,
        LIBCOUCHBASE_HTTP_STATUS_LOCKED = 423,
        LIBCOUCHBASE_HTTP_STATUS_FAILED_DEPENDENCY = 424,
        LIBCOUCHBASE_HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
        LIBCOUCHBASE_HTTP_STATUS_NOT_IMPLEMENTED = 501,
        LIBCOUCHBASE_HTTP_STATUS_BAD_GATEWAY = 502,
        LIBCOUCHBASE_HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
        LIBCOUCHBASE_HTTP_STATUS_GATEWAY_TIMEOUT = 504,
        LIBCOUCHBASE_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
        LIBCOUCHBASE_HTTP_STATUS_INSUFFICIENT_STORAGE = 507
    } libcouchbase_http_status_t;

    typedef enum {
        LIBCOUCHBASE_VBUCKET_STATE_ACTIVE = 1,   /* Actively servicing a vbucket. */
        LIBCOUCHBASE_VBUCKET_STATE_REPLICA,      /* Servicing a vbucket as a replica only. */
        LIBCOUCHBASE_VBUCKET_STATE_PENDING,      /* Pending active. */
        LIBCOUCHBASE_VBUCKET_STATE_DEAD          /* Not in use, pending deletion. */
    } libcouchbase_vbucket_state_t;

    typedef enum {
        LIBCOUCHBASE_VERBOSITY_DETAIL = 0x00,
        LIBCOUCHBASE_VERBOSITY_DEBUG = 0x01,
        LIBCOUCHBASE_VERBOSITY_INFO = 0x02,
        LIBCOUCHBASE_VERBOSITY_WARNING = 0x03
    } libcouchbase_verbosity_level_t;

    struct sockaddr;

    struct libcouchbase_iovec_st {
        char *iov_base;
        libcouchbase_size_t iov_len;
    };

    typedef struct libcouchbase_io_opt_st {
        libcouchbase_uint64_t version;
        void *cookie;
        int error;

        void (*destructor)(struct libcouchbase_io_opt_st *iops);

        /**
         * Create a non-blocking socket.
         */
        libcouchbase_socket_t (*socket)(struct libcouchbase_io_opt_st *iops,
                                        int domain,
                                        int type,
                                        int protocol);
        int (*connect)(struct libcouchbase_io_opt_st *iops,
                       libcouchbase_socket_t sock,
                       const struct sockaddr *name,
                       unsigned int namelen);

        libcouchbase_ssize_t (*recv)(struct libcouchbase_io_opt_st *iops,
                                     libcouchbase_socket_t sock,
                                     void *buffer,
                                     libcouchbase_size_t len,
                                     int flags);
        libcouchbase_ssize_t (*send)(struct libcouchbase_io_opt_st *iops,
                                     libcouchbase_socket_t sock,
                                     const void *msg,
                                     libcouchbase_size_t len,
                                     int flags);

        libcouchbase_ssize_t (*recvv)(struct libcouchbase_io_opt_st *iops,
                                      libcouchbase_socket_t sock,
                                      struct libcouchbase_iovec_st *iov,
                                      libcouchbase_size_t niov);

        libcouchbase_ssize_t (*sendv)(struct libcouchbase_io_opt_st *iops,
                                      libcouchbase_socket_t sock,
                                      struct libcouchbase_iovec_st *iov,
                                      libcouchbase_size_t niov);


        void (*close)(struct libcouchbase_io_opt_st *iops,
                      libcouchbase_socket_t sock);

        void *(*create_timer)(struct libcouchbase_io_opt_st *iops);
        void (*destroy_timer)(struct libcouchbase_io_opt_st *iops,
                              void *timer);
        void (*delete_timer)(struct libcouchbase_io_opt_st *iops,
                             void *timer);
        int (*update_timer)(struct libcouchbase_io_opt_st *iops,
                            void *timer,
                            libcouchbase_uint32_t usec,
                            void *cb_data,
                            void (*handler)(libcouchbase_socket_t sock,
                                            short which,
                                            void *cb_data));

        void *(*create_event)(struct libcouchbase_io_opt_st *iops);
        void (*destroy_event)(struct libcouchbase_io_opt_st *iops,
                              void *event);

        int (*update_event)(struct libcouchbase_io_opt_st *iops,
                            libcouchbase_socket_t sock,
                            void *event,
                            short flags,
                            void *cb_data,
                            void (*handler)(libcouchbase_socket_t sock,
                                            short which,
                                            void *cb_data));

        void (*delete_event)(struct libcouchbase_io_opt_st *iops,
                             libcouchbase_socket_t sock,
                             void *event);

        void (*stop_event_loop)(struct libcouchbase_io_opt_st *iops);
        void (*run_event_loop)(struct libcouchbase_io_opt_st *iops);

        /* Version 1 of the struct also includes the following members */
        void *dlhandle;
    } libcouchbase_io_opt_t;

    typedef enum {
        LIBCOUCHBASE_ASYNCHRONOUS = 0x00,
        LIBCOUCHBASE_SYNCHRONOUS = 0xff
    } libcouchbase_syncmode_t;

#ifdef __cplusplus
}
#endif

#endif
