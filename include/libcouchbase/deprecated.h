/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014 Couchbase, Inc.
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

#ifndef LCB_DEPRECATED_H
#define LCB_DEPRECATED_H
#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "include <libcouchbase/couchbase.h> first"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**@file
 * Deprecated APIs
 */

#define LCB_DEPR_API(X) LIBCOUCHBASE_API LCB_DEPRECATED(X)
#define LCB_DEPR_API2(X, reason) LIBCOUCHBASE_API LCB_DEPRECATED2(X, reason)

/** @deprecated Use @ref LCB_CNTL_IP6POLICY via lcb_cntl() */
LCB_DEPR_API2(void lcb_behavior_set_ipv6(lcb_t instance, lcb_ipv6_t mode), "Use LCB_CNTL_IP6POLICY");
/** @deprecated Use @ref LCB_CNTL_IP6POLICY via lcb_cntl() */
LCB_DEPR_API2(lcb_ipv6_t lcb_behavior_get_ipv6(lcb_t instance), "Use LCB_CNTL_IP6POLICY");
/** @deprecated Use @ref LCB_CNTL_CONFERRTHRESH via lcb_cntl() */
LCB_DEPR_API2(void lcb_behavior_set_config_errors_threshold(lcb_t instance, lcb_size_t num_events),
    "Use LCB_CNTL_CONFERRTHRESH");
/** @deprecated Use @ref LCB_CNTL_CONFERRTHRESH via lcb_cntl() */
LCB_DEPR_API2(lcb_size_t lcb_behavior_get_config_errors_threshold(lcb_t instance),
    "Use LCB_CNTL_CONFERRTHRESH");
/** @deprecated Use @ref LCB_CNTL_OP_TIMEOUT via lcb_cntl() */
LCB_DEPR_API2(void lcb_set_timeout(lcb_t instance, lcb_uint32_t usec),
    "Use LCB_CNTL_OP_TIMEOUT");
/** @deprecated Use @ref LCB_CNTL_OP_TIMEOUT via lcb_cntl() */
LCB_DEPR_API2(lcb_uint32_t lcb_get_timeout(lcb_t instance),
    "Use LCB_CNTL_OP_TIMEOUT");
/** @deprecated Use @ref LCB_CNTL_VIEW_TIMEOUT via lcb_cntl() */
LCB_DEPR_API2(void lcb_set_view_timeout(lcb_t instance, lcb_uint32_t usec),
    "Use LCB_CNTL_VIEW_TIMEOUT");
/** @deprecated Use @ref LCB_CNTL_VIEW_TIMEOUT via lcb_cntl() */
LCB_DEPR_API2(lcb_uint32_t lcb_get_view_timeout(lcb_t instance),
    "Use LCB_CNTL_VIEW_TIMEOUT");

/** I'm not sure what uses this anymore */
typedef enum {
    LCB_VBUCKET_STATE_ACTIVE = 1,   /* Actively servicing a vbucket. */
    LCB_VBUCKET_STATE_REPLICA = 2,  /* Servicing a vbucket as a replica only. */
    LCB_VBUCKET_STATE_PENDING = 3,  /* Pending active. */
    LCB_VBUCKET_STATE_DEAD = 4      /* Not in use, pending deletion. */
} lcb_vbucket_state_t;


typedef enum lcb_compat_t { LCB_MEMCACHED_CLUSTER = 0x00, LCB_CACHED_CONFIG = 0x01 } lcb_compat_t;
typedef lcb_compat_t lcb_cluster_t;
struct lcb_memcached_st { const char *serverlist; const char *username; const char *password; };
struct lcb_cached_config_st {
    const char *cachefile;
    struct lcb_create_st createopt;
};

/**
 * @deprecated
 * Use @ref LCB_CNTL_CONFIGCACHE for configuration cache options
 */
#define lcb_create_compat lcb__create_compat_230
LCB_DEPR_API2(lcb_error_t lcb_create_compat(lcb_compat_t type, const void *specific, lcb_t *instance, struct lcb_io_opt_st *io),
    "Use memcached:// for legacy memcached. For config cache, use LCB_CNTL_CONFIGCACHE");

LCB_DEPR_API2(const char *lcb_get_host(lcb_t),
    "Use lcb_get_node(instance, LCB_NODE_HTCONFIG, 0)");
LCB_DEPR_API2(const char *lcb_get_port(lcb_t),
    "Use lcb_get_node(instance, LCB_NODE_HTCONFIG, 0)");

/** Deprecated cntls */

/**@deprecated It is currently not possible to adjust buffer sizes */
#define LCB_CNTL_RBUFSIZE               0x02
/**@deprecated It is currently not possible to adjust buffer sizes */
#define LCB_CNTL_WBUFSIZE               0x03
/**@deprecated Initial connections are always attempted */
#define LCB_CNTL_SKIP_CONFIGURATION_ERRORS_ON_CONNECT 0x13

/**@deprecated Use error classifiers */
#define lcb_is_error_enomem(a) ((a == LCB_CLIENT_ENOMEM) || (a == LCB_ENOMEM))
/**@deprecated Use error classifiers */
#define lcb_is_error_etmpfail(a) ((a == LCB_CLIENT_ETMPFAIL) || (a == LCB_ETMPFAIL))

/* Deprecated HTTP "Status Aliases" */
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

/**
 * @deprecated
 */
typedef enum {
    /* encryption (e.g. private key for assymetric ciphers) */
    LCBCRYPTO_KEY_ENCRYPT = 0,
    /* decryption (e.g. private key for assymetric ciphers) */
    LCBCRYPTO_KEY_DECRYPT = 1,
    LCBCRYPTO_KEY__MAX
} lcbcrypto_KEYTYPE;


#ifdef __cplusplus
}
#endif
#endif
