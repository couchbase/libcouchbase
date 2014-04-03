/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2013 Couchbase, Inc.
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
#ifndef LIBCOUCHBASE_INTERNAL_H
#define LIBCOUCHBASE_INTERNAL_H 1

#include "config.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <memcached/protocol_binary.h>
#include <ep-engine/command_ids.h>
#include <libvbucket/vbucket.h>
#include <libcouchbase/couchbase.h>
#include <lcbio/lcbio.h>
#include <strcodecs/strcodecs.h>
#include "http_parser/http_parser.h"
#include "list.h"
#include "hashset.h"
#include "genhash.h"
#include "timer.h"
#include "mcserver/mcserver.h"
#include "settings.h"
#include "logging.h"
#include "mc/mcreq.h"
#include "simplestring.h"
#include "retryq.h"

#define LCB_LAST_HTTP_HEADER "X-Libcouchbase: \r\n"
#define LCB_CONFIG_CACHE_MAGIC "{{{fb85b563d0a8f65fa8d3d58f1b3a0708}}}"

#ifdef __cplusplus
extern "C" {
#endif
    struct lcb_histogram_st;

    typedef void (*vbucket_state_listener_t)(lcb_server_t *server);

    struct lcb_callback_st {
        lcb_get_callback get;
        lcb_store_callback store;
        lcb_arithmetic_callback arithmetic;
        lcb_observe_callback observe;
        lcb_remove_callback remove;
        lcb_stat_callback stat;
        lcb_version_callback version;
        lcb_touch_callback touch;
        lcb_flush_callback flush;
        lcb_error_callback error;
        lcb_http_complete_callback http_complete;
        lcb_http_data_callback http_data;
        lcb_unlock_callback unlock;
        lcb_configuration_callback configuration;
        lcb_verbosity_callback verbosity;
        lcb_durability_callback durability;
        lcb_exists_callback exists;
        lcb_errmap_callback errmap;
    };

    struct lcb_confmon_st;
    struct hostlist_st;
    struct lcb_bootstrap_st;

    struct lcb_st {
        /**
         * the type of the connection:
         * * LCB_TYPE_BUCKET
         *      NULL for bucket means "default" bucket
         * * LCB_TYPE_CLUSTER
         *      the bucket argument ignored and all data commands will
         *      return LCB_EBADHANDLE
         */
        lcb_type_t type;
        VBUCKET_DISTRIBUTION_TYPE dist_type;
        mc_CMDQUEUE cmdq;

        /** The number of replicas */
        lcb_uint16_t nreplicas;

        struct lcb_confmon_st *confmon;
        struct hostlist_st *usernodes;
        struct clconfig_info_st *cur_configinfo;
        struct lcb_bootstrap_st *bootstrap;

        unsigned int weird_things;

        vbucket_state_listener_t vbucket_state_listener;

        /** The set of the timers */
        hashset_t timers;
        /** The set of the pointers to HTTP requests to Cluster */
        hashset_t http_requests;
        /** Set of pending durability polls */
        hashset_t durability_polls;

        struct lcb_callback_st callbacks;
        struct lcb_histogram_st *histogram;
        int wait;
        const void *cookie;

        /** Socket pool for memcached connections */
        lcbio_MGR *memd_sockpool;

        lcb_error_t last_error;

        struct {
            lcb_compat_t type;
            union {
                struct {
                    char *cachefile;
                } cached;
            } value;
        } compat;

        lcb_settings *settings;
        lcbio_pTABLE iotable;
        lcb_RETRYQ *retryq;
        char *scratch; /* storage for random strings, lcb_get_host, etc */

#ifdef LCB_DEBUG
        lcb_debug_st debug;
#endif

#ifdef __cplusplus
        lcb_settings* getSettings() { return settings; }
        lcbio_pTABLE getIOT() { return iotable; }
#endif
    };

    #define LCBT_VBCONFIG(instance) (instance)->cmdq.config
    #define LCBT_NSERVERS(instance) (instance)->cmdq.npipelines
    #define LCBT_NREPLICAS(instance) (instance)->nreplicas
    #define LCBT_GET_SERVER(instance, ix) (lcb_server_t *)(instance)->cmdq.pipelines[ix]
    #define LCBT_SETTING(instance, name) (instance)->settings->name

    struct lcb_http_header_st {
        struct lcb_http_header_st *next;
        char *data;
    };

    typedef struct {
        lcb_list_t list;
        char *key;
        char *val;
    } lcb_http_header_t;

    typedef enum {
        /**
         * The request is still ongoing. Callbacks are still active
         */
        LCB_HTREQ_S_ONGOING = 0,

        /**
         * The on_complete callback has been invoked
         */
        LCB_HTREQ_S_CBINVOKED = 1 << 0,

        /**
         * The object has been purged from either its servers' or instances'
         * hashset.
         */
        LCB_HTREQ_S_HTREMOVED = 1 << 1

    } lcb_http_request_status_t;

    struct lcb_http_request_st {
        lcb_t instance;
        /** The URL buffer */
        char *url;
        lcb_size_t nurl;
        /** The URL info */
        struct http_parser_url url_info;
        /** The requested path (without couch api endpoint) */
        char *path;
        lcb_size_t npath;
        /** The body buffer */
        char *body;
        lcb_size_t nbody;
        /** The type of HTTP request */
        lcb_http_method_t method;
        /** The HTTP response parser */
        http_parser *parser;
        http_parser_settings parser_settings;
        char *host;
        lcb_size_t nhost;
        char *port;
        lcb_size_t nport;

        /** Non-zero if caller would like to receive response in chunks */
        int chunked;
        /** This callback will be executed when the whole response will be
         * transferred */
        lcb_http_complete_callback on_complete;
        /** This callback will be executed for each chunk of the response */
        lcb_http_data_callback on_data;
        /** The accumulator for result (when chunked mode disabled) */
        ringbuffer_t result;
        /** The cookie belonging to this request */
        const void *command_cookie;
        /** Reference count */
        unsigned int refcount;
        /** Redirect count */
        int redircount;
        char *redirect_to;
        lcb_string outbuf;

        /** Current state */
        lcb_http_request_status_t status;

        /** Request type; views or management */
        lcb_http_type_t reqtype;

        /** Request headers */
        lcb_http_header_t headers_out;

        /** Linked list of headers */
        struct lcb_http_header_st *headers_list;
        /** Headers array for passing to callbacks */
        const char **headers;
        /** Number of headers **/
        lcb_size_t nheaders;

        lcbio_pTABLE io;
        lcbio_CONNREQ creq;
        lcbio_CTX *ioctx;

        lcb_timer_t io_timer;
        /** IO Timeout */
        lcb_uint32_t timeout;
    };


    lcb_error_t lcb_error_handler(lcb_t instance,
                                  lcb_error_t error,
                                  const char *errinfo);
    /**
     * Returns true if this server has pending I/O on it
     */
    void lcb_initialize_packet_handlers(lcb_t instance);
    void lcb_record_metrics(lcb_t instance, hrtime_t delta,lcb_uint8_t opcode);

    LCB_INTERNAL_API
    void lcb_maybe_breakout(lcb_t instance);

    struct clconfig_info_st;
    void lcb_update_vbconfig(lcb_t instance, struct clconfig_info_st *config);
    /**
     * Hashtable wrappers
     */
    genhash_t *lcb_hashtable_nc_new(lcb_size_t est);
    genhash_t *lcb_hashtable_szt_new(lcb_size_t est);

    void lcb_http_request_finish(lcb_t instance,
                                 lcb_http_request_t req,
                                 lcb_error_t error);
    void lcb_http_request_decref(lcb_http_request_t req);
    lcb_error_t lcb_http_verify_url(lcb_http_request_t req, const char *base, lcb_size_t nbase);
    lcb_error_t lcb_http_request_exec(lcb_http_request_t req);
    lcb_error_t lcb_http_parse_setup(lcb_http_request_t req);
    lcb_error_t lcb_http_request_connect(lcb_http_request_t req);
    void lcb_setup_lcb_http_resp_t(lcb_http_resp_t *resp,
                                   lcb_http_status_t status,
                                   const char *path,
                                   lcb_size_t npath,
                                   const char *const *headers,
                                   const void *bytes,
                                   lcb_size_t nbytes);

    struct lcb_durability_set_st;
    void lcb_durability_dset_destroy(struct lcb_durability_set_st *dset);

    lcb_error_t lcb_iops_cntl_handler(int mode,
                                      lcb_t instance, int cmd, void *arg);

    /**
     * These two routines define portable ways to get environment variables
     * on various platforms.
     *
     * They are mainly useful for Windows compatibility.
     */
    LCB_INTERNAL_API
    int lcb_getenv_nonempty(const char *key, char *buf, lcb_size_t len);
    LCB_INTERNAL_API
    int lcb_getenv_boolean(const char *key);

    /**
     * Initialize the socket subsystem. For windows, this initializes Winsock.
     * On Unix, this does nothing
     */
    LCB_INTERNAL_API
    lcb_error_t lcb_initialize_socket_subsystem(void);

    /**
     * These three functions are all reentrant safe. They control asynchronous
     * scheduling of cluster configuration retrievals.
     */

    /** Call this for initial bootstrap */
    lcb_error_t lcb_bootstrap_initial(lcb_t instance);

    /** Call this on not-my-vbucket, or when a toplogy change is evident */
    lcb_error_t lcb_bootstrap_refresh(lcb_t instance);

    /** Call this when a non-specicic error has taken place, such as a timeout */
    void lcb_bootstrap_errcount_incr(lcb_t instance);

    void lcb_bootstrap_destroy(lcb_t instance);

    lcb_error_t lcb_init_providers(lcb_t obj,
                                   const struct lcb_create_st2 *e_options);


    LCB_INTERNAL_API
    lcb_server_t *
    lcb_find_server_by_host(lcb_t instance, const lcb_host_t *host);


    LCB_INTERNAL_API
    lcb_server_t *
    lcb_find_server_by_index(lcb_t instance, int ix);

    LCB_INTERNAL_API
    lcb_error_t
    lcb_getconfig(lcb_t instance, const void *cookie, lcb_server_t *server);

#ifdef __cplusplus
}
#endif

#endif
