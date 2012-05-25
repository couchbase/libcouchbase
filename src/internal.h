/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011, 2012 Couchbase, Inc.
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

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <memcached/protocol_binary.h>
#include <libvbucket/vbucket.h>
#include <libcouchbase/couchbase.h>
#ifdef HAVE_SYSTEM_LIBSASL
#include <sasl/sasl.h>
#else
#include "isasl.h"
#endif

#include "http_parser/http_parser.h"
#include "ringbuffer.h"
#include "hashset.h"
#include "debug.h"

/*
 * libevent2 define evutil_socket_t so that it'll automagically work
 * on windows
 */
#ifndef evutil_socket_t
#define evutil_socket_t int
#endif

#define LIBCOUCHBASE_DEFAULT_TIMEOUT 2500000

#ifdef __cplusplus
extern "C" {
#endif
    struct libcouchbase_server_st;
    typedef struct libcouchbase_server_st libcouchbase_server_t;

    typedef void (*EVENT_HANDLER)(evutil_socket_t fd, short which, void *arg);

    typedef void (*REQUEST_HANDLER)(libcouchbase_server_t *instance,
                                    const void *command_cookie,
                                    protocol_binary_request_header *req);
    typedef void (*RESPONSE_HANDLER)(libcouchbase_server_t *instance,
                                     const void *command_cookie,
                                     protocol_binary_response_header *res);

    /**
     * Define constants for connection attemptts
     */
    typedef enum {
        LIBCOUCHBASE_CONNECT_OK = 0,
        LIBCOUCHBASE_CONNECT_EINPROGRESS,
        LIBCOUCHBASE_CONNECT_EALREADY,
        LIBCOUCHBASE_CONNECT_EISCONN,
        LIBCOUCHBASE_CONNECT_EINTR,
        LIBCOUCHBASE_CONNECT_EFAIL,
        LIBCOUCHBASE_CONNECT_EUNHANDLED
    } libcouchbase_connect_status_t;

    typedef struct {
        char *data;
        libcouchbase_size_t size;
        libcouchbase_size_t avail;
    } buffer_t;
    int grow_buffer(buffer_t *buffer, libcouchbase_size_t min_free);

    /**
     * Data stored per command in the command-cookie buffer...
     */
    struct libcouchbase_command_data_st {
        hrtime_t start;
        const void *cookie;
    };

    struct libcouchbase_histogram_st;

    typedef void (*vbucket_state_listener_t)(libcouchbase_server_t *server);

    struct libcouchbase_callback_st {
        libcouchbase_get_callback get;
        libcouchbase_storage_callback storage;
        libcouchbase_arithmetic_callback arithmetic;
        libcouchbase_remove_callback remove;
        libcouchbase_stat_callback stat;
        libcouchbase_version_callback version;
        libcouchbase_touch_callback touch;
        libcouchbase_flush_callback flush;
        libcouchbase_tap_mutation_callback tap_mutation;
        libcouchbase_tap_deletion_callback tap_deletion;
        libcouchbase_tap_flush_callback tap_flush;
        libcouchbase_tap_opaque_callback tap_opaque;
        libcouchbase_tap_vbucket_set_callback tap_vbucket_set;
        libcouchbase_error_callback error;
        libcouchbase_couch_complete_callback couch_complete;
        libcouchbase_couch_data_callback couch_data;
    };

    struct libcouchbase_st {
        /** The couchbase host */
        char host[NI_MAXHOST + 1];
        /** The port of the couchbase server */
        char port[NI_MAXSERV + 1];

        /** The URL request to send to the server */
        char *http_uri;
        size_t n_http_uri_sent;


        /** The event item representing _this_ object */
        void *event;

        /** The current vbucket config handle */
        VBUCKET_CONFIG_HANDLE vbucket_config;

        struct {
            char *header;
            buffer_t input;
            size_t chunk_size;
            buffer_t chunk;
        } vbucket_stream;

        struct libcouchbase_io_opt_st *io;

        /* The current synchronous mode */
        libcouchbase_syncmode_t syncmode;

        evutil_socket_t sock;
        struct addrinfo *ai;
        struct addrinfo *curr_ai;

        /** The number of couchbase server in the configuration */
        size_t nservers;
        /** The array of the couchbase servers */
        libcouchbase_server_t *servers;

        /** The array of last known nodes as hostname:port */
        char **backup_nodes;
        /** The current connect index */
        int backup_idx;

        /** The number of vbuckets */
        libcouchbase_uint16_t nvbuckets;
        /** A map from the vbucket to the server hosting the vbucket */
        libcouchbase_vbucket_t *vb_server_map;

        vbucket_state_listener_t vbucket_state_listener;

        /** for initial configuration.
         * see breakout_vbucket_state_listener in wait.c*/
        vbucket_state_listener_t vbucket_state_listener_last;

        RESPONSE_HANDLER response_handler[0x100];
        REQUEST_HANDLER request_handler[0x100];

        struct {
            const char *name;
            union {
                sasl_secret_t secret;
                char buffer[256];
            } password;
            sasl_callback_t callbacks[4];
        } sasl;

        struct {
            libcouchbase_tap_filter_t filter;
        } tap;


        struct libcouchbase_callback_st callbacks;
        struct libcouchbase_histogram_st *histogram;

        libcouchbase_uint32_t seqno;
        int wait;
        const void *cookie;

        libcouchbase_error_t last_error;

        struct {
            hrtime_t next;
            void *event;
            libcouchbase_uint32_t usec;
        } timeout;
#ifdef LIBCOUCHBASE_DEBUG
        libcouchbase_debug_st debug;
#endif
    };

    /**
     * The structure representing each couchbase server
     */
    struct libcouchbase_server_st {
        /** The server index in the list */
        int index;
        /** The name of the server */
        char *hostname;
        /** The servers port */
        char *port;
        /** The server endpoint as hostname:port */
        char *authority;
        /** The Couchbase Views API endpoint base */
        char *couch_api_base;
        /** The REST API server as hostname:port */
        char *rest_api_server;
        /** The socket to the server */
        evutil_socket_t sock;
        /** The address information for this server (the one to release) */
        struct addrinfo *root_ai;
        /** The address information for this server (the one we're trying) */
        struct addrinfo *curr_ai;

        /** The output buffer for this server */
        ringbuffer_t output;
        /** The sent buffer for this server so that we can resend the
         * command to another server if the bucket is moved... */
        ringbuffer_t cmd_log;
        ringbuffer_t output_cookies;
        /**
         * The pending buffer where we write data until we're in a
         * connected state;
         */
        ringbuffer_t pending;
        ringbuffer_t pending_cookies;

        /** The input buffer for this server */
        ringbuffer_t input;

        /** The set of the pointers to Couchbase View requests */
        hashset_t couch_requests;

        /** The SASL object used for this server */
        sasl_conn_t *sasl_conn;
        /** The event item representing _this_ object */
        void *event;
        /** Is this server in a connected state (done with sasl auth) */
        int connected;
        /** The current event handler */
        EVENT_HANDLER ev_handler;
        /* Pointer back to the instance */
        libcouchbase_t instance;

        hrtime_t next_timeout;
    };

    struct libcouchbase_couch_request_st {
        /** The socket to the server */
        evutil_socket_t sock;
        struct libcouchbase_io_opt_st *io;
        /** The origin node */
        libcouchbase_server_t *server;
        /** Short ref to instance (server->instance) */
        libcouchbase_t instance;
        /** The URL buffer */
        char *url;
        libcouchbase_size_t nurl;
        /** The URL info */
        struct http_parser_url url_info;
        /** The hostname of the server */
        char *host;
        /** The string representation of the port number (binary is url_info.port) */
        char *port;
        /** The requested path (without couch api endpoint) */
        const char *path;
        libcouchbase_size_t npath;
        /** The type of HTTP request */
        libcouchbase_http_method_t method;
        /** The HTTP response parser */
        http_parser *parser;
        http_parser_settings parser_settings;
        /** The address information for this server (the one to release) */
        struct addrinfo *root_ai;
        /** The address information for this server (the one we're trying) */
        struct addrinfo *curr_ai;
        /** The event item representing _this_ object */
        void *event;
        /** Non-zero if caller would like to receive response in chunks */
        int chunked;
        /** This callback will be executed when the whole response will be
         * transferred */
        libcouchbase_couch_complete_callback on_complete;
        /** This callback will be executed for each chunk of the response */
        libcouchbase_couch_data_callback on_data;
        /** The outgoing buffer for this request */
        ringbuffer_t output;
        /** The incoming buffer for this request */
        ringbuffer_t input;
        /** The accumulator for result (when chunked mode disabled) */
        ringbuffer_t result;
        /** The cookie belonging to this request */
        const void *command_cookie;
        int cancelled;
    };

    void libcouchbase_couch_request_destroy(libcouchbase_couch_request_t req);


    libcouchbase_error_t libcouchbase_synchandler_return(libcouchbase_t instance, libcouchbase_error_t retcode);

    libcouchbase_error_t libcouchbase_error_handler(libcouchbase_t instance,
                                                    libcouchbase_error_t error,
                                                    const char *errinfo);

    int libcouchbase_server_purge_implicit_responses(libcouchbase_server_t *c,
                                                     libcouchbase_uint32_t seqno,
                                                     hrtime_t delta);
    void libcouchbase_server_destroy(libcouchbase_server_t *server);
    void libcouchbase_server_connected(libcouchbase_server_t *server);

    void libcouchbase_server_initialize(libcouchbase_server_t *server,
                                        int servernum);



    void libcouchbase_server_buffer_start_packet(libcouchbase_server_t *c,
                                                 const void *command_cookie,
                                                 ringbuffer_t *buff,
                                                 ringbuffer_t *buff_cookie,
                                                 const void *data,
                                                 libcouchbase_size_t size);

    void libcouchbase_server_buffer_retry_packet(libcouchbase_server_t *c,
                                                 struct libcouchbase_command_data_st *ct,
                                                 ringbuffer_t *buff,
                                                 ringbuffer_t *buff_cookie,
                                                 const void *data,
                                                 libcouchbase_size_t size);

    void libcouchbase_server_buffer_write_packet(libcouchbase_server_t *c,
                                                 ringbuffer_t *buff,
                                                 const void *data,
                                                 libcouchbase_size_t size);

    void libcouchbase_server_buffer_end_packet(libcouchbase_server_t *c,
                                               ringbuffer_t *buff);

    void libcouchbase_server_buffer_complete_packet(libcouchbase_server_t *c,
                                                    const void *command_cookie,
                                                    ringbuffer_t *buff,
                                                    ringbuffer_t *buff_cookie,
                                                    const void *data,
                                                    libcouchbase_size_t size);

    /**
     * Initiate a new packet to be sent
     * @param c the server connection to send it to
     * @param command_cookie the cookie belonging to this command
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libcouchbase_server_start_packet(libcouchbase_server_t *c,
                                          const void *command_cookie,
                                          const void *data,
                                          libcouchbase_size_t size);

    void libcouchbase_server_retry_packet(libcouchbase_server_t *c,
                                          struct libcouchbase_command_data_st *ct,
                                          const void *data,
                                          libcouchbase_size_t size);
    /**
     * Write data to the current packet
     * @param c the server connection to send it to
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libcouchbase_server_write_packet(libcouchbase_server_t *c,
                                          const void *data,
                                          libcouchbase_size_t size);
    /**
     * Mark this packet complete
     */
    void libcouchbase_server_end_packet(libcouchbase_server_t *c);

    /**
     * Create a complete packet (to avoid calling start + end)
     * @param c the server connection to send it to
     * @param command_cookie the cookie belonging to this command
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libcouchbase_server_complete_packet(libcouchbase_server_t *c,
                                             const void *command_cookie,
                                             const void *data,
                                             libcouchbase_size_t size);
    /**
     * Start sending packets
     * @param server the server to start send data to
     */
    void libcouchbase_server_send_packets(libcouchbase_server_t *server);


    void libcouchbase_server_event_handler(libcouchbase_socket_t sock, short which, void *arg);

    void libcouchbase_initialize_packet_handlers(libcouchbase_t instance);

    int libcouchbase_base64_encode(const char *src, char *dst, libcouchbase_size_t sz);

    void libcouchbase_record_metrics(libcouchbase_t instance,
                                     hrtime_t delta,
                                     libcouchbase_uint8_t opcode);

    void libcouchbase_update_timer(libcouchbase_t instance);
    void libcouchbase_purge_timedout(libcouchbase_t instance);


    int libcouchbase_lookup_server_with_command(libcouchbase_t instance,
                                                libcouchbase_uint8_t opcode,
                                                libcouchbase_uint32_t opaque,
                                                libcouchbase_server_t *exc);

    void libcouchbase_purge_single_server(libcouchbase_server_t *server,
                                          ringbuffer_t *stream,
                                          ringbuffer_t *cookies,
                                          hrtime_t tmo,
                                          hrtime_t now,
                                          libcouchbase_error_t error);

    libcouchbase_error_t libcouchbase_failout_server(libcouchbase_server_t *server,
                                                     libcouchbase_error_t error);

    int libcouchbase_has_data_in_buffers(libcouchbase_t instance);

    void libcouchbase_maybe_breakout(libcouchbase_t instance);

    libcouchbase_connect_status_t libcouchbase_connect_status(int err);

    void libcouchbase_sockconn_errinfo(int connerr,
                                       const char *hostname,
                                       const char *port,
                                       const struct addrinfo *root_ai,
                                       char *buf,
                                       libcouchbase_size_t nbuf,
                                       libcouchbase_error_t *uerr);

    evutil_socket_t libcouchbase_gai2sock(libcouchbase_t instance,
                                          struct addrinfo **curr_ai,
                                          int *connerr);

    void libcouchbase_apply_vbucket_config(libcouchbase_t instance,
                                           VBUCKET_CONFIG_HANDLE config);

#ifdef __cplusplus
}
#endif

#include <libcouchbase/couchbase.h>

#endif
