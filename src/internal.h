/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc.
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
#ifndef WIN32
#include <event.h>
#else
#include "myevent.h"
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <memcached/protocol_binary.h>
#include <libvbucket/vbucket.h>
#include <libcouchbase/couchbase.h>
#include <sasl/sasl.h>

/*
 * libevent2 define evutil_socket_t so that it'll automagically work
 * on windows
 */
#ifndef evutil_socket_t
#define evutil_socket_t int
#endif

#ifdef __cplusplus
extern "C" {
#endif
    struct libcouchbase_server_st;
    typedef struct libcouchbase_server_st libcouchbase_server_t;

    typedef void (*EVENT_HANDLER)(evutil_socket_t fd, short which, void *arg);

    typedef void (*REQUEST_HANDLER)(libcouchbase_server_t *instance, protocol_binary_request_header *req);
    typedef void (*RESPONSE_HANDLER)(libcouchbase_server_t *instance,
                                     protocol_binary_response_header *res);

    typedef struct {
        char *data;
        size_t size;
        size_t avail;
    } buffer_t;
    bool grow_buffer(buffer_t *buffer, size_t min_free);

    typedef void (*vbucket_state_listener_t)(libcouchbase_server_t *server);

    struct libcouchbase_callback_st {
        void (*get)(libcouchbase_t instance,
                    libcouchbase_error_t error,
                    const void *key, size_t nkey,
                    const void *bytes, size_t nbytes,
                    uint32_t flags, uint64_t cas);
        void (*storage)(libcouchbase_t instance,
                        libcouchbase_storage_t operation,
                        libcouchbase_error_t error,
                        const void *key, size_t nkey,
                        uint64_t cas);
        void (*arithmetic)(libcouchbase_t instance,
                           libcouchbase_error_t error,
                           const void *key, size_t nkey,
                           uint64_t value, uint64_t cas);
        void (*remove)(libcouchbase_t instance,
                       libcouchbase_error_t error,
                       const void *key, size_t nkey);
        void (*touch)(libcouchbase_t instance,
                      libcouchbase_error_t error,
                      const void *key, size_t nkey);
        void (*tap_mutation)(libcouchbase_t instance,
                             const void *key,
                             size_t nkey,
                             const void *data,
                             size_t nbytes,
                             uint32_t flags,
                             uint32_t exp,
                             const void *es,
                             size_t nes);
        void (*tap_deletion)(libcouchbase_t instance,
                             const void *key,
                             size_t nkey,
                             const void *es,
                             size_t nes);
        void (*tap_flush)(libcouchbase_t instance,
                          const void *es,
                          size_t nes);
        void (*tap_opaque)(libcouchbase_t instance,
                           const void *es,
                           size_t nes);
        void (*tap_vbucket_set)(libcouchbase_t instance,
                                uint16_t vbid,
                                vbucket_state_t state,
                                const void *es,
                                size_t nes);
    };

    struct libcouchbase_st {
        /** The couchbase host */
        char *host;
        /** The port of the couchbase server */
        const char *port;
        /** The username to connect with */
        char *user;
        /** The password to connect with */
        char *passwd;
        /** The bucket to use */
        char *bucket;
        /** The event base this instance is connected to */
        struct event_base *ev_base;
        /** The event item representing _this_ object */
        struct event ev_event;
        /** The curret set of flags */
        short ev_flags;

        /** The current vbucket config handle */
        VBUCKET_CONFIG_HANDLE vbucket_config;

        struct {
            char *header;
            buffer_t input;
            size_t chunk_size;
        } vbucket_stream;

        evutil_socket_t sock;
        struct addrinfo *ai;

        /** The number of couchbase server in the configuration */
        size_t nservers;
        /** The array of the couchbase servers */
        libcouchbase_server_t *servers;

        /** The number of vbuckets */
        uint16_t nvbuckets;
        /** A map from the vbucket to the server hosting the vbucket */
        uint16_t *vb_server_map;

        vbucket_state_listener_t vbucket_state_listener;
        RESPONSE_HANDLER response_handler[0x100];
        REQUEST_HANDLER request_handler[0x100];
        libcouchbase_packet_filter_t packet_filter;

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

        uint32_t seqno;
        bool execute;
        const void *cookie;
    };

    /**
     * The structure representing each couchbase server
     */
    struct libcouchbase_server_st {
        /** The name of the server */
        char *hostname;
        /** The servers port */
        char *port;
        /** The socket to the server */
        evutil_socket_t sock;
        /** The address information for this server (the one to release) */
        struct addrinfo *root_ai;
        /** The address information for this server (the one we're trying) */
        struct addrinfo *curr_ai;
        /** The output buffer for this server */
        buffer_t output;
        /** The sent buffer for this server so that we can resend the
         * command to another server if the bucket is moved... */
        buffer_t cmd_log;
        /**
         * The pending buffer where we write data until we're in a
         * connected state;
         */
        buffer_t pending;
        /** offset to the beginning of the packet being built */
        size_t current_packet;
        /** The input buffer for this server */
        buffer_t input;
        /** The SASL object used for this server */
        sasl_conn_t *sasl_conn;
        /** The event item representing _this_ object */
        struct event ev_event;
        /** The curret set of flags */
        short ev_flags;
        /** Is this server in a connected state (done with sasl auth) */
        bool connected;
        /** The current event handler */
        EVENT_HANDLER ev_handler;
        /* Pointer back to the instance */
        libcouchbase_t instance;
    };

    void libcouchbase_server_purge_implicit_responses(libcouchbase_server_t *c,
                                                      uint32_t seqno);
    void libcouchbase_server_destroy(libcouchbase_server_t *server);
    void libcouchbase_server_connected(libcouchbase_server_t *server);

    void libcouchbase_server_initialize(libcouchbase_server_t *server,
                                        int servernum);



    void libcouchbase_server_buffer_start_packet(libcouchbase_server_t *c,
                                                 buffer_t *buff,
                                                 const void *data,
                                                 size_t size);

    void libcouchbase_server_buffer_write_packet(libcouchbase_server_t *c,
                                                 buffer_t *buff,
                                                 const void *data,
                                                 size_t size);

    void libcouchbase_server_buffer_end_packet(libcouchbase_server_t *c,
                                               buffer_t *buff);

    void libcouchbase_server_buffer_complete_packet(libcouchbase_server_t *c,
                                                    buffer_t *buff,
                                                    const void *data,
                                                    size_t size);

    /**
     * Initiate a new packet to be sent
     * @param c the server connection to send it to
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libcouchbase_server_start_packet(libcouchbase_server_t *c,
                                          const void *data,
                                          size_t size);
    /**
     * Write data to the current packet
     * @param c the server connection to send it to
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libcouchbase_server_write_packet(libcouchbase_server_t *c,
                                          const void *data,
                                          size_t size);
    /**
     * Mark this packet complete
     */
    void libcouchbase_server_end_packet(libcouchbase_server_t *c);

    /**
     * Create a complete packet (to avoid calling start + end)
     * @param c the server connection to send it to
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libcouchbase_server_complete_packet(libcouchbase_server_t *c,
                                             const void *data,
                                             size_t size);
    /**
     * Start sending packets
     * @param server the server to start send data to
     */
    void libcouchbase_server_send_packets(libcouchbase_server_t *server);




    void libcouchbase_server_update_event(libcouchbase_server_t *c, short flags,
                                          EVENT_HANDLER handler);
    void libcouchbase_server_event_handler(evutil_socket_t sock, short which, void *arg);

    void libcouchbase_initialize_packet_handlers(libcouchbase_t instance);

    void libcouchbase_ensure_vbucket_config(libcouchbase_t instance);

    int libcouchbase_base64_encode(const char *src, char *dst, size_t sz);

#ifdef __cplusplus
}
#endif

#include <libcouchbase/couchbase.h>

#endif
