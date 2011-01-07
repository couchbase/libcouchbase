/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Membase, Inc.
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
#ifndef LIBMEMBASE_INTERNAL_H
#define LIBMEMBASE_INTERNAL_H 1

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <event.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <memcached/protocol_binary.h>
#include <libvbucket/vbucket.h>
#include <libmembase/membase.h>
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
    struct libmembase_server_st;
    typedef struct libmembase_server_st libmembase_server_t;

    typedef void (*EVENT_HANDLER)(evutil_socket_t fd, short which, void *arg);

    typedef void (*REQUEST_HANDLER)(libmembase_server_t *instance, protocol_binary_request_header *req);
    typedef void (*RESPONSE_HANDLER)(libmembase_server_t *instance,
                                     protocol_binary_response_header *res);

    typedef struct {
        char *data;
        size_t size;
        size_t avail;
    } buffer_t;
    bool grow_buffer(buffer_t *buffer, size_t min_free);

    typedef void (*vbucket_state_listener)(libmembase_server_t *server);

    struct libmembase_st {
        /** The membase host */
        char *host;
        /** The port of the membase server */
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

        /** The number of membase server in the configuration */
        size_t nservers;
        /** The array of the membase servers */
        libmembase_server_t *servers;

        /** The number of vbuckets */
        uint16_t nvbuckets;
        /** A map from the vbucket to the server hosting the vbucket */
        uint16_t *vb_server_map;

        vbucket_state_listener vbucket_state_listener;
        RESPONSE_HANDLER response_handler[0x100];
        REQUEST_HANDLER request_handler[0x100];
        libmembase_packet_filter_t packet_filter;

        struct {
            const char *name;
            union {
                sasl_secret_t secret;
                char buffer[256];
            } password;
            sasl_callback_t callbacks[4];
        } sasl;

        struct {
            libmembase_tap_filter_t filter;
        } tap;


        libmembase_callback_t callbacks;

        uint32_t seqno;
        bool execute;
        const void *cookie;
    };

    /**
     * The structure representing each membase server
     */
    struct libmembase_server_st {
        /** The socket to the server */
        evutil_socket_t sock;
        /** The address information for this server */
        struct addrinfo *ai;
        /** The output buffer for this server */
        buffer_t output;
        /** The sent buffer for this server so that we can resend the
         * command to another server if the bucket is moved... */
        buffer_t cmd_log;
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
        /** The current event handler */
        EVENT_HANDLER ev_handler;
        /* Pointer back to the instance */
        libmembase_t instance;
    };

    /**
     * Initiate a new packet to be sent
     * @param c the server connection to send it to
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libmembase_server_start_packet(libmembase_server_t *c,
                                        const void *data,
                                        size_t size);
    /**
     * Write data to the current packet
     * @param c the server connection to send it to
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libmembase_server_write_packet(libmembase_server_t *c,
                                        const void *data,
                                        size_t size);
    /**
     * Mark this packet complete
     */
    void libmembase_server_end_packet(libmembase_server_t *c);

    /**
     * Create a complete packet (to avoid calling start + end)
     * @param c the server connection to send it to
     * @param data pointer to data to include in the packet
     * @param size the size of the data to include
     */
    void libmembase_server_complete_packet(libmembase_server_t *c,
                                           const void *data,
                                           size_t size);

    void libmembase_server_update_event(libmembase_server_t *c, short flags,
                                        EVENT_HANDLER handler);
    void libmembase_server_event_handler(evutil_socket_t sock, short which, void *arg);

    void libmembase_initialize_packet_handlers(libmembase_t instance);

    void libmembase_ensure_vbucket_config(libmembase_t instance);

    int libmembase_base64_encode(const char *src, char *dst, size_t sz);

#ifdef __cplusplus
}
#endif

#include <libmembase/membase.h>

#endif
