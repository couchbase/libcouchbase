/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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
 * Common header for IO routines
 */

#ifndef LIBCOUCHBASE_INTERNAL_H
#error "Please include internal.h first"
#endif

#ifndef LCBIO_H
#define LCBIO_H

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum {
        LCB_CONN_CONNECTED = 1,
        LCB_CONN_INPROGRESS = 2,
        LCB_CONN_ERROR = 3
    } lcb_connection_result_t;

    typedef enum {
        LCB_SOCKRW_READ = 1,
        LCB_SOCKRW_WROTE = 2,
        LCB_SOCKRW_IO_ERROR = 3,
        LCB_SOCKRW_GENERIC_ERROR = 4,
        LCB_SOCKRW_WOULDBLOCK = 5
    } lcb_sockrw_status_t;

    struct lcb_connection_st;
    typedef void (*lcb_connection_handler)(struct lcb_connection_st*, lcb_error_t);

    struct lcb_connection_st {
        struct addrinfo *ai;
        struct addrinfo *curr_ai;

        /** instance */
        lcb_t instance;

        void *data;

        /** callback to be invoked when the connection is complete */
        lcb_connection_handler on_connect_complete;

        lcb_connection_handler on_connect_timeout;

        /** for generic timeout events */
        lcb_connection_handler on_timeout;

        /** event for the connection */
        void *event;

        /** timer for the connection */
        void *timer;

        /** Host/Port */
        char host[NI_MAXHOST+1];
        char port[NI_MAXSERV+1];

        /**
         * OUT parameters
         */
        int timeout_active;
        int event_active;

        /** this is populated with the socket when the connection is done */
        lcb_socket_t sockfd;
        int connected;

    };

    typedef struct lcb_connection_st* lcb_connection_t;


    /**
     * Request a connection. The connection object should be filled with the
     * appropriate callbacks
     * @param conn a connection object with properly initialized fields
     * @param nocb if true, don't invoke callbacks if anything happens during
     * this first call. This is to avoid strange behavior if this function is
     * invoked while the user still has control of the event lioop.
     */
    lcb_connection_result_t lcb_connection_start(lcb_connection_t conn,
                                                 int nocb,
                                                 lcb_uint32_t timeout);

    /**
     * Close the socket and clean up any socket-related resources
     */
    void lcb_connection_close(lcb_connection_t conn);

    /**
     * Wrapper around lcb_getaddrinfo
     */
    int lcb_connection_getaddrinfo(lcb_connection_t conn, int refresh);

    /**
     * Free any resources allocated by the connection subsystem
     */
    void lcb_connection_cleanup(lcb_connection_t conn);

    /**
     * Update the connection-level timer
     * @param conn a connection object
     * @param usec when the timeout should be triggered
     * @param handler a callback to be invoked when the timeout has been reached
     */
    void lcb_connection_update_timer(lcb_connection_t conn,
                                     lcb_uint32_t usec,
                                     lcb_connection_handler handler);

    /**
     * Cancel any timeout event set by update_timer on the connection
     */
    void lcb_connection_delete_timer(lcb_connection_t conn);


    /* Read a bit of data */
    lcb_sockrw_status_t lcb_sockrw_read(lcb_connection_t conn, ringbuffer_t *buf);

    /* Exhaust the data until there is nothing to read */
    lcb_sockrw_status_t lcb_sockrw_slurp(lcb_connection_t conn, ringbuffer_t *buf);

    /* Write as much data from the write buffer until blocked */
    lcb_sockrw_status_t lcb_sockrw_write(lcb_connection_t conn, ringbuffer_t *buf);


#ifdef __cplusplus
}
#endif

#endif /* LCBIO_H */
