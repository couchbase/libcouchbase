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

#ifndef LCBIO_H
#define LCBIO_H

#include <libcouchbase/couchbase.h>
#include <libcouchbase/iops.h>
#include "ringbuffer.h"
#include "config.h"
#include "hostlist.h"
#include "iotable.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /**
     * A pending operation was completed.
     */
    LCBIO_STATUS_COMPLETED = 0,

    /**
     * An operation is still pending
     */
    LCBIO_STATUS_PENDING = 1,

    /** Numbers >= this constant are errors */
    LCBIO__STATUS_SUCCESS_MAX,

    /** Error Codes */

    /** I/O Error */
    LCBIO_STATUS_IOERR,

    /** Internal Error */
    LCBIO_STATUS_INTERR,

    /** Graceful close */
    LCBIO_STATUS_SHUTDOWN
} lcbio_status_t;


#define LCBIO_STATUS_WFLUSHED LCBIO_STATUS_COMPLETED
#define LCBIO_STATUS_CANREAD LCBIO_STATUS_COMPLETED
#define LCBIO_STATUS_CONNECT_SCHEDULED LCBIO_STATUS_PENDING
#define LCBIO_STATUS_CONNECT_COMPLETE LCBIO_STATUS_COMPLETED

#define LCBIO_IS_OK(s) ((s) < LCBIO__STATUS_SUCCESS_MAX)

typedef enum {
    LCBCONN_S_UNINIT = 0,
    LCBCONN_S_CONNECTED,
    LCBCONN_S_PENDING
} lcbconn_state_t;

typedef struct lcb_ioconnect_st * lcb_ioconnect_t;

struct lcb_connection_st;
typedef void (*lcb_connection_handler)(struct lcb_connection_st *, lcb_error_t);

/**
 * These 'easy' handlers simply invoke the specified callback.
 */
typedef void (*lcb_io_generic_cb)(struct lcb_connection_st*);

/** v0 handler */
typedef void (*lcb_event_handler_cb)(lcb_socket_t, short, void *);

struct lcb_nibufs_st {
    char local[NI_MAXHOST + NI_MAXSERV + 2];
    char remote[NI_MAXHOST + NI_MAXSERV + 2];
};

struct lcb_settings_st;
typedef void (*protoctx_dtor_t)(void*);
typedef void (*protoctx_xfr_t)(void *, struct lcb_connection_st *);

typedef struct {
    /** Callback for all socket events */
    lcb_ioE_callback handler;
    void *ptr;
    lcb_socket_t sockfd;
    int active;
} lcbio_Ectx;

typedef struct {
    lcb_ioC_read_callback read;
    lcb_ioC_write2_callback write;
    lcb_sockdata_t *sockptr;
} lcbio_Cctx;

struct lcb_connection_st {
    ringbuffer_t *input;
    ringbuffer_t *output;
    lcb_iotable *iotable;
    struct lcb_settings_st *settings;

    /** Host we're connected to: PRIVATE */
    lcb_host_t *cur_host_;

    /**
     * Data associated with the connection. This is also passed as the
     * third argument for the v0 event handler
     */
    void *data;

    /** Protocol specific data bound to the connection itself */
    void *protoctx;

    /** Destructor function called to clean up the protoctx pointer */
    protoctx_dtor_t protoctx_dtor;
    /** Function called to update any internal references to the old connection */
    protoctx_xfr_t protoctx_transfer;

    lcb_ioconnect_t ioconn;

    /** Information for pools */
    void *poolinfo;

    struct {
        lcb_io_generic_cb read;
    } easy;

    union {
        lcbio_Cctx c;
        lcbio_Ectx e;
    } u_model;

    lcb_io_generic_cb errcb;
    lcb_timer_t as_err;

    lcbconn_state_t state;

    short want;


    /** We should really typedef this... */
    /**
     * This contains the last "real" socket error received by this
     * connection. This can be something like ECONNREFUSED or similar.
     * Very helpful for debugging, and may also be exposed to the user
     * one day..
     */
#ifdef _WIN32
    DWORD last_error;
#else
    int last_error;
#endif
};

typedef struct {
    lcb_connection_handler handler;
    lcb_uint32_t timeout;
    lcb_host_t *destination;
} lcbconn_params;

typedef struct lcb_connection_st *lcbconn_t;

/**
 * Initialize the connection object's buffers, usually allocating them
 */
lcb_error_t lcbconn_init(lcbconn_t conn,
                         lcb_iotable *iotable,
                         struct lcb_settings_st *settings);


/**
 * Resets the buffers in the connection. This allocates new writes or
 * read buffers if needed, or resets the mark of the existing ones, depending
 * on their ownership
 */
lcb_error_t lcbconn_reset_bufs(lcbconn_t conn);


/**
 * Request a connection. The connection object should be filled with the
 * appropriate callbacks
 * The LCBIO subsystem will deliver a callback once the state of the connection
 * is known.
 *
 */
lcbio_status_t lcbconn_connect(lcbconn_t conn, const lcbconn_params *params);

/**
 * Close the socket and clean up any socket-related resources
 */
void lcbconn_close(lcbconn_t conn);

/**
 * Free any resources allocated by the connection subsystem
 */
void lcbconn_cleanup(lcbconn_t conn);

/* Read a bit of data */
lcbio_status_t lcbconn_Erb_read(lcbconn_t conn);

/* Exhaust the data until there is nothing to read */
lcbio_status_t lcbconn_Erb_slurp(lcbconn_t conn);

/* Write as much data from the write buffer until blocked */
lcbio_status_t lcbconn_Erb_write(lcbconn_t conn);

int lcbconn_is_flushed(lcbconn_t conn);
/**
 * Indicates that buffers should be read into or written from
 * @param conn the connection
 * @param events a set of event bits to request
 * @param clear_existing whether to clear any existing 'want' events. By
 * default, the existing events are AND'ed with the new ones.
 */
void lcbconn_set_want(lcbconn_t conn, short events, int clear_existing);

/**
 * Apply the 'want' events. This means to start (waiting for) reading and
 * writing.
 */
void lcbconn_apply_want(lcbconn_t conn);

int lcb_flushing_buffers(lcb_t instance);

/**
 * Call this to unpack any related data related with the operation and the
 * socket.
 *
 * @param sock The socket upon which the data was received
 * @param event either LCB_READ_EVENT or LCB_WRITE_EVENT
 * @param nr the number of bytes read (for READ) or a status code (for WRITE)
 * @param wbuf The opaque buffer, if any, which was passed
 * @param datap A pointer to be set to the related connection's "Data" field.
 *
 * @return true on success. false on failure. On failure you _MUST_ return
 * from your function and perform no further action
 */
int lcbconn_Crb_enter(lcb_sockdata_t *sock,
                      short event, lcb_ssize_t nr,
                      void *wbuf, void **datap);

lcb_socket_t lcb_gai2sock(struct lcb_iotable_st *io,
                          struct addrinfo **curr_ai,
                          int *connerr);

lcb_sockdata_t *lcb_gai2sock_v1(struct lcb_iotable_st *io,
                                struct addrinfo **ai,
                                int *connerr);

int lcb_getaddrinfo(struct lcb_settings_st *settings,
                    const char *hostname,
                    const char *servname,
                    struct addrinfo **res);


struct hostlist_st;
struct lcb_host_st;

lcb_error_t lcbconn_next_node(lcbconn_t conn,
                              struct hostlist_st *hostlist,
                              lcbconn_params *params,
                              char **errinfo);

lcb_error_t lcbconn_cycle_nodes(lcbconn_t conn,
                                        struct hostlist_st *hostlist,
                                        lcbconn_params *params,
                                        char **errinfo);

/**
 * Populates the 'nistrs' pointers with the local and remote endpoint
 * addresses as strings.
 * @param conn a connected object
 * @param nistrs an allocated structure
 * @return true on failure, false on error.
 */
int lcb_get_nameinfo(lcbconn_t conn, struct lcb_nibufs_st *nistrs);



struct lcb_io_use_st {
    /** Set this to 1 if using the "Easy I/O" mode */
    int easy;

    /** User data to be associated with the connection */
    void *udata;

    lcb_io_generic_cb error;

    union {
        struct {
            /** Event handler for V0 I/O */
            lcb_event_handler_cb v0_handler;
            lcb_ioC_write2_callback v1_write;
            lcb_io_read_cb v1_read;
        } ex;
        struct {
            /** Easy handlers */
            lcb_io_generic_cb read;
        } easy;
    } u;
};

/**
 * These two functions take ownership of the specific handlers installed
 * within the connection object. They are intended to be used as safe ways
 * to handle a connection properly. They are also required to maintain order
 * in case one subsystem transfers a connection to another subsystem.
 */

void lcbconn_use(lcbconn_t conn, const struct lcb_io_use_st *use);

/**
 * Populates an 'io_use' structure for extended I/O callbacks
 */
void lcbconn_use_ex(struct lcb_io_use_st *use,
                    void *data,
                    lcb_event_handler_cb v0_handler,
                    lcb_io_read_cb v1_read_cb,
                    lcb_ioC_write2_callback v1_write_cb,
                    lcb_io_generic_cb error_cb);

/**
 * Populates an 'io_use' structure for simple I/O callbacks
 */
LCB_INTERNAL_API
void lcbconn_use_easy(struct lcb_io_use_st *use,
                      void *data,
                      lcb_io_generic_cb read_cb,
                      lcb_io_generic_cb err_cb);

/** Private */
void lcb__io_wire_easy(struct lcb_io_use_st *use);

/**
 * Initialize an 'empty' connection to with an initialized connection 'from'.
 * The target connection shall contain the source's socket resources and
 * structures, and shall be initialized with the callback parameters
 * specified in 'use'
 *
 * The intention of this function is to allow the assignment/transferring
 * of connections without requiring connections themselves to be pointers
 * and also to allow for a clean and programmatic way to 'own' an existing
 * connection.
 *
 * @param from the connection to use. The connection must be "clear",
 * meaning it must not have any pending events on it
 *
 * @param to the target connection to be populated. This connection must
 * be in an uninitialized state (i.e. no pending connect and no pending
 * I/O).
 *
 * @param use the structure containing the relevant callbacks and user
 * specified data to employ.
 */
LCB_INTERNAL_API
void lcbconn_transfer(lcbconn_t from,
                      lcbconn_t to, const struct lcb_io_use_st *use);

const lcb_host_t * lcbconn_get_host(const lcbconn_t);

/**
 * Schedule an asynchronous error to be sent to the error handler. The common
 * error callback will be invoked
 * @param conn the connection to set the error on
 * @param err the error value visible as the 'last_error' variable within
 * the connection object.
 *
 * It is safe to call this function multiple times. Multiple calls to this
 * function may result in possibly only a single call.
 */
void lcbconn_senderr(lcbconn_t conn, int err);

#define LCB_CONN_DATA(conn) (conn->data)

#ifdef __cplusplus
}
#endif

#endif /* LCBIO_H */
