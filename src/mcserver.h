#ifndef LCB_MCSERVER_H
#define LCB_MCSERVER_H

#include "cbsasl/cbsasl.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lcb_server_st;
struct negotiation_context;
typedef void (*negotiation_callback)(struct negotiation_context *, lcb_error_t);

struct negotiation_context {
    cbsasl_conn_t *sasl;
    /** Selected mechanism */
    char *mech;
    /** Mechanism length */
    unsigned int nmech;
    /** Backref */
    struct lcb_server_st *server;
    /** Callback */
    negotiation_callback complete;

    /** Error context */
    struct {
        char *msg;
        lcb_error_t err;
    } errinfo;
};

/**
 * The structure representing each couchbase server
 */
typedef struct lcb_server_st {
    /** The server index in the list */
    int index;
    /** Non-zero for node is using for configuration */
    int is_config_node;
    /** The server endpoint as hostname:port */
    char *authority;
    /** The Couchbase Views API endpoint base */
    char *couch_api_base;
    /** The REST API server as hostname:port */
    char *rest_api_server;
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

    int connection_ready;

    /**
     * This flag is for use by server_send_packets. By default, this
     * function calls apply_want, but this is unsafe if we are already
     * inside the handler, because at this point the read buffer may not
     * have been owned by us, while a read event may still be requested.
     *
     * If this is the case, apply_want will not be called from send_packets
     * but it will be called when the event handler regains control.
     */
    int inside_handler;

    /* Pointer back to the instance */
    lcb_t instance;
    struct lcb_connection_st connection;
    struct negotiation_context *negotiation;
} lcb_server_t;


/**
 * Starts negotiation on an initialized server object. The server must already
 * be in a connected state and must not already be in the process of a SASL
 * negotiation.
 * @param server the server for which to negotiate
 * @param remote a string of host:port for the remote end of the connection
 * @param local a string of host:port for the local end of the connection
 * @param callback a callback to be invoked when the negotiation succeeds or
 * fails. The callback will only be called if the return value is successful.
 * Additionally, if the callback is not successful, it MUST destroy the I/O
 * loop within the server structure.
 *
 * @return LCB_SUCCESS on success, an error code on failure.
 *
 * Note that this function does not check if negotiation is ready or note.
 */
lcb_error_t lcb_negotiation_init(struct lcb_server_st *server,
                                 const char *remote,
                                 const char *local,
                                 negotiation_callback callback);


/**
 * Destroys any resources created by negotiation_init.
 * This is safe to call even if negotiation_init itself was not called.
 */
void lcb_negotiation_destroy(struct lcb_server_st *server);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* LCB_MCSERVER_H */
