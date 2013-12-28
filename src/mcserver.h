#ifndef LCB_MCSERVER_H
#define LCB_MCSERVER_H

#include <libcouchbase/couchbase.h>
#include "cbsasl/cbsasl.h"
#include "lcbio.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lcb_settings_st;
struct negotiation_context;
typedef void (*negotiation_callback)(struct negotiation_context *, lcb_error_t);


struct negotiation_context {
    cbsasl_conn_t *sasl;

    /** Selected mechanism */
    char *mech;

    /** Mechanism length */
    unsigned int nmech;

    /** Callback */
    negotiation_callback complete;

    /** Error context */
    struct {
        char *msg;
        lcb_error_t err;
    } errinfo;

    void *data;

    /** Connection */
    lcb_connection_t conn;

    /** Settings structure from whence we get our username/password info */
    struct lcb_settings_st *settings;

    union {
        cbsasl_secret_t secret;
        char buffer[256];
    } u_auth;

    cbsasl_callback_t sasl_callbacks[4];
};

/**
 * The structure representing each couchbase server
 */
typedef struct lcb_server_st {
    /** The server index in the list */
    int index;
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
 * Creates a negotiation context. The negotiation context shall use an
 * existing _connected_ connection object and perform memcached SASL
 * negotiation on it.
 *
 * @param conn a connected object
 *
 * @param settings a settings structure to use for retrieving username
 * and password information
 *
 * @param remote a string in the form of host:port representing the remote
 * server address
 *
 * @param local a string in the form of host:port representing the local end
 * of the connection
 *
 * @param err a pointer to an error which will be populated if this function
 * fails.
 *
 * @return a new negotiation context object, or NULL if initialization failed.
 * If initialization failed, err will be set with the reason.
 *
 */
struct negotiation_context* lcb_negotiation_create(lcb_connection_t conn,
                                                   struct lcb_settings_st *settings,
                                                   const char *remote,
                                                   const char *local,
                                                   lcb_error_t *err);

/**
 * Destroys any resources created by negotiation_init.
 * This is safe to call even if negotiation_init itself was not called.
 */
void lcb_negotiation_destroy(struct negotiation_context *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* LCB_MCSERVER_H */
