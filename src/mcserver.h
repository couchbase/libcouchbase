#ifndef LCB_MCSERVER_H
#define LCB_MCSERVER_H

#include <libcouchbase/couchbase.h>
#include "cbsasl/cbsasl.h"
#include "lcbio.h"
#include "timer.h"
#include "connmgr.h"
#include "mc/mcreq.h"
#include "netbuf/netbuf.h"

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

    unsigned int done_;

    /** Callback */
    negotiation_callback complete;

    /** Error context */
    struct {
        char *msg;
        lcb_error_t err;
    } errinfo;

    void *data;

    /** Connection */
    lcbconn_t conn;

    /** Settings structure from whence we get our username/password info */
    struct lcb_settings_st *settings;

    union {
        cbsasl_secret_t secret;
        char buffer[256];
    } u_auth;

    lcb_timer_t timer;

    cbsasl_callback_t sasl_callbacks[4];
};

struct lcb_server_st;

/**
 * The structure representing each couchbase server
 */
typedef struct lcb_server_st {
    /** Pipeline object for command queues */
    mc_PIPELINE pipeline;

    /** The server endpoint as hostname:port */
    char *datahost;

    /** The Couchbase Views API endpoint base */
    char *viewshost;

    /** The REST API server as hostname:port */
    char *resthost;

    /** Whether we are inside an I/O handler for this server */
    int entered;

    /** This is invoked when we have a timeout on an event */
    int dirty;

    /** Reference count on the server structure itself */
    unsigned refcount;
    unsigned nwpending;
    unsigned cflush_errsize;

    /** Pointer back to the instance */
    lcb_t instance;

    /** IO/Operation timer */
    lcb_timer_t io_timer;

    struct lcb_connection_st connection;

    /** Request for current connection */
    connmgr_request *connreq;
    lcb_host_t curhost;
} lcb_server_t, mc_SERVER;


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
struct negotiation_context*
lcb_negotiation_create(
        lcbconn_t conn, struct lcb_settings_st *settings,lcb_uint32_t timeout,
        const char *remote, const char *local, lcb_error_t *err);

struct negotiation_context* lcb_negotiation_get(lcbconn_t conn);

/**
 * Destroys any resources created by negotiation_init.
 * This is safe to call even if negotiation_init itself was not called.
 */
void lcb_negotiation_destroy(struct negotiation_context *ctx);

#define lcb_negotiation_is_busy(conn) \
    ((struct negotiation_context *)ctx)->done_

#define MCCONN_IS_NEGOTIATING(conn) \
    ((conn)->protoctx && \
            ((struct negotiation_context *)(conn)->protoctx)->done_ == 0)

#define MCSERVER_TIMEOUT(c) (c)->instance->settings.operation_timeout

/**
 * Allocate and initialize a new server object. The object will not be
 * connected
 * @param instance the instance to which the server belongs
 * @param ix the server index in the configuration
 * @return the new object or NULL on allocation failure.
 */
mc_SERVER *
mcserver_alloc(lcb_t instance, int ix);

#define mcserver_incref(server) (server)->refcount++

/**
 * Decrease the reference count on the server object. When the count hits zero
 * the server's resources are freed.
 * @param server the server
 * @param ok whether the connection has been clean. This is the return value
 *        of a prior call to mcserver_is_clean().
 *
 * The normal way to use this function is like so:
 * int was_clean = mcserver_is_clean(server);
 * < fail out commands here >
 * mcserver_decref(server, was_clean)
 */
void
mcserver_decref(mc_SERVER *server, int ok);

/**
 * Determines if a server is 'clean'. A 'clean' server is one which does not
 * have any pending I/O operations on it (and thus has no references either
 * in the server or locally pointing to it).
 *
 *
 * Since this function inspects the pending commands to determine whether it
 * is safe or not to re-release the connection, it should only be called _before_
 * any kind of fail-outs are performed. Otherwise a partially scheduled command
 * might still exist inside the network buffer, but be absent from the queue.
 */
int
mcserver_is_clean(mc_SERVER *server);

/**
 * Schedule a flush and potentially flush some immediate data on the server.
 * This is safe to call multiple times, however performance considerations
 * should be taken into account
 */
void
mcserver_flush(mc_SERVER *server);

void
mcserver_wire_io(mc_SERVER *server, lcbconn_t src);

/**
 * Handle a socket error. This function will close the current connection
 * and trigger a failout of any pending commands.
 *
 * This function triggers a configuration refresh
 */
void
mcserver_socket_error(mc_SERVER *server, lcb_error_t err);

/**
 *
 */
void
mcserver_fail_chain(mc_SERVER *server, lcb_error_t err);

/**
 * Returns true or false depending on whether there are pending commands on
 * this server
 */
int
mcserver_has_pending(mc_SERVER *server);

/**
 * Marks any unflushed data inside this server as being already flushed. This
 * should be done within error handling. If subsequent data is flushed on this
 * pipeline to the same connection, the results are undefined.
 */
void
mcserver_errflush(mc_SERVER *server);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* LCB_MCSERVER_H */
