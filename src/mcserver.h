#ifndef LCB_MCSERVER_H
#define LCB_MCSERVER_H
#include <libcouchbase/couchbase.h>
#include <lcbio/lcbio.h>
#include <lcbio/timer-ng.h>
#include <mc/mcreq.h>
#include <netbuf/netbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lcb_settings_st;
typedef struct mc_SASLREQ *mc_pSASLREQ;
typedef struct mc_SASLINFO *mc_pSASLINFO;
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

    /** Pointer back to the instance */
    lcb_t instance;

    lcb_settings *settings;

    /** Whether mcserver_close() was invoked on this server */
    int closed;

    /** IO/Operation timer */
    lcbio_pTIMER io_timer;

    lcbio_CTX *connctx;
    lcbio_CONNREQ connreq;

    /** Request for current connection */
    lcb_host_t curhost;
} lcb_server_t, mc_SERVER;

mc_pSASLREQ
mc_sasl_start(
        lcbio_SOCKET *sock, struct lcb_settings_st *settings,
        uint32_t tmo, lcbio_CONNDONE_cb callback, void *data);

void
mc_sasl_cancel(mc_pSASLREQ handle);

mc_pSASLINFO
mc_sasl_get(lcbio_SOCKET *sock);

const char *
mc_sasl_getmech(mc_pSASLINFO info);

#define MCSERVER_TIMEOUT(c) (c)->settings->operation_timeout

/**
 * Allocate and initialize a new server object. The object will not be
 * connected
 * @param instance the instance to which the server belongs
 * @param ix the server index in the configuration
 * @return the new object or NULL on allocation failure.
 */
mc_SERVER *
mcserver_alloc(lcb_t instance, int ix);

/**
 * Close the server. The resources of the server may still continue to persist
 * internally for a bit until all callbacks have been delivered and all buffers
 * flushed and/or failed.
 * @param server the server to release
 * @param isok whether the server's socket may be reused.
 */
void
mcserver_close(mc_SERVER *server, int isok);

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
mcserver_wire_io(mc_SERVER *server, lcbio_SOCKET *sock);

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
