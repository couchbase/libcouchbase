#ifndef LCBIO_CONNECTION_H
#define LCBIO_CONNECTION_H
#include <libcouchbase/couchbase.h>
#include "list.h"
#include "logging.h"
#include "settings.h"
#include "hostlist.h"
#ifdef __cplusplus
extern "C" {
#endif

struct lcbio_PROTOCTX;
struct lcbio_CONNSTART;
struct lcbio_MGRREQ;

typedef struct lcbio_CONNSTART *lcbio_pCONNSTART;
typedef struct lcbio_MGRREQ *lcbio_pMGRREQ;
typedef struct lcbio_TABLE *lcbio_pTABLE;
typedef struct lcbio_TIMER *lcbio_pTIMER, *lcbio_pASYNC;

#ifdef WIN32
typedef DWORD lcbio_OSERR;
#else
typedef int lcbio_OSERR;
#endif

typedef enum {
    LCBIO_COMPLETED = 0,
    LCBIO_PENDING,
    LCBIO__SUCCESS_MAX,
    LCBIO_IOERR,
    LCBIO_INTERR,
    LCBIO_SHUTDOWN
} lcbio_IOSTATUS;

#define LCBIO_WFLUSHED LCBIO_COMPLETED
#define LCBIO_CANREAD LCBIO_COMPLETED
#define LCBIO_IS_OK(s) ((s) < LCBIO__SUCCESS_MAX)


typedef enum {
    LCBIO_PROTOCTX_SASL = 1,
    LCBIO_PROTOCTX_POOL,
    LCBIO_PROTOCTX_HOSTINFO
} lcbio_PROTOID;

/**
 * A protocol context is an object which is bound to the actual low level
 * socket connection rather than the logical socket owner. This is used for
 * resources which operate on the TCP state (such as encryption or authentication)
 * or which employ socket reuse (for things such as pooling).
 */
typedef struct lcbio_PROTOCTX {
    lcb_list_t ll;
    lcbio_PROTOID id; /* identifier for the context */
    void (*dtor)(struct lcbio_PROTOCTX *);
} lcbio_PROTOCTX;

typedef struct {
    unsigned naddr;
    struct sockaddr_storage sa_remote;
    struct sockaddr_storage sa_local;
    lcb_host_t ep; /* host:port for easy comparison */
} lcbio_CONNINFO;

typedef struct {
    lcbio_pTABLE io;
    lcb_settings *settings; /* used for logging */
    void *ctx; /* opaque "current" context */
    lcbio_CONNINFO *info; /* information about current connection */
    lcbio_OSERR last_error; /* last OS error */
    unsigned refcount; /* refcount on socket */
    union {
        lcb_sockdata_t *sd;
        lcb_socket_t fd;
    } u;
    lcb_list_t protos; /* linked list of PROTOCTX structures */
} lcbio_SOCKET;

/**
 * Invoked when the connection result is ready
 * @param s the socket to use. You should call lcbio_ref() on it. May be NULL
 *        in the case of an error
 * @param arg user provided argument to the lcbio_connect() function
 * @param err an error code (if connection is NULL)\
 * @param syserr the raw errno variable received.
 */
typedef void (*lcbio_CONNDONE_cb)
        (lcbio_SOCKET *s, void *arg, lcb_error_t err, lcbio_OSERR syserr);


/**
 * Schedule a new connection to a remote endpoint.
 *
 * @param iot
 * @param settings
 * @param dest the endpoint to connect to
 * @param timeout number of time to wait for connection
 * @param handler a handler to invoke with the result
 * @param arg the argument passed to the handler
 * @return a CONNSTART handle. The handle may be cancelled (to stop the pending
 *         connection attempt) before the handler is invoked.
 */
lcbio_pCONNSTART
lcbio_connect(lcbio_pTABLE iot,
              lcb_settings *settings,
              lcb_host_t *dest,
              uint32_t timeout,
              lcbio_CONNDONE_cb handler, void *arg);

lcbio_pCONNSTART
lcbio_connect_hl(lcbio_pTABLE iot, lcb_settings *settings,
                 hostlist_t hl, int rollover,
                 uint32_t timeout, lcbio_CONNDONE_cb handler, void *arg);

/**
 * Cancel a pending connection attempt. Once the attempt is cancelled the
 * handler will not be invoked and the CONNSTART object will be invalid.
 *
 * @param cs the CONNSTART handle returned from lcbio_connect(()
 */
void
lcbio_connect_cancel(lcbio_pCONNSTART cs);

/**
 * Shutdown I/O on this socket, scheduling an eventual close. Depending on the
 * I/O implementation, subsequent events may yet still be delivered.
 */
void
lcbio_shutdown(lcbio_SOCKET *);

/**
 * Add a protoctx object to the list of contexts
 * @param socket the socket the context should be added to
 * @param proto the object to be added
 */
void
lcbio_protoctx_add(lcbio_SOCKET *socket, lcbio_PROTOCTX *proto);

/**
 * Retrieve an existing protocol context by its ID
 * @param socket The socket to query
 * @param id The ID of the context
 * @return the context, or NULL if not found
 */
lcbio_PROTOCTX *
lcbio_protoctx_get(lcbio_SOCKET *socket, lcbio_PROTOID id);

/**
 * Remove a protocol context by its ID
 * @param socket socket from which to remove
 * @param id The id of the context to remove
 * @param call_dtor whether the destructor should be invoked
 * @return the returned context, or NULL if not found
 */
lcbio_PROTOCTX *
lcbio_protoctx_delid(lcbio_SOCKET *socket, lcbio_PROTOID id, int call_dtor);

void
lcbio_protoctx_delptr(lcbio_SOCKET *socket, lcbio_PROTOCTX *ctx, int call_dtor);

void
lcbio__protoctx_delall(lcbio_SOCKET *s);

#define lcbio_get_host(sock) (&(sock)->info->ep)

/**
 * Internal destroy function for when the refcount hits 0
 * @private
 */
void
lcbio__destroy(lcbio_SOCKET *s);

/**
 * Reference counting routines for lcb_SOCKET
 */
#define lcbio_ref(s) (s)->refcount++
#define lcbio_unref(s) if ( !--(s)->refcount ) { lcbio__destroy(s); }

lcbio_pTABLE
lcbio_table_new(lcb_io_opt_t io);

void
lcbio_table_unref(lcbio_pTABLE iot);

void
lcbio_table_ref(lcbio_pTABLE iot);

#ifdef __cplusplus
}
#endif
#endif
