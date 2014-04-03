#ifndef LCBIO_MANAGER_H
#define LCBIO_MANAGER_H
#include "connect.h"
#include "settings.h"
#include "timer.h"
#include "genhash.h"
#include "list.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * General purpose connection manager for LCB sockets. This object is
 * responsible for maintaining and properly handling idle connections
 * and pooling them (optionally).
 */
struct lcbio_MGRREQ;
struct lcbio_MGR;

typedef struct lcbio_MGR {
    genhash_t* ht;
    lcb_settings *settings;
    lcbio_pTABLE io;
    uint32_t tmoidle;
    unsigned maxtotal;
    unsigned maxidle;
    unsigned refcount;
} lcbio_MGR;

/**
 * Create a socket pool controlled by the given settings and IO structure
 */
LCB_INTERNAL_API
lcbio_MGR*
lcbio_mgr_create(lcb_settings *settings, lcbio_pTABLE io);

/**
 * Free the socket pool
 */
LCB_INTERNAL_API
void
lcbio_mgr_destroy(lcbio_MGR *);

/**
 * Request a connection from the socket pool. The semantics and prototype
 * of this function are by design similar to lcbio_connect() as they do the
 * same things.
 * @param mgr the manager to use for connection
 * @param dest the host to connect to
 * @param timeout amount of time to wait for a connection to be estblished
 * @param handler a callback to invoke when the result is ready
 * @param arg an argument passed to the callback
 * @return a request handle which may be cancelled
 */
LCB_INTERNAL_API
struct lcbio_MGRREQ *
lcbio_mgr_get(lcbio_MGR *mgr, lcb_host_t *dest, uint32_t timeout,
              lcbio_CONNDONE_cb handler, void *arg);

/**
 * Cancel a pending request. The callback for the request must have not already
 * been invoked (if it has, use sockpool_put)
 * @param pool the pool which the request was made to
 * @param req the request to cancel
 */
LCB_INTERNAL_API
void
lcbio_mgr_cancel(struct lcbio_MGRREQ *req);

/**
 * Release a socket back into the pool. This means the socket is no longer
 * used and shall be available for reuse for another request. To verify these
 * constraints, the socket's reference count must be one. Once the socket
 * has been released its reference count should not be modified.
 */
LCB_INTERNAL_API
void lcbio_mgr_put(lcbio_SOCKET *sock);

/**
 * Mark a slot as available but discard the current connection. This should be
 * done if the connection itself is "dirty", i.e. has a protocol error on it
 * or is otherwise not suitable for reuse
 */
LCB_INTERNAL_API
void lcbio_mgr_discard(lcbio_SOCKET *sock);

/**
 * Like lcbio_MGR_discard() except the source connection is left untouched. It
 * is removed from the pool instead.
 *
 * Because the lcbio_MGR object itself has internal limits and thresholds on how
 * many leased and/or open connections it can contain, when a connection receives
 * an error it must either be discarded back to the pool (in which case the
 * connection is cleaned up and is freed) or it must be detached (in which case
 * the connection object itself still remains valid, but the pool does not know
 * about it, and all its counters are restored, as with lcbio_MGR_discard).
 *
 * lcbio_MGR_discard() itself is now implemented as the equivalent to:
 *  lcbio_MGR_detach(mgr, conn);
 */
LCB_INTERNAL_API
void lcbio_mgr_detach(lcbio_SOCKET *sock);

/**
 * Dumps the connection manager state to stderr
 */
LCB_INTERNAL_API
void lcbio_mgr_dump(lcbio_MGR *mgr, FILE *out);

#ifdef __cplusplus
}
#endif
#endif /* LCB_SOCKPOOL_H */
