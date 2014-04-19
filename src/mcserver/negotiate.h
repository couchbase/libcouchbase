#ifndef LCB_MCSERVER_NEGOTIATE_H
#define LCB_MCSERVER_NEGOTIATE_H
#include <libcouchbase/couchbase.h>
#include <lcbio/lcbio.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief SASL Negotiation routines
 *
 * @defgroup LCB_SASL Server/SASL Negotiation
 * @details
 * This module contains routines to initialize a server and authenticate it
 * against a cluster. In the future this will also be used to handle things
 * such as TLS negotiation and the HELLO command
 * @addtogroup LCB_SASL
 * @{
 */

struct lcb_settings_st;
typedef struct mc_SASLREQ *mc_pSASLREQ;
typedef struct mc_SASLINFO *mc_pSASLINFO;

/**
 * @brief Start SASL negotiation on a connected socket
 *
 * This will start negotiation on the socket. Once complete (or an error has
 * taken place) the `callback` will be invoked with the result.
 *
 * @param sock A connected socket to use. Its reference count will be increased
 * @param settings A settings structure. Used for auth information as well as
 * logging
 * @param tmo Time in microseconds to wait until the negotiation is done
 * @param callback A callback to invoke when a result has been received
 * @param data User-defined pointer passed to the callback
 * @return A new handle which may be cancelled via mc_sasl_cancel(). As with
 * other cancellable requests, once this handle is cancelled a callback will
 * not be received for it, and once the callback is received the handle may not
 * be cancelled as it will point to invalid memory.
 *
 * Once the socket has been negotiated successfuly, you may then use the
 * mc_sasl_get() function to query the socket about various negotiation aspects
 *
 * @code{.c}
 * lcbio_CONNREQ creq;
 * mc_pSASLREQ req;
 * req = mc_sasl_start(sock, settings, tmo, callback, data);
 * LCBIO_CONNREQ_MKGENERIC(req, mc_sasl_cancel);
 * @endcode
 *
 * @see lcbio_connreq_cancel()
 * @see LCBIO_CONNREQ_MKGENERIC
 */
mc_pSASLREQ
mc_sasl_start(
        lcbio_SOCKET *sock, struct lcb_settings_st *settings,
        uint32_t tmo, lcbio_CONNDONE_cb callback, void *data);

/**
 * @brief Cancel a pending SASL negotiation request
 * @param handle The handle to cancel
 */
void
mc_sasl_cancel(mc_pSASLREQ handle);

/**
 * @brief Get an opaque handle representing the negotiated state of the socket
 * @param sock The negotiated socket
 * @return the `SASLINFO` structure if the socket is negotiated, or `NULL` if
 * the socket has not been negotiated.
 *
 * @see mc_sasl_getmech()
 */
mc_pSASLINFO
mc_sasl_get(lcbio_SOCKET *sock);

/**
 * @brief Get the mechanism employed for authentication
 * @param info pointer retrieved via mc_sasl_get()
 * @return A string indicating the mechanism used. This may be `PLAIN` or
 * `CRAM-MD5`.
 */
const char *
mc_sasl_getmech(mc_pSASLINFO info);

/**@}*/

#ifdef __cplusplus
}
#endif
#endif
