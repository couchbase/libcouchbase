#ifndef LCB_MCSERVER_NEGOTIATE_H
#define LCB_MCSERVER_NEGOTIATE_H
#include <libcouchbase/couchbase.h>
#include <lcbio/lcbio.h>
#ifdef __cplusplus
extern "C" {
#endif

struct lcb_settings_st;
typedef struct mc_SASLREQ *mc_pSASLREQ;
typedef struct mc_SASLINFO *mc_pSASLINFO;

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

#ifdef __cplusplus
}
#endif
#endif
