#ifndef LCB_IOTABLE_H
#define LCB_IOTABLE_H

#include <libcouchbase/couchbase.h>

/**
 * This file defines the iotable layout as well as various macros associated
 * with its use. The actual "Public" API (i.e. just for passing it around) can
 * be found in <lcbio/connect.h>
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lcbio_TABLE {
    lcb_io_opt_t p;
    lcb_iomodel_t model;
    lcb_timer_procs timer;
    lcb_loop_procs loop;

    union {
        struct {
            lcb_ev_procs ev;
            lcb_bsd_procs io;
        } v0;
        lcb_completion_procs completion;
    } u_io;

    unsigned refcount;
} lcbio_TABLE;

#define IOT_IS_EVENT(iot) (iot)->model == LCB_IOMODEL_EVENT
#define IOT_V0EV(iot) (iot)->u_io.v0.ev
#define IOT_V0IO(iot) (iot)->u_io.v0.io
#define IOT_V1(iot) (iot)->u_io.completion
#define IOT_ERRNO(iot) (iot)->p->v.v0.error
#define IOT_START(iot) (iot)->loop.start((iot)->p)
#define IOT_STOP(iot) (iot)->loop.stop((iot)->p)

/** First argument to IO Table */
#define IOT_ARG(iot) (iot)->p

#ifdef __cplusplus
}
#endif
#endif
