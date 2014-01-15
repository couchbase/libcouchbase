#ifndef LCB_IOTABLE_H
#define LCB_IOTABLE_H

#include <libcouchbase/couchbase.h>

/** NO INTERNAL DEPENDENCIES */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lcb_iotable_st {
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
} lcb_iotable;

#define IOT_IS_EVENT(iot) (iot)->model == LCB_IOMODEL_EVENT
#define IOT_V0EV(iot) (iot)->u_io.v0.ev
#define IOT_V0IO(iot) (iot)->u_io.v0.io
#define IOT_V1(iot) (iot)->u_io.completion
#define IOT_ERRNO(iot) (iot)->p->v.v0.error
#define IOT_START(iot) (iot)->loop.start((iot)->p)
#define IOT_STOP(iot) (iot)->loop.stop((iot)->p)

/** First argument to IO Table */
#define IOT_ARG(iot) (iot)->p

LCB_INTERNAL_API
int
lcb_init_io_table(lcb_iotable *table, lcb_io_opt_t io);

#ifdef __cplusplus
}
#endif
#endif
