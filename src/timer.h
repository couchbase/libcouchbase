#ifndef LCB_TIMER_H
#define LCB_TIMER_H

#include <libcouchbase/couchbase.h>

#ifdef __cplusplus
extern "C" {
#endif /** __cplusplus */


typedef enum {
    LCB_TIMER_STANDALONE = 1 << 0,
    LCB_TIMER_PERIODIC = 1 << 1
} lcb_timer_options;


struct lcb_timer_st {
    /** Interval */
    lcb_uint32_t usec;
    int state;
    lcb_timer_options options;
    void *event;

    /** User data */
    const void *cookie;

    /** Callback to invoke */
    lcb_timer_callback callback;

    /** Note that 'instance' may be NULL in this case */
    lcb_t instance;
    lcb_io_opt_t io;
};

typedef lcb_timer_t lcb_async_t;

/**
 * Creates a timer using the io plugins' timer capabilities. The timer
 * may optionally be bound to an instance in which case the lcb_wait
 * called upon the instance will not return until the timer has fired.
 * @param io the I/O instance for the timer
 * @param usec seconds from now at which the timer will fire
 * @param options flag of LCB_TIMER_* options. The options are:
 *  LCB_TIMER_STANDALONE: Don't peg the timer to the instance. This means
 *  the timer will not be associated with a call to lcb_wait and will
 *  thus not control the exiting or entering of the instance' event loop.
 *  The default is a standalone timer (for which instance must be provided)
 *
 *  LCB_TIMER_PERIODIC:
 *  Repeat the call to the timer callback periodically until the timer
 *  is explicitly stopped
 * @param callback the callback to invoke for each interval
 * @param instance the instance to provide for the timer. Required if the
 * timer is not standalone.
 * @param error a pointer to an error which is set if this function failes.
 */
LCB_INTERNAL_API
lcb_timer_t lcb_timer_create2(lcb_io_opt_t io,
                              const void *cookie,
                              lcb_uint32_t usec,
                              lcb_timer_options options,
                              lcb_timer_callback callback,
                              lcb_t instance,
                              lcb_error_t *error);

/**
 * Creates an 'asynchronous call'. An asynchronous call is like a timer
 * except that it has no interval and will be called "immediately" when the
 * event loop regains control. Asynchronous calls are implemented using
 * timers - and specifically, standalone timers. lcb_async_t is currently
 * a typedef of lcb_timer_t
 */
LCB_INTERNAL_API
lcb_async_t lcb_async_create(lcb_io_opt_t io,
                             const void *command_cookie,
                             lcb_timer_callback callback,
                             lcb_error_t *error);

/**
 * Create a simple one-shot standalone timer.
 */
LCB_INTERNAL_API
lcb_timer_t lcb_timer_create_simple(lcb_io_opt_t io,
                                    const void *cookie,
                                    lcb_uint32_t usec,
                                    lcb_timer_callback callback);

#define lcb_async_destroy lcb_timer_destroy


#ifdef __cplusplus
}
#endif /** __cplusplus */
#endif /* LCB_TIMER_H */
