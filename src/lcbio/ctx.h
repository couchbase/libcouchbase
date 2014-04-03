#ifndef LCBIO_CTXEASY_H
#define LCBIO_CTXEASY_H
#include "connect.h"
#include "rdb/rope.h"
#include "ringbuffer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lcbio_CTX *lcbio_pCTX;
typedef struct {
    /** Error handler invoked with the context and the received error */
    void (*cb_err)(lcbio_pCTX, lcb_error_t);

    /**  Read handler invoked with the context and the number of bytes read */
    void (*cb_read)(lcbio_pCTX, unsigned total);

    /** See the wwant/put_ex functions for a description of these callbacks */
    void (*cb_flush_ready)(lcbio_pCTX);
    void (*cb_flush_done)(lcbio_pCTX, unsigned requested, unsigned nflushed);
} lcbio_EASYPROCS;

/** Container buffer handle containing a backref to the original context. */
typedef struct {
    ringbuffer_t rb;
    lcbio_pCTX parent;
} lcbio__EASYRB;

/** Callback invoked right before the context is freed. Used for testing */
typedef void (*lcbio_CTXDTOR_cb)(lcbio_pCTX);

/**
 * The CTX structure represents an ownership of a socket. It provides routines
 * for reading and writing from and to the socket, as well as associating
 * application data with the socket.
 *
 * To create a new context, invoke the ctx_new() function. When you are done
 * with it call the ctx_close() function.
 *
 * To put data, use one of the put() or wwant() functions. To read data, use
 * the rwant function to declare how much data should be read, and then the
 * rpeek/rptr functions to obtain the data when the handler is invoked.
 */
typedef struct lcbio_CTX {
    lcbio_SOCKET *sock; /* Socket resource */
    lcbio_pTABLE io; /* Cached IO table */
    void *data; /* Associative pointer */
    void *event; /* event pointer for E-model I/O */
    lcb_sockdata_t *sd; /* cached SD for C-model I/O */
    lcbio__EASYRB *output; /* for put() */
    lcb_socket_t fd; /* cached FD for E-model I/O */
    char evactive; /* watcher is active for E-model I/O */
    lcb_error_t err; /* pending error */
    rdb_IOROPE ior; /* for reads */
    unsigned npending; /* reference count on pending I/O */
    unsigned rdwant; /* number of remaining bytes to read */
    char wwant; /* flag for put_ex */
    char state; /* internal state */
    char entered; /* inside event handler */
    char schedreq;
    lcbio_pASYNC as_err; /* async error handler */
    lcbio_EASYPROCS procs; /* callbacks */
    const char *subsys; /* handy string for debugging */
} lcbio_CTX;

/**
 * Creates a new easyctx object
 * @param sock the underlying socket object
 * @param data user defined data to associate with context
 * @param procs callback table
 * @return a new context object.
 */
lcbio_CTX *
lcbio_ctx_new(lcbio_SOCKET *sock, void *data, const lcbio_EASYPROCS *procs);


/**
 * Callback invoked when the connection is about to be release
 * @param sock the socket being released
 * @param releasable whether the socket may be reused
 * @param arg an argument passed to the close() function
 * If you wish to reuse the socket (and reusable is true) then the socket's
 * reference count should be incremented.
 */
typedef void
(*lcbio_CTXCLOSE_cb)(lcbio_SOCKET *sock, int releasable, void *arg);

/**
 * Close the context object. This will invalidate any pending I/O operations
 * and subsequent callbacks on the context will not be received. After calling
 * this function, the pointer will be deemed invalid.
 * @param ctx the context
 * @param callback a callback to invoke (see above)
 * @param arg argument passed to the callback
 */
void
lcbio_ctx_close(lcbio_CTX *ctx, lcbio_CTXCLOSE_cb callback, void *arg);

/**
 * @private
 * Used primarily for testing.
 */
void
lcbio_ctx_close_ex(lcbio_CTX *ctx, lcbio_CTXCLOSE_cb cb, void *cbarg,
                   lcbio_CTXDTOR_cb dtor, void *dtor_arg);

/**
 * Add output data to the write buffer
 * @param ctx the context
 * @param buf the buffer to write
 * @param nbuf the size of the buffer to write
 */
void
lcbio_ctx_put(lcbio_CTX *ctx, const void *buf, unsigned nbuf);

/**
 * Invoke the flush_ready() callback when a flush may be invoked. The
 * flush_ready callback may be invoked from within this function itself, or
 * it may be invoked at some point later.
 *
 * In order to ensure that the flush_ready callback is actually invoked (in
 * cases where it is not invoked immediately), call schedule() before returning
 * to the loop.
 *
 * When the flush_ready callback is invoked, you should call put_ex() function
 * multiple times until either no write buffers remain, or the function itself
 * returns a false value.
 *
 * When data is actually flushed to the socket's buffers, the flush_done()
 * callback is invoked. This callback indicates the underlying buffers are
 * no longer required and may be released or reused by the application. Note
 * that the IOV array passed into put_ex is always "Conceptually" copied (i.e.
 * this may be a stack-based structure which does not need to remain valid
 * outside the function call to put_ex() itself).
 *
 * Additionally, note that the number of bytes flushed within the flush_done()
 * callback may not equal the number of bytes initially placed inside the IOVs
 * (i.e. it may be less). In this case the application is expected to update
 * the IOV structures and the origin buffers appropriately.
 *
 * This model allows for efficient handling in both completion and event based
 * environments.
 *
 * For completion-based models, the flush_ready() callback is invoked immediately
 * from the wwant() function, while the flush_done() is dependent on the actual
 * completion of the write.
 *
 * For event-based models, the wwant flag is set inside the context and is then
 * checked by the schedule() function. When the event handler is invoked, the
 * flush_ready() callback is invoked as well - typically in a loop until an
 * EWOULDBLOCK is received on the socket itself.
 */
void
lcbio_ctx_wwant(lcbio_CTX *ctx);

/**
 * This function is to be invoked within the flush_ready() handler (see wwant).
 * It returns true if more data can be written, and false otherwise.
 * @param ctx the context
 * @param iov the IOV array
 * @param niov number of elements in the array
 * @param nb number of total bytes within the array
 */
int
lcbio_ctx_put_ex(lcbio_CTX *ctx, lcb_IOV *iov, unsigned niov, unsigned nb);

typedef struct {
    unsigned remaining;
    void *buf;
    unsigned nbuf;
} lcbio_CTXRDITER;

/**
 * Starts iterating over the read buffers. This is an alternative interface
 * to rptr/radv.
 *
 * The iterator is initialized with ristart and advanced with rinext. When
 * ridone is true the loop has finished:
 *
 * lcbio_CTXRDITER iter;
 * for (lcbio_ctx_ristart(ctx, &iter); !lcbio_ctx_ridone(&iter);
 *      lcbio_ctx_rinext(ctx, &iter) {
 *      void *buf = lcbio_ctx_ribuf(&iter);
 *      unsigned nbuf = lcbio_ctx_risize(&iter);
 *      < do stuff with the buffer >
 * }.
 *
 * When each iteration is complete, the pointer returned by ctx_ribuf is
 * no longer valid.
 *
 * @param ctx the context
 * @param
 */
void
lcbio_ctx_ristart(lcbio_CTX *ctx, lcbio_CTXRDITER *iter, unsigned nb);

void
lcbio_ctx_rinext(lcbio_CTX *ctx, lcbio_CTXRDITER *iter);

#define lcbio_ctx_ridone(iter) (!(iter)->remaining)
#define lcbio_ctx_ribuf(iter) ((iter)->buf)
#define lcbio_ctx_risize(iter) ((iter)->nbuf)

/**
 * Macro to make the for loop a bit nicer looking
 */
#define LCBIO_CTX_ITERFOR(ctx, iter, nb) \
    for (lcbio_ctx_ristart(ctx, iter, nb); !lcbio_ctx_ridone(iter); \
    lcbio_ctx_rinext(ctx, iter))


/**
 * Require that the read callback not be invoked until at least <n>
 * bytes are available within the buffer.
 * @param ctx the context
 * @param n the number of bytes required to be in the buffer before the
 *        callback should be invoked.
 *
 * Note that this flag does _not_ maintain state between successive callbacks.
 * You must call this function each time you need more data as it is cleared
 * before the invocation into the callback.
 */
void
lcbio_ctx_rwant(lcbio_CTX *ctx, unsigned n);

/**
 * Schedule any pending I/O to be scheduled immediately. This must only be
 * called right before returning control to the event loop.
 */
void
lcbio_ctx_schedule(lcbio_CTX *ctx);

#define LCBIO_CTX_RSCHEDULE(ctx, nb) do { \
    lcbio_ctx_rwant(ctx, nb); \
    lcbio_ctx_schedule(ctx); \
} while (0)

/**
 * Get the data associated with the context. This is the pointer specified
 * during the constructor
 */
#define lcbio_ctx_data(ctx) (ctx)->data

/**
 * Get the underlying lcbio_SOCKET
 */
#define lcbio_ctx_sock(ctx) (ctx)->sock

void
lcbio_ctx_senderr(lcbio_CTX *ctx, lcb_error_t err);

void
lcbio_ctx_dump(lcbio_CTX *ctx);

#ifdef __cplusplus
}
#endif
#endif
