#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "include libcouchbase/couchbase.h first"
#endif

#ifndef LCB_IOPS_H
#define LCB_IOPS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int lcb_socket_t;
struct sockaddr;

#ifndef _WIN32
#define LCB_IOV_LAYOUT_UIO
struct lcb_iovec_st {
    void *iov_base;
    size_t iov_len;
};
#else
#define LCB_IOV_LAYOUT_WSABUF
struct lcb_iovec_st {
    ULONG iov_len;
    void *iov_base;
};
#endif

struct lcb_nameinfo_st {
    struct {
        struct sockaddr *name;
        int *len;
    } local;

    struct {
        struct sockaddr *name;
        int *len;
    } remote;
};

typedef struct lcb_iovec_st lcb_IOV;
typedef struct lcb_io_opt_st* lcb_io_opt_t;

/**
 * Callback invoked for all poll-like events
 * @param sock the socket associated with the event
 * @param events the events which activated this callback
 * @param uarg a user-defined pointer
 */
typedef void (*lcb_ioE_callback)
        (lcb_socket_t sock, short events, void *uarg);

/**
 * Create a timer.
 * @param iops the io structure
 * @return an opaque timer handle
 */
typedef void *(*lcb_io_timer_create_fn)
        (lcb_io_opt_t iops);

/**
 * Destroy a timer previously created with timer_create_fn
 * @param iops the io structure
 * @param timer the opaque handle
 *
 * The timer must have already been cancelled, if active
 */
typedef void (*lcb_io_timer_destroy_fn)
        (lcb_io_opt_t iops, void *timer);

/**
 * Cancel and unregister a pending timer. If the timer has already
 * fired, this does nothing
 * @param iops the I/O structure
 * @param timer the timer to cancel.
 */
typedef void (*lcb_io_timer_cancel_fn)
        (lcb_io_opt_t iops, void *timer);

/**
 * Schedule a timer to be fired within usec microseconds from now
 * @param iops the I/O structure
 * @param timer a timer previously created with timer_create
 * @param usecs the timer interval
 * @param uarg the user-defined pointer to be passed in the callback
 * @param callback the callback to invoke
 */
typedef int (*lcb_io_timer_schedule_fn)
        (lcb_io_opt_t iops, void *timer,
                lcb_uint32_t usecs,
                void *uarg,
                lcb_ioE_callback callback);


/**
 * Create an event object. An event object may be used to monitor a socket
 * for given I/O readiness events
 * @param iops the I/O structure
 */
typedef void *(*lcb_ioE_event_create_fn)
        (lcb_io_opt_t iops);

/**
 * Destroy an event object. The object must not be active
 * @param iops the I/O structure
 * @param event the event to free
 */
typedef void (*lcb_ioE_event_destroy_fn)
        (lcb_io_opt_t iops, void *event);

/**
 * Unregister any pending event watchers on the socket and event
 * @param iops the I/O structure
 * @param sock the socket associated with the event
 * @param event the opaque event object
 */
typedef void (*lcb_ioE_event_cancel_fn)
        (lcb_io_opt_t iops, lcb_socket_t sock, void *event);


/** Data is available for reading */
#define LCB_READ_EVENT 0x02
/** Data can be written */
#define LCB_WRITE_EVENT 0x04
/** Exceptional condition ocurred on socket */
#define LCB_ERROR_EVENT 0x08
#define LCB_RW_EVENT (LCB_READ_EVENT|LCB_WRITE_EVENT)

/**
 * Associate an event with a socket, requesting notification when one of
 * the events specified in 'flags' becomes available on the socket
 * @param iops the IO context
 * @param socket the socket to watch
 * @param event the event to associate with the socket
 * @param evflags a bitflag of events to watch. This is one of LCB_READ_EVENT,
 * LCB_WRITE_EVENT, or LCB_RW_EVENT.
 * Note that the callback may _also_ receive LCB_ERROR_EVENT but this cannot
 * be requested as an event to watch for.
 *
 * @param uarg a user defined pointer to be passed to the callback
 * @param callback the callback to invoke when one of the events becomes
 * ready
 */
typedef int (*lcb_ioE_event_watch_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t socket,
                void *event,
                short evflags,
                void *uarg,
                lcb_ioE_callback callback);

/** See recv(2) */
typedef lcb_ssize_t (*lcb_ioE_recv_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t sock,
                void *target_buf,
                lcb_size_t buflen,
                int _unused_flags);

/** See send(2) */
typedef lcb_ssize_t (*lcb_ioE_send_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t sock,
                const void *srcbuf,
                lcb_size_t buflen,
                int _unused_flags);

/** See readv(2) */
typedef lcb_ssize_t (*lcb_ioE_recvv_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t sock,
                struct lcb_iovec_st *iov,
                lcb_size_t niov);

/** See writev(2) */
typedef lcb_ssize_t (*lcb_ioE_sendv_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t sock,
                struct lcb_iovec_st *iov,
                lcb_size_t niov);

/** See socket(2) */
typedef lcb_socket_t (*lcb_ioE_socket_fn)
        (lcb_io_opt_t iops,
                int domain,
                int type,
                int protocol);

/** See connect(2) */
typedef int (*lcb_ioE_connect_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t sock,
                const struct sockaddr *dst,
                unsigned int addrlen);

/** See bind(2) */
typedef int (*lcb_ioE_bind_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t sock,
                const struct sockaddr *srcaddr,
                unsigned int addrlen);

/** See listen(2) */
typedef int (*lcb_ioE_listen_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t bound_sock,
                unsigned int queuelen);

/** See accept(2) */
typedef lcb_socket_t (*lcb_ioE_accept_fn)
        (lcb_io_opt_t iops,
                lcb_socket_t lsnsock);

/** See close(2) */
typedef void (*lcb_ioE_close_fn)
        (lcb_io_opt_t iops, lcb_socket_t sock);


struct ringbuffer_st;
struct lcb_connection_st;

struct lcb_buf_info {
    /**
     * This is an allocated buffer. The IOPS plugin will free this
     * when the containing structure is destroyed. This must be freed
     * using lcb_mem_free
     */
    char *root;

    /** Size of the allocated buffer */
    lcb_size_t size;

    /**
     * Ringbuffer structure used by lcb internally. Its contents are not
     * public, but it will be freed by the IOPS plugin when the containing
     * structure is destroyed as well.
     *
     * Should be freed using lcb_mem_free
     */
    struct ringbuffer_st *ringbuffer;

    /**
     * A pair of iov structures. This is always mapped to the 'root'
     * and should never be freed directly.
     */
    struct lcb_iovec_st iov[2];
};

typedef struct lcb_sockdata_st {
    /**
     * Underlying socket/handle
     */
    lcb_socket_t socket;

    /**
     * Pointer to the parent IOPS structure
     */
    lcb_io_opt_t parent;

    /**
     * The underlying connection object:
     */
    struct lcb_connection_st *lcbconn;

    /**
     * Whether libcouchbase has logically 'closed' this socket.
     * For use by libcouchbase only.
     * Handy if we get a callback from a pending-close socket.
     */
    int closed;
    int is_reading;

    /**
     * Pointer to underlying buffer and size of the iov_r field.
     * This is owned by the IO plugin until the read operation has
     * completed.
     */
    struct lcb_buf_info read_buffer;
} lcb_sockdata_t;

/**
 * IO plugins should subclass this if there is any additional
 * metadata associated with a 'write' structure. The 'iov' fields
 * contain memory pointed to by libcouchbase, and should not be modified
 * outside of libcouchbase, though the IO plugin should read its
 * contents.
 *
 * A valid structure should be returned via io->create_writebuf and should
 * be released with io->free_writebuf. These functions should only
 * allocate the *structure*, not the actual buffers
 */
typedef struct lcb_io_writebuf_st {
    /**
     * Because the pointer to the cursock's "privadata" may no longer
     * be valid, use a direct pointer to the IO structure to free the
     * buffer
     */
    struct lcb_io_opt_st *parent;

    struct lcb_buf_info buffer;
} lcb_io_writebuf_t;


/**
 * Create an opaque socket handle
 * @param iops the IO context
 * @param domain socket address family, e.g. AF_INET
 * @param type the transport type, e.g. SOCK_STREAM
 * @param protocol the IP protocol, e.g. IPPROTO_TCP
 * @return a socket pointer or NULL on failure.
 */
typedef lcb_sockdata_t* (*lcb_ioC_socket_fn)
        (lcb_io_opt_t iops,
                int domain,
                int type,
                int protocol);

/**
 * Callback invoked for a connection result.
 * @param socket the socket which is being connected
 * @param status the status. 0 for success, nonzero on failure
 */
typedef void (*lcb_io_connect_cb)(lcb_sockdata_t *socket, int status);

/**
 * Request a connection for a socket
 * @param iops the IO context
 * @param sd the socket pointer
 * @param dst the address to connect to
 * @param naddr the size of the address len, e.g. sizeof(struct sockaddr_in)
 * @param callback the callback to invoke when the connection status is determined
 * @return 0 on success, nonzero if a connection could not be scheduled.
 */
typedef int (*lcb_ioC_connect_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sd,
                const struct sockaddr *dst,
                unsigned int naddr,
                lcb_io_connect_cb callback);

/**
 * Callback invoked when a new client connection has been established
 * @param sd_server the server listen socket
 * @param sd_client the new client socket
 * @param status if there was an error accepting (in this case, sd_client is NULL
 */
typedef void (lcb_ioC_serve_callback)
        (lcb_sockdata_t *sd_server,
                lcb_sockdata_t *sd_client,
                int status);

/**
 * Specify that the socket start accepting connections. This should be called
 * on a newly created non-connected socket
 * @param iops the I/O context
 * @param server_socket the socket used to listen with
 * @param sockaddr the local address for listening
 * @param callback the callback to invoke for each new connection
 */
typedef int (*lcb_ioC_serve_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *server_socket,
                const struct sockaddr *listen_addr,
                lcb_ioC_serve_callback callback);

/**
 * Called when data has been read
 * @param sd the socket
 * @param nread the number of bytes read, or < 1 on error
 */
typedef void (*lcb_ioC_read_callback)
        (lcb_sockdata_t *sd, lcb_ssize_t nread);
#define lcb_io_read_cb lcb_ioC_read_callback

/**
 * Start reading data on  socket. The data is read into the socket's internal
 * IOV structure
 * @param sd the socket from which to read
 * @param callback the callback to invoke when data has arrived
 */
typedef int (*lcb_ioC_read_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sd,
                lcb_ioC_read_callback callback);

/**
 * Request address information on a connected socket
 * @param iops the I/O context
 * @param sock the socket from which to retrieve information
 * @param ni a nameinfo structure to populate with the relevant details
 */
typedef int (*lcb_ioC_nameinfo_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sock,
                struct lcb_nameinfo_st *ni);

/**
 * Allocate a 'write context' buffer. This buffer may be used to contain IOV
 * information about buffers to write.
 * @param iops the I/O context
 * @param sd the socket which will eventually write the buffer. Note that this
 * does not schedule a write. The socket is present so that the I/O system
 * may optimize by perhaps including an embedded writebuf structure within a
 * socket rather than allocating always off the heap
 *
 * @return a new writebuf structure
 */
typedef lcb_io_writebuf_t* (*lcb_ioC_wballoc_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sd);

/**
 * Release the writebuf structure. This structure _must_ be owned by the user.
 * This means that it must not be part of a pending write operation
 * @param iops the IO context
 * @param sd the socket with which the writebuf is associated
 * @param wb the writebuf to release
 */
typedef void (*lcb_ioC_wbfree_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sd,
                lcb_io_writebuf_t *wb);

/**
 * Called when the writebuf's contents have been flushed (or an error has
 * occurred)
 * @param sd the socket
 * @paam flushed_wb the writebuf whose contents have been flushed
 * @param status nonzero on error
 */
typedef void (*lcb_ioC_write_callback)
        (lcb_sockdata_t *sd,
                lcb_io_writebuf_t *flushed_wb,
                int status);
#define lcb_io_write_cb lcb_ioC_write_callback

/**
 * Write the contents of a writebuf structure to the network
 * @param iops the IO context
 * @param sd the socket on which to send the data
 * @param buf_to_flush the writebuf structure
 * @param callback the callback to invoke when flushed
 */
typedef int (*lcb_ioC_write_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sd,
                lcb_io_writebuf_t *buf_to_flush,
                lcb_ioC_write_callback callback);


/**
 * Callback for the "write2" function
 * @param sd the socket
 * @param status nonzero on error
 * @param arg the opaque handle passed in the write2 call
 */
typedef void (*lcb_ioC_write2_callback)
        (lcb_sockdata_t *sd,
                int status,
                void *arg);

/**
 * Alternate write function. This does not require a writebuf structure and
 * can handle more than two IOV structures
 * @param iops the I/O context
 * @param sd the socket on which to send
 * @param iov an array of IOV structures
 * @param niov the number of IOV structures within the array
 * @param uarg an opaque pointer to be passed in the callback
 * @param callback the callback to invoke
 */
typedef int (*lcb_ioC_write2_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sd,
                struct lcb_iovec_st *iov,
                lcb_size_t niov,
                void *uarg,
                lcb_ioC_write2_callback callback);


/**
 * Alternate read callback
 * @param sd the socket
 * @param nread number of bytes read, or -1 on error
 * @param arg user provided argument for callback.
 */
typedef void (*lcb_ioC_read2_callback)
        (lcb_sockdata_t *sd, lcb_ssize_t nread, void *arg);

/**
 * Alternate read function. This does not use the embedded readbuf structure
 * and can handle more than two IOV structures
 * @param iops the I/O context
 * @param sd the socket on which to read
 * @param iov an array of IOV structures
 * @param niov the number of IOV structures within the array
 * @param uarg a pointer passed to the callback
 * @param callback the callback to invoke
 * @return 0 on success, nonzero on error
 *
 * The IOV array itself shall copied (if needed) into the I/O implementation
 * and thus does not need to be kept in memory after the function has been
 * called. Note that the underlying buffers _do_ need to remain valid until
 * the callback is received.
 */
typedef int (*lcb_ioC_read2_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sd,
                lcb_IOV *iov,
                lcb_size_t niov,
                void *uarg,
                lcb_ioC_read2_callback callback);

/**
 * Request an asynchronous close for the specified socket. This merely releases
 * control from the library over to the plugin for the specified socket and
 * does _not_ actually imply that the resources have been closed.
 *
 * Notable, callbacks for read and write operations will _still_ be invoked
 * in order to maintain proper resource deallocation. However the socket's
 * closed field will be set to true.
 *
 * @param iops the I/O context
 * @param sd the socket structure
 */
typedef unsigned int (*lcb_ioC_close_fn)
        (lcb_io_opt_t iops,
                lcb_sockdata_t *sd);

typedef void (*lcb_io_start_fn)(lcb_io_opt_t iops);
typedef void (*lcb_io_stop_fn)(lcb_io_opt_t iops);

/** NOT USED */
LCB_DEPRECATED(typedef void (*lcb_io_error_cb)(lcb_sockdata_t *socket));

#define LCB_IOPS_BASE_FIELDS \
    void *cookie; \
    int error; \
    int need_cleanup;

/**
 * IOPS For poll-style notification, AKA 'v0'
 */
struct lcb_iops_evented_st {
    LCB_IOPS_BASE_FIELDS

    lcb_ioE_socket_fn socket;
    lcb_ioE_connect_fn connect;
    lcb_ioE_recv_fn recv;
    lcb_ioE_send_fn send;
    lcb_ioE_recvv_fn recvv;
    lcb_ioE_sendv_fn sendv;
    lcb_ioE_close_fn close;

    lcb_io_timer_create_fn create_timer;
    lcb_io_timer_destroy_fn destroy_timer;
    lcb_io_timer_cancel_fn delete_timer;
    lcb_io_timer_schedule_fn update_timer;

    lcb_ioE_event_create_fn create_event;
    lcb_ioE_event_destroy_fn destroy_event;
    lcb_ioE_event_watch_fn update_event;
    lcb_ioE_event_cancel_fn delete_event;

    lcb_io_stop_fn stop_event_loop;
    lcb_io_start_fn run_event_loop;
};

/**
 * IOPS optimized for IOCP-style IO.
 * The non-IO routines are intended to be binary compatible
 * with the older v0 structure, so I don't have to change too
 * much code initially. Hence the 'pad'.
 * The intent is that the following functions remain
 * ABI-compatible with their v0 counterparts:
 *
 * - create_timer
 * - destroy_timer
 * - update_timer
 * - cookie
 * - error
 * - need_cleanup
 * - run_event_loop
 * - stop_event_loop
 *
 * - The send/recv functions have been replaced with completion-
 *    oriented counterparts of start_write and start_read;
 *
 * - connect has been replace by start_connect
 *
 * - update_event, delete_event, and destroy_event are not
 *   available in v1.
 *
 * - close is asynchronous, and is implied in destroy_socket.
 *   destroy_socket will only be called once all pending
 *   operations have been completed.
 *
 * Note that the 'destructor' itself *must* be asynchronous,
 * as 'destroy' may be called when there are still pending
 * operations. In this case, it means that libcouchbase is
 * done with the IOPS structure, but the implementation should
 * check that no operations are pending before freeing the
 * data.
 */
struct lcb_iops_completion_st {
    LCB_IOPS_BASE_FIELDS

    lcb_ioC_socket_fn create_socket;
    lcb_ioC_connect_fn start_connect;
    lcb_ioC_wballoc_fn create_writebuf;
    lcb_ioC_wbfree_fn release_writebuf;
    lcb_ioC_write_fn start_write;
    lcb_ioC_read_fn start_read;
    lcb_ioC_close_fn close_socket;

    lcb_io_timer_create_fn create_timer;
    lcb_io_timer_destroy_fn destroy_timer;
    lcb_io_timer_cancel_fn delete_timer;
    lcb_io_timer_schedule_fn update_timer;

    lcb_ioC_nameinfo_fn get_nameinfo;

    void (*pad1)(void);
    void (*pad2)(void);

    /** No longer used */
    void (*send_error)(struct lcb_io_opt_st*, lcb_sockdata_t*,void(*)(lcb_sockdata_t*));

    lcb_io_stop_fn stop_event_loop;
    lcb_io_start_fn run_event_loop;
};

/** Common functions for starting and stopping timers */
typedef struct lcb_timerprocs_st {
    lcb_io_timer_create_fn create;
    lcb_io_timer_destroy_fn destroy;
    lcb_io_timer_cancel_fn cancel;
    lcb_io_timer_schedule_fn schedule;
} lcb_timer_procs;

/** Common functions for starting and stopping the event loop */
typedef struct lcb_loopprocs_st {
    lcb_io_start_fn start;
    lcb_io_stop_fn stop;
} lcb_loop_procs;

typedef struct lcb_bsdprocs_st {
    lcb_ioE_socket_fn socket0;
    lcb_ioE_connect_fn connect0;
    lcb_ioE_recv_fn recv;
    lcb_ioE_recvv_fn recvv;
    lcb_ioE_send_fn send;
    lcb_ioE_sendv_fn sendv;
    lcb_ioE_close_fn close;
    lcb_ioE_bind_fn bind;
    lcb_ioE_listen_fn listen;
    lcb_ioE_accept_fn accept;
} lcb_bsd_procs;

typedef struct lcb_evprocs_st {
    lcb_ioE_event_create_fn create;
    lcb_ioE_event_destroy_fn destroy;
    lcb_ioE_event_cancel_fn cancel;
    lcb_ioE_event_watch_fn watch;
} lcb_ev_procs;


typedef struct {
    lcb_ioC_socket_fn socket;
    lcb_ioC_close_fn close;
    lcb_ioC_read_fn read;
    lcb_ioC_connect_fn connect;
    lcb_ioC_wballoc_fn wballoc;
    lcb_ioC_wbfree_fn wbfree;
    lcb_ioC_write_fn write;
    lcb_ioC_write2_fn write2;
    lcb_ioC_read2_fn read2;
    lcb_ioC_serve_fn serve;
    lcb_ioC_nameinfo_fn nameinfo;
} lcb_completion_procs;

typedef enum {
    LCB_IOMODEL_EVENT,
    LCB_IOMODEL_COMPLETION
} lcb_iomodel_t;

/**
 * Called with version==2
 *
 * As opposed to the v0 and v1 IOPS structures that require a table to be
 * populated and returned, the v2 IOPS works differently. Specifically, the
 * IOPS population happens at multiple stages:
 *
 * (1) The base structure is returned, i.e. lcb_create_NAME_iops where NAME is
 *     the name of the plugin
 *
 * (2) Once the structure is returned, LCB shall invoke the v.v2.get_procs()
 *     function. The callback is responsible for populating the relevant fields.
 *
 * Note that v0 and v1 I/O structures are now proxied via this mechanism. Note
 * that it _is_ possible to still monkey-patch the IO routines, but ensure the
 * monkey patching takes place _before_ the instance is created (as the
 * instance will initialize its own IO Table)
 *
 *
 * @param version the ABI/API version for the proc structures. Note that
 * ABI is forward compatible for all proc structures, meaning that newer
 * versions will always extend new fields and never replace existing ones.
 *
 * However in order to avoid a situation where a newer version of a plugin
 * is loaded against an older version of the library (in which case the plugin
 * will assume the proc table size is actually bigger than it is) the version
 * serves as an indicator for this
 *
 * @param loop_procs a table to be set to basic loop control routines
 * @param timer_procs a table to be set to the timer routines
 * @param bsd_procs a table to be set to BSD socket API routines
 * @param ev_procs a table to be set to event watcher routines
 * @param completion_procs a table to be set to completion routines
 * @param iomodel the I/O model to be used. If this is IOMODEL_COMPLETION
 * then the contents of bsd_procs will be ignored and completion_procs must
 * be populated. If the mode is IOMODEL_EVENT then the bsd_procs must be
 * populated and completion procs is ignored.
 *
 * Important to note that internally the ev, bsd, and completion procs are
 * defined as a union, thus
 * union {
 *     struct {
 *         lcb_bsd_procs;
 *         lcb_ev_procs;
 *     } event;
 *     struct lcb_completion_procs completion;
 * }
 * thus setting both fields will actually clobber.
 *
 * Note that the library takes ownership of the passed tables and it should
 * not be controlled or accessed by the plugin.
 *
 * Additionally, this function may not have any side effects as it may be called
 * multiple times.
 */
typedef void (*lcb_io_procs_fn)
        (int version,
                lcb_loop_procs *loop_procs,
                lcb_timer_procs *timer_procs,
                lcb_bsd_procs *bsd_procs,
                lcb_ev_procs *ev_procs,
                lcb_completion_procs *completion_procs,
                lcb_iomodel_t *iomodel);

struct lcb_iops2_st {
    LCB_IOPS_BASE_FIELDS
    lcb_io_procs_fn get_procs;
};

/**
 * This number is bumped up each time a new field is added to any of the
 * function tables
 */
#define LCB_IOPROCS_VERSION 2

struct lcb_io_opt_st {
    int version;
    void *dlhandle;
    void (*destructor)(struct lcb_io_opt_st *iops);
    union {
        struct {
            LCB_IOPS_BASE_FIELDS
        } base;

        /** These two names are deprecated internally */
        struct lcb_iops_evented_st v0;
        struct lcb_iops_completion_st v1;
        struct lcb_iops_evented_st v0_INTERNAL;
        struct lcb_iops_completion_st v1_INTERNAL;
        struct lcb_iops2_st v2;
    } v;
};

/**
 * Called with version==0
 * @param version the plugin init API version. This will be 0 for this function
 * @param io a pointer to be set to the I/O table
 * @param cookie a user-defined argument passed to the I/O initializer
 * @return LCB_SUCCESS on success, an error on failure
 */
typedef lcb_error_t (*lcb_io_create_fn)
        (int version, lcb_io_opt_t *io, void *cookie);


#ifdef __cplusplus
}
#endif

#endif
