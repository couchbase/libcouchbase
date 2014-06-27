#ifndef LCB_API3_H
#define LCB_API3_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief
 * Public "V3" API
 */

/**
 * @ingroup MCREQ LCB_PUBAPI
 * @defgroup MCREQ_PUBAPI Memcached/Libcouchbase v3 API
 *
 * @brief
 * Basic command and structure definitions for public API. This represents the
 * "V3" API of libcouchbase.
 *
 *
 * # Scheduling APIs
 *
 * The following operation APIs are low level entry points which create a
 * single operation. To use these operation APIs you should call the
 * lcb_sched_enter() which creates a virtual scope in which to create operations.
 *
 * For each of these operation APIs, the actual API call will insert the
 * created packet into a "Scheduling Queue" (this is done through
 * mcreq_sched_add() which is in mcreq.h). You may add as many items to this
 * scheduling queue as you would like.
 *
 * Note that an operation is only added to the queue if it was able to be
 * scheduled properly. If a scheduling failure occurred (for example, if a
 * configuration is missing, the command had invalid input, or memory allocation
 * failed) then the command will not be placed into the queue.
 *
 * Once all operations have been scheduled you can call
 * lcb_sched_leave() which will place all commands scheduled into the I/O
 * queue.
 *
 * If you wish to _discard_ all scheduled operations (for example, if one of
 * them errored, and your application cannot handle partial scheduling failures)
 * then you may call lcb_sched_fail() which will release all the resources
 * of the packets placed into the temporary queue.
 *
 * # Operation APIs
 *
 * Operation APIs each schedule only a single logical command. These differ from
 * the _V2_ APIs in libcouchbase which schedule multiple commands. In this
 * version of the library, the _V2_ APIs wrap the _V3_ APIs listed here.
 *
 * @addtogroup MCREQ_PUBAPI
 * @{
 */

/** @brief Flags indicating the storage policy for a buffer */
typedef enum {
    LCB_KV_COPY = 0, /**< The buffer should be copied */
    LCB_KV_CONTIG, /**< The buffer is contiguous and should not be copied */
    LCB_KV_IOV /**< The buffer is not contiguous and should not be copied */
} lcb_KVBUFTYPE;

#define LCB_KV_HEADER_AND_KEY LCB_KV_CONTIG

/**
 * @brief simple buf/length structure for a contiguous series of bytes
 */
typedef struct lcb_CONTIGBUF {
    const void *bytes;
    /** Number of total bytes */
    lcb_size_t nbytes;
} lcb_CONTIGBUF;

/** @brief Common request header for all keys */
typedef struct lcb_KEYBUF {
    /**
     * The type of key to provide. This can currently be LCB_KV_COPY (Default)
     * to copy the key into the pipeline buffers, or LCB_KV_HEADER_AND_KEY
     * to provide a buffer with the header storage and the key.
     *
     * TODO:
     * Currently only LCB_KV_COPY should be used. LCB_KV_HEADER_AND_KEY is used
     * internally but may be exposed later on
     */
    lcb_KVBUFTYPE type;
    lcb_CONTIGBUF contig;
} lcb_KEYBUF;

/**
 * @brief Initialize a contiguous request backed by a buffer which should be
 * copied
 * @param req the key request to initialize
 * @param k the key to copy
 * @param nk the size of the key
 */
#define LCB_KREQ_SIMPLE(req, k, nk) do { \
    (req)->type = LCB_KV_COPY; \
    (req)->contig.bytes = k; \
    (req)->contig.nbytes = nk; \
} while (0);

/**
 * Structure for an IOV buffer to be supplied as a buffer. This is currently
 * only used for value buffers
 */
typedef struct lcb_FRAGBUF {
    /** An IOV array */
    lcb_IOV *iov;

    /** Number of elements in iov array */
    unsigned int niov;

    /**
     * Total length of the items. This should be set, if known, to prevent the
     * library from manually traversing the iov array to calculate the length.
     */
    unsigned int total_length;
} lcb_FRAGBUF;

/** @brief Structure representing a value to be stored */
typedef struct lcb_VALBUF {
    /**
     * Value request type. This may be one of:
     * - LCB_KV_COPY: Copy over the value into LCB's own buffers
     *   Use the 'contig' field to supply the information.
     *
     * - LCB_KV_CONTIG: The buffer is a contiguous chunk of value data.
     *   Use the 'contig' field to supply the information.
     *
     * - LCB_KV_IOV: The buffer is a series of IOV elements. Use the 'multi'
     *   field to supply the information.
     */
    lcb_KVBUFTYPE vtype;
    union {
        lcb_CONTIGBUF contig;
        lcb_FRAGBUF multi;
    } u_buf;
} lcb_VALBUF;

/**
 * @brief Common options for commands.
 *
 * This contains the CAS and expiration
 * of the item. These should be filled in if applicable, or they may be ignored.
 */
typedef struct lcb_CMDOPTIONS {
    lcb_cas_t cas;
    lcb_time_t exptime;
} lcb_CMDOPTIONS;

/**
 * @brief Common ABI header for all commands
 */
typedef struct lcb_CMDBASE {
    lcb_uint32_t cmdflags; /**< Common flags for commands */
    lcb_KEYBUF key; /**< Key for the command */
    lcb_KEYBUF hashkey; /**< Hashkey for command */
    lcb_CMDOPTIONS options; /**< Common options */
} lcb_CMDBASE;

/**
 * @brief Base command structure macro used to fill in the actual command fields
 * @see lcb_cmd_st
 */
#define LCB_CMD_BASE \
    lcb_uint32_t cmdflags; \
    lcb_KEYBUF key; \
    lcb_KEYBUF hashkey; \
    lcb_CMDOPTIONS options

typedef lcb_CMDBASE lcb_CMDTOUCH;
typedef lcb_CMDBASE lcb_CMDSTATS;
typedef lcb_CMDBASE lcb_CMDFLUSH;
typedef lcb_CMDBASE lcb_CMDOBSERVE;

#define LCB_RESP_BASE \
    void *cookie; /**< User data associated with request */ \
    const void *key; /**< Key for request */ \
    lcb_SIZE nkey; /**< Size of key */ \
    lcb_cas_t cas; /**< CAS for response (if applicable) */ \
    lcb_error_t rc; /**< Status code */ \
    lcb_U16 version; /**< ABI version for response */ \
    lcb_U16 rflags; /**< Response specific flags */

/**
 * @brief
 * Base response structure for callbacks
 */
typedef struct {
    LCB_RESP_BASE
} lcb_RESPBASE;

typedef struct {
    LCB_RESP_BASE
    const void *value;
    lcb_SIZE nvalue;
    void* bufh;
    lcb_datatype_t datatype;
    lcb_U32 itmflags;
} lcb_RESPGET;

typedef struct {
    LCB_RESP_BASE
    lcb_U64 value;
} lcb_RESPARITH;

typedef struct {
    LCB_RESP_BASE
    lcb_U8 status;
    lcb_U8 ismaster;
    lcb_U32 ttp;
    lcb_U32 ttr;
} lcb_RESPOBSERVE;

#define LCB_RESP_SERVER_BASE \
    LCB_RESP_BASE \
    const char *server;

typedef struct {
    LCB_RESP_SERVER_BASE
} lcb_RESPSERVERBASE;

typedef struct {
    LCB_RESP_SERVER_BASE
    const char *value;
    lcb_SIZE nvalue;
} lcb_RESPSTATS;

typedef lcb_RESPSERVERBASE lcb_RESPFLUSH;
typedef lcb_RESPSERVERBASE lcb_RESPVERBOSITY;

typedef struct {
    LCB_RESP_SERVER_BASE
    const char *mcversion;
    lcb_SIZE nversion;
} lcb_RESPMCVERSION;

typedef struct {
    LCB_RESP_BASE
    lcb_U16 nresponses;
    lcb_U8 exists_master;
    lcb_U8 persisted_master;
    lcb_U8 npersisted;
    lcb_U8 nreplicated;
} lcb_RESPENDURE;

typedef struct {
    LCB_RESP_BASE
    lcb_storage_t op;
} lcb_RESPSTORE;

typedef lcb_RESPBASE lcb_RESPDELETE;
typedef lcb_RESPBASE lcb_RESPTOUCH;
typedef lcb_RESPBASE lcb_RESPUNLOCK;


/**Response flags. These provide additional 'meta' information about the
 * response*/
typedef enum {
    /** No more responses are to be received for this request */
    LCB_RESP_F_FINAL = 0x01,

    /**The response was artificially generated inside the client.
     * This does not contain reply data from the server for the command, but
     * rather contains the basic fields to indicate success or failure and is
     * otherwise empty.
     */
    LCB_RESP_F_CLIENTGEN = 0x02,

    /**The response was a result of a not-my-vbucket error */
    LCB_RESP_F_NMVGEN = 0x04
} lcb_RESPFLAGS;

/**
 * The type of response passed to the callback. This is used to install callbacks
 * for the library and to distinguish between responses if a single callback
 * is used for multiple response types
 */
typedef enum {
    /**Generic callback type. This is only ever used on input, and indicates
     * that this callback should be invoked for any responses which do not have
     * dedicated handlers */
    LCB_CALLBACK_DEFAULT = 0,

    /**Callback invoked for lcb_get3()*/
    LCB_CALLBACK_GET,
    /**Callback invoked for lcb_store3() */
    LCB_CALLBACK_STORE,
    /**Callback invoked for lcb_arithmetic3()*/
    LCB_CALLBACK_ARITHMETIC,
    /**Callback invoked for lcb_touch3()*/
    LCB_CALLBACK_TOUCH,
    /**Callback invoked for lcb_remove3()*/
    LCB_CALLBACK_DELETE,
    /**Callback invoked for lcb_unlock3()*/
    LCB_CALLBACK_UNLOCK,
    /**Callback invoked for lcb_stats3()*/
    LCB_CALLBACK_STATS,
    /**Callback invoked for lcb_server_versions3()*/
    LCB_CALLBACK_VERSIONS,
    /**Callback invoked for lcb_server_verbosity3()*/
    LCB_CALLBACK_VERBOSITY,
    /**Callback invoked for lcb_flush3()*/
    LCB_CALLBACK_FLUSH,
    /**Callback invoked for lcb_observe3()*/
    LCB_CALLBACK_OBSERVE,
    /**Callback invoked for lcb_rget3() */
    LCB_CALLBACK_GETREPLICA,
    /**Callback invoked for lcb_endure3() */
    LCB_CALLBACK_ENDURE,
    LCB_CALLBACK__MAX /* Number of callbacks */
} lcb_CALLBACKTYPE;

typedef void (*lcb_RESP_cb)
        (lcb_t instance, lcb_CALLBACKTYPE cbtype, const lcb_RESPBASE* resp);


LIBCOUCHBASE_API
lcb_RESP_cb
lcb_install_callback3(lcb_t instance, lcb_CALLBACKTYPE cbtype, lcb_RESP_cb cb);

/**@volatile*/
LIBCOUCHBASE_API
void lcb_sched_enter(lcb_t);

/**@volatile*/
LIBCOUCHBASE_API
void lcb_sched_leave(lcb_t);

/**@volatile*/
LIBCOUCHBASE_API
void lcb_sched_fail(lcb_t);

/** @brief Command for retrieving a single item */
typedef struct {
    LCB_CMD_BASE;
    /**If set to true, the `exptime` field inside `options` will take to mean
     * the time the lock should be held. While the lock is held, other operations
     * trying to access the key will fail with an `LCB_ETMPFAIL` error. The
     * item may be unlocked either via `lcb_unlock3()` or via a mutation
     * operation with a supplied CAS
     */
    int lock;
} lcb_CMDGET;

/**
 * @brief Spool a single get operation
 * @volatile
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_get3(lcb_t instance, const void *cookie, const lcb_CMDGET *cmd);

/**
 * @brief Command for counter operations
 */
typedef struct {
    LCB_CMD_BASE;
    /**Delta value. If this number is negative the item on the server is
     * decremented. If this number is positive then the item on the server
     * is incremented */
    lcb_int64_t delta;
    /**If the item does not exist on the server (and `create` is true) then
     * this will be the initial value for the item. */
    lcb_uint64_t initial;
    /**Boolean value. Create the item and set it to `initial` if it does not
     * already exist */
    int create;
} lcb_CMDINCRDECR;
/**
 * @brief Spool a single arithmetic operation
 * @volatile
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_arithmetic3(lcb_t instance, const void *cookie, const lcb_CMDINCRDECR *cmd);

/**
 * @brief Command for lcb_unlock3()
 * @attention `options.cas` must be specified, or the operation will fail on
 * the server
 */
typedef lcb_CMDBASE lcb_CMDUNLOCK;
/** @brief Unlock a previously locked item */
LIBCOUCHBASE_API
lcb_error_t
lcb_unlock3(lcb_t instance, const void *cookie, const lcb_CMDUNLOCK *cmd);

/**
 * @brief Command for requesting an item from a replica
 * @note The `options.exptime` and `options.cas` fields are ignored for this
 * command.
 */
typedef struct {
    LCB_CMD_BASE;
    /** Strategy to use for selecting a replica */
    lcb_replica_t strategy;
    int index;
} lcb_CMDGETREPLICA;
/**
 * @brief Spool a single get-with-replica request
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_rget3(lcb_t instance, const void *cookie, const lcb_CMDGETREPLICA *cmd);

/**@brief Command for storing an item to the server */
typedef struct {
    LCB_CMD_BASE;
    lcb_VALBUF value; /**< Value to store on the server */
    /**These flags are stored alongside the item on the server. They are
     * typically used by higher level clients to store format/type information*/
    lcb_uint32_t flags;
    /**Ignored for now */
    lcb_datatype_t datatype;
    /**Must be assigned*/
    lcb_storage_t operation;
} lcb_CMDSTORE;

#define LCB_VALUE_SIMPLE(scmd, val_buf, val_len) do { \
    scmd->value.type = LCB_KV_COPY; \
    scmd->value.u_buf.contig.bytes = val_buf; \
    scmd->value.u_buf.contig.nbytes = val_len; \
} while (0);

/**
 * @brief Spool a single storage request
 * @volatile
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_store3(lcb_t instance, const void *cookie, const lcb_CMDSTORE *cmd);

/**@brief Command for removing an item from the server
 * @note The `options.exptime` field here does nothing. The CAS field may be
 * set to the last CAS received from a previous operation if you wish to
 * ensure the item is removed only if it has not been mutated since the last
 * retrieval
 */
typedef lcb_CMDBASE lcb_CMDREMOVE;
/**@brief Schedule a removal of an item from the server
 * @volatile */
LIBCOUCHBASE_API
lcb_error_t
lcb_remove3(lcb_t instance, const void *cookie, const lcb_CMDREMOVE * cmd);

/**@brief Modify an item's expiration time
 * @volatile*/
LIBCOUCHBASE_API
lcb_error_t
lcb_touch3(lcb_t instance, const void *cookie, lcb_CMDTOUCH *cmd);

/**@volatile*/
LIBCOUCHBASE_API
lcb_error_t
lcb_stats3(lcb_t instance, const void *cookie, const lcb_CMDSTATS * cmd);

/**
 * Multi Command Context API
 * Some commands (notably, OBSERVE and its higher level equivalent, endue)
 * are handled more efficiently at the cluster side by stuffing multiple
 * items into a single packet.
 *
 * This structure defines three function pointers to invoke. The #addcmd()
 * function will add a new command to the current packet, the #done()
 * function will schedule the packet(s) into the current scheduling context
 * and the #fail() function will destroy the context without progressing
 * further.
 *
 * Some commands will return an lcb_MULTICMD_CTX object to be used for this
 * purpose:
 *
 * @code{.c}
 * lcb_MUTLICMD_CTX *ctx = lcb_observe3_ctxnew(instance);
 *
 * lcb_CMDOBSERVE cmd = { 0 };
 * LCB_KREQ_SIMPLE(&cmd.key, "key1", strlen("key1"));
 * ctx->addcmd(ctx, &cmd);
 * LCB_KREQ_SIMPLE(&cmd.key, "key2", strlen("key2"));
 * ctx->addcmd(ctx, &cmd);
 * LCB_KREQ_SIMPLE(&cmd.key, "key3", strlen("key3"));
 * ctx->addcmd(ctx, &cmd);
 *
 * lcb_sched_enter(instance);
 * ctx->done(ctx);
 * lcb_sched_leave(instance);
 * lcb_wait(instance);
 * @endcode
 */
struct lcb_MULTICMD_CTX_st;
typedef struct lcb_MULTICMD_CTX_st {
    /**
     * Add a command to the current context
     * @param ctx the context
     * @param cmd the command to add. Note that `cmd` may be a subclass of lcb_CMDBASE
     * @return LCB_SUCCESS, or failure if a command could not be added.
     */
    lcb_error_t (*addcmd)(struct lcb_MULTICMD_CTX_st *ctx, const lcb_CMDBASE *cmd);

    /**
     * Indicate that no more commands are added to this context, and that the
     * context should assemble the packets and place them in the current
     * scheduling context
     * @param ctx The multi context
     * @param cookie The cookie for all commands
     */
    void (*done)(struct lcb_MULTICMD_CTX_st *ctx, const void *cookie);

    /**
     * Indicate that no more commands should be added to this context, and that
     * the context should not add its contents to the packet queues, but rather
     * release its resources. Called if you don't want to actually perform
     * the operations.
     * @param ctx
     */
    void (*fail)(struct lcb_MULTICMD_CTX_st *ctx);
} lcb_MULTICMD_CTX;

/**Set this bit in the cmdflags field to indicate that only the master node
 * should be contacted*/
#define LCB_CMDOBSERVE_F_MASTER_ONLY 1<<16

LIBCOUCHBASE_API
lcb_MULTICMD_CTX *
lcb_observe3_ctxnew(lcb_t instance);

LIBCOUCHBASE_API
lcb_MULTICMD_CTX *
lcb_endure3_ctxnew(lcb_t instance, const lcb_durability_opts_t *options);

/**@volatile*/
LIBCOUCHBASE_API
lcb_error_t
lcb_server_versions3(lcb_t instance, const void *cookie, const lcb_CMDBASE * cmd);

typedef struct {
    /* unused */
    LCB_CMD_BASE;
    const char *server;
    lcb_verbosity_level_t level;
} lcb_CMDVERBOSITY;

/**@volatile*/
LIBCOUCHBASE_API
lcb_error_t
lcb_server_verbosity3(lcb_t instance, const void *cookie, const lcb_CMDVERBOSITY *cmd);

/**@volatile*/
LIBCOUCHBASE_API
lcb_error_t
lcb_flush3(lcb_t instance, const void *cookie, const lcb_CMDFLUSH *cmd);
/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* LCB_API3_H */
