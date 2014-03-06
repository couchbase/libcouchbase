#ifndef MCREQ_PUBLIC_H
#define MCREQ_PUBLIC_H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 ******************************************************************************
 ** Operation Structures                                                     **
 ******************************************************************************
 ******************************************************************************/

/**
 * Basic command and structure definitions for public API. This represents the
 * "V3" API of libcouchbase.
 */

typedef enum {
    LCB_KV_COPY = 0,
    LCB_KV_CONTIG,
    LCB_KV_IOV
} lcb_kvbuf_type_t;

typedef struct lcb_kvbuf_contig_st {
    /**
     * Contiguous bytes of [header] + key. Header is only needed if in
     * no-copy mode. Note that in this case, the header size is implicit in the
     * command per the binary memcached protocol. It is the caller's
     * responsibility to ensure the correct amount of bytes exactly follows the
     * key.
     *
     * Note that the data does not need to be aligned.
     *
     * Also note that the header part of the key _will be modified_.
     */
    const void *bytes;

    /** Number of total bytes */
    lcb_size_t nbytes;
} lcb_kvbuf_contig_t;

typedef struct lcb_krequest_st {
    /**
     * The type of key to provide. This can currently be LCB_KV_COPY (Default)
     * to copy the key into the pipeline buffers, or LCB_KV_CONTIG to provide
     * a buffer with the header storage and the key.
     */
    lcb_kvbuf_type_t type;

    /** 'contig' structure for key buffer */
    lcb_kvbuf_contig_t contig;
} lcb_key_request_t;

#define LCB_KREQ_CONTIG(req, k, nk) do { \
    (req)->type = LCB_KV_CONTIG; \
    (req)->contig.bytes = k; \
    (req)->contig.nbytes = nk; \
} while (0);

#define LCB_KREQ_SIMPLE(req, k, nk) do { \
    (req)->type = LCB_KV_COPY; \
    (req)->contig.bytes = k; \
    (req)->contig.nbytes = nk; \
} while (0);

/**
 * Structure for an IOV buffer to be supplied as a buffer. This is currently
 * only used for value buffers
 */
typedef struct lcb_kvbuf_multi_st {
    /** An IOV array */
    nb_IOV *iov;

    /** Number of elements in iov array */
    unsigned int niov;

    /**
     * Total length of the items. This should be set, if known, to prevent the
     * library from manually traversing the iov array to calculate the length.
     */
    unsigned int total_length;
} lcb_kvbuf_multi_t;

typedef struct lcb_value_request_st {
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
    lcb_kvbuf_type_t vtype;
    union {
        lcb_kvbuf_contig_t contig;
        lcb_kvbuf_multi_t multi;
    } u_buf;
} lcb_value_request_t;

/**
 * Common options for popular commands. This contains the CAS and expiration
 * of the item. These should be filled in if applicable, or they may be ignored.
 */
typedef struct lcb_cmd_options_st {
    lcb_cas_t cas;
    lcb_time_t exptime;
} lcb_cmd_options_t;

/**
 * Common ABI header for commands. All commands will be binary compatible with
 * this header.
 */
typedef struct lcb_cmd_st {
    lcb_key_request_t key;
    lcb_key_request_t hashkey;
    lcb_cmd_options_t options;
} lcb_cmd_t;

#define LCB_CMD_BASE \
    lcb_key_request_t key; \
    lcb_key_request_t hashkey; \
    lcb_cmd_options_t options

typedef struct {
    LCB_CMD_BASE;
    lcb_int64_t delta;
    lcb_uint64_t initial;
    int create;
} lcb_arithmetic3_cmd_t;

typedef struct {
    LCB_CMD_BASE;
    int lock;
} lcb_sget3_cmd_t;

typedef struct {
    LCB_CMD_BASE;
    lcb_value_request_t value;
    lcb_uint32_t flags;
    lcb_datatype_t datatype;
    lcb_storage_t operation;
} lcb_store3_cmd_t;

typedef struct {
    LCB_CMD_BASE;
    lcb_replica_t strategy;
    int index;
} lcb_rget3_cmd_t;

typedef lcb_cmd_t lcb_unlock3_cmd_t;
typedef lcb_cmd_t lcb_remove3_cmd_t;
typedef lcb_cmd_t lcb_touch3_cmd_t;
typedef lcb_cmd_t lcb_stats3_cmd_t;
typedef lcb_cmd_t lcb_flush3_cmd_t;

typedef struct {
    /* unused */
    LCB_CMD_BASE;
    const char *server;
    lcb_verbosity_level_t level;
} lcb_verbosity3_cmd_t;

/******************************************************************************
 ******************************************************************************
 ** Scheduling Operations                                                    **
 ******************************************************************************
 ******************************************************************************/

/**
 * The following operation APIs are low level entry points which create a
 * single operation. To use these operation APIs you should call the
 * mcreq_sched_enter() function which prepares the cmdqueue structure to
 * start scheduling operations.
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
 * mcreq_sched_leave() which will place all the commands in the scheduling
 * queue into the I/O queue. The do_flush parameter determines if each
 * affected pipeline's 'flush_start()' callback is called.
 *
 * If you wish to _discard_ all scheduled operations (for example, if one of
 * them errored, and your application cannot handle partial scheduling failures)
 * then you may call mcreq_sched_fail() which will release all the resources
 * of the packets placed into the temporary queue.
 */
struct mc_cmdqueue_st;
struct mc_pipeline_st;

void
mcreq_sched_enter(struct mc_cmdqueue_st *queue);

void
mcreq_sched_leave(struct mc_cmdqueue_st *queue, int do_flush);

void
mcreq_sched_fail(struct mc_cmdqueue_st *queue);

/******************************************************************************
 ******************************************************************************
 ** Operation Functions                                                      **
 ******************************************************************************
 ******************************************************************************/

/**
 * Operation APIs each schedule only a single logical command. These differ from
 * the "V2" APIs in libcouchbase which schedule multiple commands. In this
 * version of the library, the "V2" APIs wrap the "V3" APIs listed here.
 *
 * As noted above, you should use these function calls in conjunction with the
 * mcreq_sched_* routines
 */

LIBCOUCHBASE_API
lcb_error_t
lcb_arithmetic3(lcb_t instance, const void *cookie,
                const lcb_arithmetic3_cmd_t *cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_sget3(lcb_t instance, const void *cookie, const lcb_sget3_cmd_t *cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_unlock3(lcb_t instance, const void *cookie, const lcb_unlock3_cmd_t *cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_rget3(lcb_t instance, const void *cookie, const lcb_rget3_cmd_t *cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_store3(lcb_t instance, const void *cookie, const lcb_store3_cmd_t *cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_remove3(lcb_t instance, const void *cookie, const lcb_remove3_cmd_t * cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_stats3(lcb_t instance, const void *cookie, const lcb_stats3_cmd_t * cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_server_versions3(lcb_t instance, const void *cookie, const lcb_cmd_t * cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_server_verbosity3(lcb_t instance, const void *cookie,
                      const lcb_verbosity3_cmd_t *cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_flush3(lcb_t instance, const void *cookie, const lcb_flush3_cmd_t *cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_touch3(lcb_t instance, const void *cookie, lcb_touch3_cmd_t *cmd);

#ifdef __cplusplus
}
#endif

#endif /* MCREQ_PUBLIC_H */
