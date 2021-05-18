/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2018-2020 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef LIBCOUCHBASE_couchbase_internalstructs_h__
#define LIBCOUCHBASE_couchbase_internalstructs_h__

#include <libcouchbase/utils.h>
#include "mutation_token.hh"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @private
 */
struct lcb_KEY_VALUE_ERROR_CONTEXT_ {
    lcb_STATUS rc;
    uint16_t status_code;
    uint32_t opaque;
    uint64_t cas;
    const char *key;
    size_t key_len;
    const char *bucket;
    size_t bucket_len;
    const char *collection;
    size_t collection_len;
    const char *scope;
    size_t scope_len;
    const char *ref;
    size_t ref_len;
    const char *context;
    size_t context_len;
    char endpoint[NI_MAXHOST + NI_MAXSERV + 4];
    size_t endpoint_len;
};

/**
 * @private
 */
struct lcb_HTTP_ERROR_CONTEXT_ {
    lcb_STATUS rc;
    uint32_t response_code;
    const char *path;
    size_t path_len;
    const char *body;
    size_t body_len;
    const char *endpoint;
    size_t endpoint_len;
};

struct lcb_CREATEOPTS_ {
    lcb_INSTANCE_TYPE type;
    const char *connstr;
    size_t connstr_len;
    struct lcb_io_opt_st *io;
    const char *username;
    size_t username_len;
    const char *password;
    size_t password_len;
    const lcb_LOGGER *logger;
    const lcb_AUTHENTICATOR *auth;
    /* override bucket in connection string */
    const char *bucket;
    size_t bucket_len;
};

/**
 * @name Receiving Responses
 * @details
 *
 * This section describes the APIs used in receiving responses.
 *
 * Each command will have a callback invoked (typically once, for some commands
 * this may be more than once) with a response structure. The response structure
 * will be of a type that extends lcb_RESPBASE. The response structure should
 * not be modified and any of its fields should be considered to point to memory
 * which will be released after the callback exits.
 *
 * The common response header contains the lcb_RESPBASE::cookie field which
 * is the pointer to your application context (passed as the second argument
 * to the spooling function) and allows you to associate a specific command
 * with a specific response.
 *
 * The header will also contain the key (lcb_RESPBASE::key) field which can
 * also help identify the specific command. This is useful if you maintain a
 * single _cookie_ for multiple commands, and have per-item specific data
 * you wish to associate within the _cookie_ itself.
 *
 * Success or failure of the operation is signalled through the lcb_RESPBASE::rc
 * field. Note that even in the case of failure, the lcb_RESPBASE::cookie and
 * lcb_RESPBASE::key fields will _always_ be populated.
 *
 * Most commands also return the CAS of the item (as it exists on the server)
 * and this is placed inside the lcb_RESPBASE::cas field, however it is
 * only valid in the case where lcb_RESPBASE::rc is LCB_SUCCESS.
 *
 * @{
 */

#define LCB_RESP_BASE                                                                                                  \
    /**                                                                                                                \
     Application-defined pointer passed as the `cookie` parameter when                                                 \
     scheduling the command.                                                                                           \
     */                                                                                                                \
    lcb_KEY_VALUE_ERROR_CONTEXT ctx;                                                                                   \
    void *cookie;                                                                                                      \
    /** Response specific flags. see ::lcb_RESPFLAGS */                                                                \
    lcb_U16 rflags;

#define LCB_RESP_SERVER_FIELDS                                                                                         \
    /** String containing the `host:port` of the server which sent this response */                                    \
    const char *server;


/**@brief Common ABI header for all commands. _Any_ command may be safely
 * casted to this type.*/
struct lcb_CMDBASE_ {
    LCB_CMD_BASE;
};

/**
 * Flag for lcb_CMDBASE::cmdflags which indicates that the lcb_CMDBASE::cookie
 * is a special callback object. This flag is used internally within the
 * library.
 *
 * @internal
 */
#define LCB_CMD_F_INTERNAL_CALLBACK (1u << 0u)

/**
 * If this flag is set, then multiple authentication credentials will be passed
 * to the server. By default only the bucket's credentials (i.e. bucket SASL
 * password) are passed.
 */
#define LCB_CMD_F_MULTIAUTH (1u << 1u)

#define LCB_CMD_F_CLONE (1u << 2u)

/**@}*/

/**
 * @brief
 * Base response structure for callbacks.
 * All responses structures derive from this ABI.
 */
struct lcb_RESPBASE_ {
    LCB_RESP_BASE
};

/**
 * @committed
 *
 * @brief Set the value buffer for the command. This may be used when the new
 * value is a single contiguous buffer.
 *
 * @param scmd an lcb_CMDSTORE pointer
 * @param valbuf the buffer for the value
 * @param vallen the length of the buffer
 *
 * The buffer needs to remain valid only until the command is passed to the
 * lcb_store3() function.
 */
#define LCB_CMD_SET_VALUE(scmd, valbuf, vallen)                                                                        \
    do {                                                                                                               \
        (scmd)->value.vtype = LCB_KV_COPY;                                                                             \
        (scmd)->value.u_buf.contig.bytes = valbuf;                                                                     \
        (scmd)->value.u_buf.contig.nbytes = vallen;                                                                    \
    } while (0);

/**
 * @committed
 *
 * @brief Set value from a series of input buffers. This may be used when the
 * input buffer is not contiguous. Using this call eliminates the need for
 * creating a temporary contiguous buffer in which to store the value.
 *
 * @param scmd the command which needs a value
 * @param iovs an array of @ref lcb_IOV structures
 * @param niovs number of items in the array.
 *
 * The buffers (and the IOV array itself)
 * need to remain valid only until the scheduler function is called. Once the
 * scheduling function is called, the buffer contents are copied into the
 * library's internal buffers.
 */
#define LCB_CMD_SET_VALUEIOV(scmd, iovs, niovs)                                                                        \
    do {                                                                                                               \
        (scmd)->value.vtype = LCB_KV_IOVCOPY;                                                                          \
        (scmd)->value.u_buf.multi.iov = iovs;                                                                          \
        (scmd)->value.u_buf.multi.niov = niovs;                                                                        \
    } while (0);


/**
 * @ingroup lcb-kv-api
 * @defgroup lcb-mctx MULTICMD API
 * @addtogroup lcb-mctx
 * @{
 */
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
 * LCB_CMD_SET_KEY(&cmd, "key1", strlen("key1"));
 * ctx->addcmd(ctx, &cmd);
 * LCB_CMD_SET_KEY(&cmd.key, "key2", strlen("key2"));
 * ctx->addcmd(ctx, &cmd);
 * LCB_CMD_SET_KEY(&cmd.key, "key3", strlen("key3"));
 * ctx->addcmd(ctx, &cmd);
 *
 * ctx->done(ctx);
 * lcb_wait(instance, LCB_WAIT_DEFAULT);
 * @endcode
 */
typedef struct lcb_MULTICMD_CTX_st {
    /**
     * Add a command to the current context
     * @param ctx the context
     * @param cmd the command to add. Note that `cmd` may be a subclass of lcb_CMDBASE
     * @return LCB_SUCCESS, or failure if a command could not be added.
     */
    lcb_STATUS (*addcmd)(struct lcb_MULTICMD_CTX_st *ctx, const lcb_CMDBASE *cmd);

    /**
     * Indicate that no more commands are added to this context, and that the
     * context should assemble the packets and place them in the current
     * scheduling context
     * @param ctx The multi context
     * @param cookie The cookie for all commands
     * @return LCB_SUCCESS if scheduled successfully, or an error code if there
     * was a problem constructing the packet(s).
     */
    lcb_STATUS (*done)(struct lcb_MULTICMD_CTX_st *ctx, const void *cookie);

    /**
     * Indicate that no more commands should be added to this context, and that
     * the context should not add its contents to the packet queues, but rather
     * release its resources. Called if you don't want to actually perform
     * the operations.
     * @param ctx
     */
    void (*fail)(struct lcb_MULTICMD_CTX_st *ctx);

    /**
     * Associate parent tracing span with the group operation
     *
     * @param ctx The multi context
     * @param span Parent span
     */
    void (*setspan)(struct lcb_MULTICMD_CTX_st *ctx, lcbtrace_SPAN *span);
} lcb_MULTICMD_CTX;
/**@}*/

/**
 * @ingroup lcb-kv-api
 * @defgroup lcb-durability Durability
 * @brief Ensure persistence and mutation of documents
 * @addtogroup lcb-durability
 * @{
 */

/**
 * @name Wait for a mutation to be persisted/replicated
 * @{
 */

/**
 * Type of durability polling to use.
 */
typedef enum {
    /**
     * Use the preferred durability. If ::LCB_CNTL_FETCH_MUTATION_TOKENS is
     * enabled and the server version is 4.0 or greater then ::LCB_DURABILITY_MODE_SEQNO
     * is used. Otherwise ::LCB_DURABILITY_MODE_CAS is used.
     */
    LCB_DURABILITY_MODE_DEFAULT = 0,

    /**
     * Explicitly request CAS-based durability. This is done by checking the
     * CAS of the item on each server with the item specified in the input.
     * The durability operation is considered complete when all items' CAS
     * values match. If the CAS value on the master node changes then the
     * durability operation will fail with ::LCB_ERR_DOCUMENT_EXISTS.
     *
     * @note
     * CAS may change either because of a failover or because of another
     * subsequent mutation. These scenarios are possible (though unlikely).
     * The ::LCB_DURABILITY_MODE_SEQNO mode is not subject to these constraints.
     */
    LCB_DURABILITY_MODE_CAS,

    /**
     * Use sequence-number based polling. This is done by checking the current
     * "mutation sequence number" for the given mutation. To use this mode
     * either an explicit @ref lcb_MUTATION_TOKEN needs to be passed, or
     * the ::LCB_CNTL_DURABILITY_MUTATION_TOKENS should be set, allowing
     * the caching of the latest mutation token for each vBucket.
     */
    LCB_DURABILITY_MODE_SEQNO
} lcb_DURMODE;

/** @brief Options for lcb_endure3_ctxnew() */
typedef struct {
    /**
     * Upper limit in microseconds from the scheduling of the command. When
     * this timeout occurs, all remaining non-verified keys will have their
     * callbacks invoked with @ref LCB_ERR_TIMEOUT.
     *
     * If this field is not set, the value of @ref LCB_CNTL_DURABILITY_TIMEOUT
     * will be used.
     */
    lcb_U32 timeout;

    /**
     * The durability check may involve more than a single call to observe - or
     * more than a single packet sent to a server to check the key status. This
     * value determines the time to wait (in microseconds)
     * between multiple probes for the same server.
     * If not set, the @ref LCB_CNTL_DURABILITY_INTERVAL will be used
     * instead.
     */
    lcb_U32 interval;

    /**
     * how many nodes the key should be persisted to (including master).
     * If set to 0 then persistence will not be checked. If set to a large
     * number (i.e. UINT16_MAX) and #cap_max is also set, will be set to the
     * maximum number of nodes to which persistence is possible (which will
     * always contain at least the master node).
     *
     * The maximum valid value for this field is
     * 1 + the total number of configured replicas for the bucket which are part
     * of the cluster. If this number is higher then it will either be
     * automatically capped to the maximum available if (#cap_max is set) or
     * will result in an ::LCB_ERR_DURABILITY_TOO_MANY error.
     */
    lcb_U16 persist_to;

    /**
     * how many nodes the key should be persisted to (excluding master).
     * If set to 0 then replication will not be checked. If set to a large
     * number (i.e. UINT16_MAX) and #cap_max is also set, will be set to the
     * maximum number of nodes to which replication is possible (which may
     * be 0 if the bucket is not configured for replicas).
     *
     * The maximum valid value for this field is the total number of configured
     * replicas which are part of the cluster. If this number is higher then
     * it will either be automatically capped to the maximum available
     * if (#cap_max is set) or will result in an ::LCB_ERR_DURABILITY_TOO_MANY
     * error.
     * */
    lcb_U16 replicate_to;

    /**
     * this flag inverts the sense of the durability check and ensures that
     * the key does *not* exist. This should be used if checking durability
     * after an lcb_remove3() operation.
     */
    lcb_U8 check_delete;

    /**
     * If replication/persistence requirements are excessive, cap to
     * the maximum available
     */
    lcb_U8 cap_max;

    /**
     * Set the polling method to use.
     * The value for this field should be one of the @ref lcb_DURMODE constants.
     */
    lcb_U8 pollopts;
} lcb_DURABILITYOPTSv0;

/**@brief Options for lcb_endure3_ctxnew() (wrapper)
 * @see lcb_DURABILITYOPTSv0 */
typedef struct lcb_durability_opts_st {
    int version;
    union {
        lcb_DURABILITYOPTSv0 v0;
    } v;
} lcb_durability_opts_t;

/**Must specify this flag if using the 'mutation_token' field, as it was added in
 * a later version */
#define LCB_CMDENDURE_F_MUTATION_TOKEN (1u << 16u)

/**@brief Command structure for endure.
 * If the lcb_CMDENDURE::cas field is specified, the operation will check and
 * verify that the CAS found on each of the nodes matches the CAS specified
 * and only then consider the item to be replicated and/or persisted to the
 * nodes. If the item exists on the master's cache with a different CAS then
 * the operation will fail
 */
typedef struct {
    LCB_CMD_BASE;
    const lcb_MUTATION_TOKEN *mutation_token;
} lcb_CMDENDURE;

/**@brief Response structure for endure */
typedef struct {
    LCB_RESP_BASE
    /**
     * Total number of polls (i.e. how many packets per server) did this
     * operation require
     */
    lcb_U16 nresponses;

    /**
     * Whether this item exists in the master in its current form. This can be
     * true even if #rc is not successful
     */
    lcb_U8 exists_master;

    /**
     * True if item was persisted on the master node. This may be true even if
     * #rc is not successful.
     */
    lcb_U8 persisted_master;

    /**
     * Total number of nodes (including master) on which this mutation has
     * been persisted. Valid even if #rc is not successful.
     */
    lcb_U8 npersisted;

    /**
     * Total number of replica nodes to which this mutation has been replicated.
     * Valid even if #rc is not successful.
     */
    lcb_U8 nreplicated;
} lcb_RESPENDURE;

/**
 * @committed
 *
 * @details
 * Ensure a key is replicated to a set of nodes
 *
 * The lcb_endure3_ctxnew() API is used to wait asynchronously until the item
 * have been persisted and/or replicated to at least the number of nodes
 * specified in the durability options.
 *
 * The command is implemented by sending a series of `OBSERVE` broadcasts
 * (see lcb_observe3_ctxnew()) to all the nodes in the cluster which are either
 * master or replica for a specific key. It polls repeatedly
 * (see lcb_DURABILITYOPTSv0::interval) until all the items have been persisted and/or
 * replicated to the number of nodes specified in the criteria, or the timeout
 * (aee lcb_DURABILITYOPTsv0::timeout) has been reached.
 *
 * The lcb_DURABILITYOPTSv0::persist_to and lcb_DURABILITYOPTS::replicate_to
 * control the number of nodes the item must be persisted/replicated to
 * in order for the durability polling to succeed.
 *
 * @brief Return a new command context for scheduling endure operations
 * @param instance the instance
 * @param options a structure containing the various criteria needed for
 * durability requirements
 * @param[out] err Error code if a new context could not be created
 * @return the new context, or NULL on error. Note that in addition to memory
 * allocation failure, this function might also return NULL because the `options`
 * structure contained bad values. Always check the `err` result.
 *
 * @par Scheduling Errors
 * The following errors may be encountered when scheduling:
 *
 * @cb_err ::LCB_ERR_DURABILITY_TOO_MANY if either lcb_DURABILITYOPTS::persist_to or
 * lcb_DURABILITYOPTS::replicate_to is too big. `err` may indicate this.
 * @cb_err ::LCB_ERR_DURABILITY_NO_MUTATION_TOKENS if no relevant mutation token
 * could be found for a given command (this is returned from the relevant
 * lcb_MULTICMD_CTX::addcmd call).
 * @cb_err ::LCB_DUPLICATE_COMMANDS if using CAS-based durability and the
 * same key was submitted twice to lcb_MULTICMD_CTX::addcmd(). This error is
 * returned from lcb_MULTICMD_CTX::done()
 *
 * @par Callback Errors
 * The following errors may be returned in the callback:
 * @cb_err ::LCB_ERR_TIMEOUT if the criteria could not be verified within the
 * accepted timeframe (see lcb_DURABILITYOPTSv0::timeout)
 * @cb_err ::LCB_ERR_DOCUMENT_EXISTS if using CAS-based durability and the item's
 * CAS has been changed on the master node
 * @cb_err ::LCB_ERR_MUTATION_LOST if using sequence-based durability and the
 * server has detected that data loss has occurred due to a failover.
 *
 * @par Creating request context
 * @code{.c}
 * lcb_durability_opts_t dopts;
 * lcb_STATUS rc;
 * memset(&dopts, 0, sizeof dopts);
 * dopts.v.v0.persist_to = -1;
 * dopts.v.v0.replicate_to = -1;
 * dopts.v.v0.cap_max = 1;
 * mctx = lcb_endure3_ctxnew(instance, &dopts, &rc);
 * // Check mctx != NULL and rc == LCB_SUCCESS
 * @endcode
 *
 * @par Adding keys - CAS
 * This can be used to add keys using CAS-based durability. This shows an
 * example within a store callback.
 * @code{.c}
 * lcb_RESPSTORE *resp = get_store_response();
 * lcb_CMDENDURE cmd = { 0 };
 * LCB_CMD_SET_KEY(&cmd, resp->key, resp->nkey);
 * cmd.cas = resp->cas;
 * rc = mctx->addcmd(mctx, (const lcb_CMDBASE*)&cmd);
 * rc = mctx->done(mctx, cookie);
 * @endcode
 *
 * @par Adding keys - explicit sequence number
 * Shows how to use an explicit sequence number as a basis for polling
 * @code{.c}
 * // during instance creation:
 * lcb_cntl_string(instance, "enable_mutation_tokens", "true");
 * lcb_connect(instance);
 * // ...
 * lcb_RESPSTORE *resp = get_store_response();
 * lcb_CMDENDURE cmd = { 0 };
 * LCB_CMD_SET_KEY(&cmd, resp->key, resp->nkey);
 * cmd.mutation_token = &resp->mutation_token;
 * cmd.cmdflags |= LCB_CMDENDURE_F_MUTATION_TOKEN;
 * rc = mctx->addcmd(mctx, (const lcb_CMDBASE*)&cmd);
 * rc = mctx->done(mctx, cookie);
 * @endcode
 *
 * @par Adding keys - implicit sequence number
 * Shows how to use an implicit mutation token (internally tracked by the
 * library) for durability:
 * @code{.c}
 * // during instance creation
 * lcb_cntl_string(instance, "enable_mutation_tokens", "true");
 * lcb_cntl_string(instance, "dur_mutation_tokens", "true");
 * lcb_connect(instance);
 * // ...
 * lcb_CMDENDURE cmd = { 0 };
 * LCB_CMD_SET_KEY(&cmd, "key", strlen("key"));
 * mctx->addcmd(mctx, (const lcb_CMDBASE*)&cmd);
 * mctx->done(mctx, cookie);
 * @endcode
 *
 * @par Response
 * @code{.c}
 * lcb_install_callback3(instance, LCB_CALLBACK_ENDURE, dur_callback);
 * void dur_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPBASE *rb)
 * {
 *     const lcb_RESPENDURE *resp = (const lcb_RESPENDURE*)rb;
 *     printf("Durability polling result for %.*s.. ", (int)resp->nkey, resp->key);
 *     if (resp->ctx.rc != LCB_SUCCESS) {
 *         printf("Failed: %s\n", lcb_strerror_short(resp->ctx.rc);
 *         return;
 *     }
 * }
 * @endcode
 */
LIBCOUCHBASE_API
lcb_MULTICMD_CTX *lcb_endure3_ctxnew(lcb_INSTANCE *instance, const lcb_durability_opts_t *options, lcb_STATUS *err);

#define LCB_DURABILITY_VALIDATE_CAPMAX (1 << 1)

/**
 * @committed
 *
 * Validate durability settings.
 *
 * This function will validate (and optionally modify) the settings. This is
 * helpful to ensure the durability options are valid _before_ issuing a command
 *
 * @param instance the instance
 *
 * @param[in,out] persist_to The desired number of servers to persist to.
 *  If the `CAPMAX` flag is set, on output this will contain the effective
 *  number of servers the item can be persisted to
 *
 * @param[in,out] replicate_to The desired number of servers to replicate to.
 *  If the `CAPMAX` flag is set, on output this will contain the effective
 *  number of servers the item can be replicated to
 *
 * @param options Options to use for validating. The only recognized option
 *  is currently `LCB_DURABILITY_VALIDATE_CAPMAX` which has the same semantics
 *  as lcb_DURABILITYOPTSv0::cap_max.
 *
 * @return LCB_SUCCESS on success
 * @return LCB_ERR_DURABILITY_TOO_MANY if the requirements exceed the number of
 *  servers currently available, and `CAPMAX` was not specifie
 * @return LCB_ERR_INVALID_ARGUMENT if both `persist_to` and `replicate_to` are 0.
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_durability_validate(lcb_INSTANCE *instance, lcb_U16 *persist_to, lcb_U16 *replicate_to, int options);

/**@} (NAME) */

/**
 * @name Retrieve current persistence/replication status
 * @{
 */

/**Set this bit in the cmdflags field to indicate that only the master node
 * should be contacted*/
#define LCB_CMDOBSERVE_F_MASTER_ONLY (1 << 16)

/**@brief Structure for an observe request.
 * To request the status from _only_ the master node of the key, set the
 * LCB_CMDOBSERVE_F_MASTERONLY bit inside the lcb_CMDOBSERVE::cmdflags field
 */
typedef struct {
    LCB_CMD_BASE;
    /**For internal use: This determines the servers the command should be
     * routed to. Each entry is an index within the server. */
    const lcb_U16 *servers_;
    size_t nservers_;
} lcb_CMDOBSERVE;

/**
 * @brief Possible statuses for keys in OBSERVE response
 */
typedef enum {
    /** The item found in the memory, but not yet on the disk */
    LCB_OBSERVE_FOUND = 0x00,
    /** The item hit the disk */
    LCB_OBSERVE_PERSISTED = 0x01,
    /** The item missing on the disk and the memory */
    LCB_OBSERVE_NOT_FOUND = 0x80,
    /** No knowledge of the key :) */
    LCB_OBSERVE_LOGICALLY_DELETED = 0x81,

    LCB_OBSERVE_MAX = 0x82
} lcb_observe_t;

/**@brief Response structure for an observe command.
 * Note that the lcb_RESPOBSERVE::cas contains the CAS of the item as it is
 * stored within that specific server. The CAS may be incorrect or stale
 * unless lcb_RESPOBSERVE::ismaster is true.
 */
typedef struct {
    LCB_RESP_BASE
    lcb_U8 status;   /**<Bit set of flags */
    lcb_U8 ismaster; /**< Set to true if this response came from the master node */
    lcb_U32 ttp;     /**<Unused. For internal requests, contains the server index */
    lcb_U32 ttr;     /**<Unused */
} lcb_RESPOBSERVE;

/**
 * @brief Create a new multi context for an observe operation
 * @param instance the instance
 * @return a new multi command context, or NULL on allocation failure.
 * @committed
 *
 * Note that the callback for this command will be invoked multiple times,
 * one for each node. To determine when no more callbacks will be invoked,
 * check for the LCB_RESP_F_FINAL flag inside the lcb_RESPOBSERVE::rflags
 * field.
 *
 * @code{.c}
 * void callback(lcb_INSTANCE, lcb_CALLBACK_TYPE, const lcb_RESPOBSERVE *resp)
 * {
 *   if (resp->rflags & LCB_RESP_F_FINAL) {
 *     return;
 *   }
 *
 *   printf("Got status for key %.*s\n", (int)resp->nkey, resp->key);
 *   printf("  Node Type: %s\n", resp->ismaster ? "MASTER" : "REPLICA");
 *   printf("  Status: 0x%x\n", resp->status);
 *   printf("  Current CAS: 0x%"PRIx64"\n", resp->cas);
 * }
 *
 * lcb_MULTICMD_CTX *mctx = lcb_observe3_ctxnew(instance);
 * lcb_CMDOBSERVE cmd = { 0 };
 * LCB_CMD_SET_KEY(&cmd, "key", 3);
 * mctx->addcmd(mctx, (lcb_CMDBASE *)&cmd);
 * mctx->done(mctx, cookie);
 * lcb_install_callback3(instance, LCB_CALLBACK_OBSERVE, (lcb_RESP_cb)callback);
 * @endcode
 *
 * @warning
 * Operations created by observe cannot be undone using lcb_sched_fail().
 */
LIBCOUCHBASE_API
lcb_MULTICMD_CTX *lcb_observe3_ctxnew(lcb_INSTANCE *instance);

/**
 * @brief Command structure for lcb_observe_seqno3().
 * Note #key, #nkey, and #cas are not used in this command.
 */
typedef struct {
    LCB_CMD_BASE;
    /**
     * Server index to target. The server index must be valid and must also
     * be either a master or a replica for the vBucket indicated in #vbid
     */
    lcb_U16 server_index;
    lcb_U16 vbid; /**< vBucket ID to query */
    lcb_U64 uuid; /**< UUID known to client which should be queried */
} lcb_CMDOBSEQNO;

/**
 * @brief Response structure for lcb_observe_seqno3()
 *
 * Note that #key, #nkey and #cas are empty because the operand is the relevant
 * mutation token fields in @ref lcb_CMDOBSEQNO
 */
typedef struct {
    LCB_RESP_BASE
    lcb_U16 vbid;            /**< vBucket ID (for potential mapping) */
    lcb_U16 server_index;    /**< Input server index */
    lcb_U64 cur_uuid;        /**< UUID for this vBucket as known to the server */
    lcb_U64 persisted_seqno; /**< Highest persisted sequence */
    lcb_U64 mem_seqno;       /**< Highest known sequence */

    /**
     * In the case where the command's uuid is not the most current, this
     * contains the last known UUID
     */
    lcb_U64 old_uuid;

    /**
     * If #old_uuid is nonzero, contains the highest sequence number persisted
     * in the #old_uuid snapshot.
     */
    lcb_U64 old_seqno;
} lcb_RESPOBSEQNO;

/**
 * @volatile
 * @brief Get the persistence/replication status for a given mutation token
 * @param instance the handle
 * @param cookie callback cookie
 * @param cmd the command
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_observe_seqno3(lcb_INSTANCE *instance, const void *cookie, const lcb_CMDOBSEQNO *cmd);

/**@} (Name: OBSERVE) */

typedef enum { LCB_DURABILITY_NONE = 0, LCB_DURABILITY_POLL = 1, LCB_DURABILITY_SYNC = 2 } lcb_DURABILITY_MODE;


/**
 * Command flag for HTTP to indicate that the callback is to be invoked
 * multiple times for each new chunk of incoming data. Once the entire body
 * have been received, the callback will be invoked once more with the
 * LCB_RESP_F_FINAL flag (in lcb_RESPHTTP::rflags) and an empty content.
 *
 * To use streaming requests, this flag should be set in the
 * lcb_CMDHTTP::cmdflags field
 */
#define LCB_CMDHTTP_F_STREAM (1 << 16)

/**
 * @internal
 * If specified, the lcb_CMDHTTP::cas field becomes the timeout for this
 * specific request.
 */
#define LCB_CMDHTTP_F_CASTMO (1 << 17)

/**
 * @internal
 * Do not inject authentication header into the request.
 */
#define LCB_CMDHTTP_F_NOUPASS (1 << 18)

/**
 * Structure for performing an HTTP request.
 * Note that the key and nkey fields indicate the _path_ for the API
 */
struct lcb_CMDHTTP_ {
    LCB_CMD_BASE;
    /**Type of request to issue. LCB_HTTP_TYPE_VIEW will issue a request
     * against a random node's view API. LCB_HTTP_TYPE_MANAGEMENT will issue
     * a request against a random node's administrative API, and
     * LCB_HTTP_TYPE_RAW will issue a request against an arbitrary host. */
    lcb_HTTP_TYPE type;
    lcb_HTTP_METHOD method; /**< HTTP Method to use */

    /** If the request requires a body (e.g. `PUT` or `POST`) then it will
     * go here. Be sure to indicate the length of the body too. */
    const char *body;

    /** Length of the body for the request */
    lcb_SIZE nbody;

    /** If non-NULL, will be assigned a handle which may be used to
     * subsequently cancel the request */
    lcb_HTTP_HANDLE **reqhandle;

    /** For views, set this to `application/json` */
    const char *content_type;

    /** Username to authenticate with, if left empty, will use the credentials
     * passed to lcb_create() */
    const char *username;

    /** Password to authenticate with, if left empty, will use the credentials
     * passed to lcb_create() */
    const char *password;

    /** If set, this must be a string in the form of `http://host:port`. Should
     * only be used for raw requests. */
    const char *host;
};

/**
 * Structure for HTTP responses.
 * Note that #rc being `LCB_SUCCESS` does not always indicate that the HTTP
 * request itself was successful. It only indicates that the outgoing request
 * was submitted to the server and the client received a well-formed HTTP
 * response. Check the #hstatus field to see the actual HTTP-level status
 * code received.
 */
struct lcb_RESPHTTP_ {
    lcb_HTTP_ERROR_CONTEXT ctx;
    void *cookie;
    lcb_U16 rflags;

    /**List of key-value headers. This field itself may be `NULL`. The list
     * is terminated by a `NULL` pointer to indicate no more headers. */
    const char *const *headers;

    /**@internal*/
    lcb_HTTP_HANDLE *_htreq;
};

/**@ingroup lcb-public-api
 * @defgroup lcb-subdoc Sub-Document API
 * @brief Experimental in-document API access
 * @details The sub-document API uses features from the upcoming Couchbase
 * 4.5 release which allows access to parts of the document. These parts are
 * called _sub-documents_ and can be accessed using the sub-document API
 *
 * @addtogroup lcb-subdoc
 * @{
 */

/**@ingroup lcb-public-api
 * @defgroup lcb-misc-cmds Miscellaneous Commands
 * @brief Additional miscellaneous commands which can be executed on the server.
 *
 * @addtogroup lcb-misc-cmds
 * @{
 */

/**@} (Name: Stats) */

/**@} (Group: Misc) */


/**
 * @ingroup lcb-public-api
 * @defgroup lcb-mutation-tokens Mutation Tokens
 *
 * @details Mutation Tokens are returned with mutations if
 * ::LCB_CNTL_FETCH_MUTATION_TOKENS is enabled (off by default). Mutation tokens
 * are largely of internal use, but can be used by N1QL queries and durability
 * requirement polling
 *
 * @addtogroup lcb-mutation-tokens
 * @{
 */

/**
 * @brief
 * Structure representing a synchronization token. This token may be used
 * for durability operations and N1QL queries. The contents of this structure
 * should be considered opaque, and accessed via the various macros
 * @struct lcb_MUTATION_TOKEN
 */

/** Get the vBucket UUID */
#define LCB_MUTATION_TOKEN_ID(p) ((p)->uuid_)
/** Get the sequence number */
#define LCB_MUTATION_TOKEN_SEQ(p) ((p)->seqno_)
/** Get the vBucket number itself */
#define LCB_MUTATION_TOKEN_VB(p) ((p)->vbid_)
/** Whether this mutation token has valid contents */
#define LCB_MUTATION_TOKEN_ISVALID(p) (p && !((p)->uuid_ == 0 && (p)->seqno_ == 0 && (p)->vbid_ == 0))

/**@} (Group: Mutation Tokens) */

/**
 * Ping data (Key/Value) service. Used in lcb_CMDPING#services
 */
#define LCB_PINGSVC_F_KV 0x01

/**
 * Ping query (N1QL) service. Used in lcb_CMDPING#services
 */
#define LCB_PINGSVC_F_N1QL 0x02

/**
 * Ping views (Map/Reduce) service. Used in lcb_CMDPING#services
 */
#define LCB_PINGSVC_F_VIEWS 0x04

/**
 * Ping full text search (FTS) service. Used in lcb_CMDPING#services
 */
#define LCB_PINGSVC_F_FTS 0x08

/**
 * Ping Analytics for N1QL service. Used in lcb_CMDPING#services
 */
#define LCB_PINGSVC_F_ANALYTICS 0x10

/**
 * Do not record any metrics or status codes from ping responses.
 * This might be useful to reduce overhead, when user-space
 * keep-alive mechanism is not interested in actual latencies,
 * but rather need keep sockets active. Used in lcb_CMDPING#options
 */
#define LCB_PINGOPT_F_NOMETRICS 0x01

/**
 * Automatically encode PING result as JSON. See njson/json fields
 * of #lcb_RESPPING structure. Used in lcb_CMDPING#options
 */
#define LCB_PINGOPT_F_JSON 0x02

/**
 * Add extra details about service status into generated JSON.
 * Requires LCB_PINGOPT_F_JSON to be set. Used in lcb_CMDPING#options
 */
#define LCB_PINGOPT_F_JSONDETAILS 0x04

/**
 * Generate indented JSON, which is better for reading. Used in lcb_CMDPING#options
 */
#define LCB_PINGOPT_F_JSONPRETTY 0x08

/**
 * Structure for PING requests.
 *
 * @committed
 */
struct lcb_CMDPING_ {
    LCB_CMD_BASE;
    uint32_t services; /**< bitmap for services to ping */
    uint32_t options;  /**< extra options, e.g. for result representation */
    const char *id;    /**< optional, zero-terminated string to identify the report */
    size_t nid;
};

/**
 * Entry describing the status of the service in the cluster.
 * It is part of lcb_RESPING structure.
 *
 * @committed
 */
typedef struct {
    lcb_PING_SERVICE type; /**< type of the service */
    /* TODO: rename to "remote" */
    const char *server;     /**< server host:port */
    lcb_U64 latency;        /**< latency in nanoseconds */
    lcb_STATUS rc;          /**< raw return code of the operation */
    const char *local;      /**< server host:port */
    const char *id;         /**< service identifier (unique in scope of lcb_INSTANCE *connection instance) */
    const char *scope;      /**< optional scope name (typically equals to the bucket name) */
    lcb_PING_STATUS status; /**< status of the operation */
} lcb_PINGSVC;

/**
 * Structure for PING responses.
 *
 * @committed
 */
struct lcb_RESPPING_ {
    LCB_RESP_BASE
    LCB_RESP_SERVER_FIELDS
    lcb_SIZE nservices;    /**< number of the nodes, replied to ping */
    lcb_PINGSVC *services; /**< the nodes, replied to ping, if any */
    lcb_SIZE njson;        /**< length of JSON string (when #LCB_PINGOPT_F_JSON was specified) */
    const char *json;      /**< pointer to JSON string */
#ifdef __cplusplus
    std::string id;
#endif
};

struct lcb_CMDDIAG_ {
    LCB_CMD_BASE;
    int options;    /**< extra options, e.g. for result representation */
    const char *id; /**< optional, zero-terminated string to identify the report */
    size_t nid;
};

struct lcb_RESPDIAG_ {
    LCB_RESP_BASE
    lcb_SIZE njson;   /**< length of JSON string (when #LCB_PINGOPT_F_JSON was specified) */
    const char *json; /**< pointer to JSON string */
};

#define LCB_CMD_CLONE(TYPE, SRC, DST)                                                                                  \
    do {                                                                                                               \
        TYPE *ret = (TYPE *)calloc(1, sizeof(TYPE));                                                                   \
        memcpy(ret, SRC, sizeof(TYPE));                                                                                \
        if (SRC->key.contig.bytes) {                                                                                   \
            ret->key.type = LCB_KV_COPY;                                                                               \
            ret->key.contig.bytes = calloc(SRC->key.contig.nbytes, sizeof(uint8_t));                                   \
            ret->key.contig.nbytes = SRC->key.contig.nbytes;                                                           \
            memcpy((void *)ret->key.contig.bytes, SRC->key.contig.bytes, ret->key.contig.nbytes);                      \
        }                                                                                                              \
        ret->cmdflags |= LCB_CMD_F_CLONE;                                                                              \
        *DST = ret;                                                                                                    \
    } while (0)

#define LCB_CMD_DESTROY_CLONE(cmd)                                                                                     \
    do {                                                                                                               \
        if (cmd->cmdflags & LCB_CMD_F_CLONE) {                                                                         \
            if (cmd->key.contig.bytes && cmd->key.type == LCB_KV_COPY) {                                               \
                free((void *)cmd->key.contig.bytes);                                                                   \
            }                                                                                                          \
        }                                                                                                              \
        free(cmd);                                                                                                     \
    } while (0)

#define LCB_CMD_CLONE_WITH_VALUE(TYPE, SRC, DST)                                                                       \
    do {                                                                                                               \
        TYPE *ret = (TYPE *)calloc(1, sizeof(TYPE));                                                                   \
        memcpy(ret, SRC, sizeof(TYPE));                                                                                \
        if (SRC->key.contig.bytes) {                                                                                   \
            ret->key.type = LCB_KV_COPY;                                                                               \
            ret->key.contig.bytes = calloc(SRC->key.contig.nbytes, sizeof(uint8_t));                                   \
            ret->key.contig.nbytes = SRC->key.contig.nbytes;                                                           \
            memcpy((void *)ret->key.contig.bytes, SRC->key.contig.bytes, ret->key.contig.nbytes);                      \
        }                                                                                                              \
        switch (SRC->value.vtype) {                                                                                    \
            case LCB_KV_COPY:                                                                                          \
            case LCB_KV_CONTIG:                                                                                        \
                ret->value.vtype = LCB_KV_COPY;                                                                        \
                ret->value.u_buf.contig.bytes = calloc(SRC->value.u_buf.contig.nbytes, sizeof(uint8_t));               \
                ret->value.u_buf.contig.nbytes = SRC->value.u_buf.contig.nbytes;                                       \
                memcpy((void *)ret->value.u_buf.contig.bytes, SRC->value.u_buf.contig.bytes,                           \
                       ret->value.u_buf.contig.nbytes);                                                                \
                break;                                                                                                 \
            case LCB_KV_IOV:                                                                                           \
            case LCB_KV_IOVCOPY:                                                                                       \
                if (SRC->value.u_buf.multi.iov) {                                                                      \
                    ret->value.vtype = LCB_KV_IOVCOPY;                                                                 \
                    const lcb_FRAGBUF *msrc = &SRC->value.u_buf.multi;                                                 \
                    lcb_FRAGBUF *mdst = &ret->value.u_buf.multi;                                                       \
                    mdst->total_length = 0;                                                                            \
                    mdst->iov = (lcb_IOV *)calloc(msrc->niov, sizeof(lcb_IOV));                                        \
                    for (size_t ii = 0; ii < msrc->niov; ii++) {                                                       \
                        if (msrc->iov[ii].iov_len) {                                                                   \
                            mdst->iov[ii].iov_base = calloc(msrc->iov[ii].iov_len, sizeof(uint8_t));                   \
                            mdst->iov[ii].iov_len = msrc->iov[ii].iov_len;                                             \
                            mdst->total_length += msrc->iov[ii].iov_len;                                               \
                            memcpy(mdst->iov[ii].iov_base, msrc->iov[ii].iov_base, mdst->iov[ii].iov_len);             \
                        }                                                                                              \
                    }                                                                                                  \
                }                                                                                                      \
                break;                                                                                                 \
            default:                                                                                                   \
                free(ret);                                                                                             \
                return LCB_ERR_INVALID_ARGUMENT;                                                                       \
                break;                                                                                                 \
        }                                                                                                              \
        ret->cmdflags |= LCB_CMD_F_CLONE;                                                                              \
        *DST = ret;                                                                                                    \
    } while (0)

#define LCB_CMD_DESTROY_CLONE_WITH_VALUE(cmd)                                                                          \
    do {                                                                                                               \
        if (cmd->cmdflags & LCB_CMD_F_CLONE) {                                                                         \
            if (cmd->key.contig.bytes && cmd->key.type == LCB_KV_COPY) {                                               \
                free((void *)cmd->key.contig.bytes);                                                                   \
            }                                                                                                          \
            switch (cmd->value.vtype) {                                                                                \
                case LCB_KV_COPY:                                                                                      \
                case LCB_KV_CONTIG:                                                                                    \
                    free((void *)cmd->value.u_buf.contig.bytes);                                                       \
                    break;                                                                                             \
                case LCB_KV_IOV:                                                                                       \
                case LCB_KV_IOVCOPY:                                                                                   \
                    if (cmd->value.u_buf.multi.iov) {                                                                  \
                        lcb_FRAGBUF *buf = &cmd->value.u_buf.multi;                                                    \
                        for (size_t ii = 0; ii < buf->niov; ii++) {                                                    \
                            if (buf->iov[ii].iov_len) {                                                                \
                                free(buf->iov[ii].iov_base);                                                           \
                            }                                                                                          \
                        }                                                                                              \
                        free(cmd->value.u_buf.multi.iov);                                                              \
                    }                                                                                                  \
                    break;                                                                                             \
                default:                                                                                               \
                    break;                                                                                             \
            }                                                                                                          \
        }                                                                                                              \
        free(cmd);                                                                                                     \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
