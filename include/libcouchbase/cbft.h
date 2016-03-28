#ifndef LCB_CBFT_H
#define LCB_CBFT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    LCB_RESP_BASE
    /** A query hit, or response metadta (if #rflags contains @ref LCB_RESP_F_FINAL) */
    const char *row;
    /** Length of #row */
    size_t nrow;
    /** Original HTTP response obejct */
    const lcb_RESPHTTP *htresp;
} lcb_RESPFTS;

typedef void (*lcb_FTSCALLBACK)(lcb_t, int, const lcb_RESPFTS *);
typedef struct lcb_FTSREQ* lcb_FTSHANDLE;

typedef struct {
    /** Modifiers for command. Currently none are defined */
    lcb_U32 cmdflags;
    /** Encoded JSON query */
    const char *query;
    /** Length of JSON query */
    size_t nquery;
    /** Callback to be invoked. This must be supplied */
    lcb_FTSCALLBACK callback;
    /**
     * Optional pointer to store the handle. The handle may then be
     * used for query cancellation
     */
    lcb_FTSHANDLE *handle;
} lcb_CMDFTS;

/**
 * @volatile
 * Issue a full-text query
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_fts_query(lcb_t, const void *, const lcb_CMDFTS*);

/**
 * @volatile
 * Cancel a full-text query in progress
 */
LIBCOUCHBASE_API
void
lcb_fts_cancel(lcb_t, lcb_FTSHANDLE);

#ifdef __cplusplus
}
#endif
#endif
