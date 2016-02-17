/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc.
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
#ifndef LCB_SUBDOC_H
#define LCB_SUBDOC_H

#ifdef __cplusplus
extern "C" {
#endif

/**@ingroup lcb-public-api
 * @defgroup lcb-subdoc Sub-Document API
 * @brief Experimental in-document API access
 * @details The sub-document API uses features from the upcoming Couchbase
 * 4.5 release which allows access to parts of the document. These parts are
 * called _sub-documents_ and can be accessed using the sub-document API
 *
 * @warning
 * The sub-document API is experimental and subject to change and is here for
 * demonstration purposes only.
 *
 * @addtogroup lcb-subdoc
 * @{
 */
typedef enum {
    /** Replace the value at the subdocument path */
    LCB_SUBDOC_REPLACE = 1,

    /** Add the value at the given path, if the given path does not exist */
    LCB_SUBDOC_DICT_ADD,

    /** Unconditionally set the value at the path */
    LCB_SUBDOC_DICT_UPSERT,

    /** Prepend the value to the array indicated by the path */
    LCB_SUBDOC_ARRAY_ADD_FIRST,

    /** Append the value to the array indicated by the path */
    LCB_SUBDOC_ARRAY_ADD_LAST,

    /**Add the value to the array indicated by the path, if the value is not
     * already in the array */
    LCB_SUBDOC_ARRAY_ADD_UNIQUE,

    /** Add the value at the given array index */
    LCB_SUBDOC_ARRAY_INSERT,

    /** These should only be used when adding a 'multi' command */
    LCB_SUBDOC_GET,
    LCB_SUBDOC_EXISTS,
    LCB_SUBDOC_COUNTER,
    LCB_SUBDOC_REMOVE,

    LCB_SUBDOC_MAX
} lcb_SUBDOCOP;

/** Create intermediate paths */
#define LCB_CMDSUBDOC_F_MKINTERMEDIATES (1<<16)

#define LCB_SUBDOC_CMD_BASE \
    LCB_CMD_BASE; \
    const void *path; /**< Sub-document path */ \
    size_t npath /**< Length of path */

#define LCB_SDCMD_SET_PATH(scmd, p, n) do { \
    (scmd)->path = p; \
    (scmd)->npath = n; \
} while (0);

typedef struct {
    LCB_SUBDOC_CMD_BASE;
} lcb_CMDSDBASE;

typedef lcb_CMDSDBASE lcb_CMDSDGET;
typedef lcb_CMDSDBASE lcb_CMDSDEXISTS;
typedef lcb_CMDSDBASE lcb_CMDSDREMOVE;

/**
 * Gets the given path within the document.
 * Upon completion, LCB_CALLBACK_SDGET callback is invoked with a response
 * of type lcb_RESPGET
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_sdget3(lcb_t instance, const void *cookie, const lcb_CMDSDGET *cmd);

/**
 * Checks if the given path exists within the document
 * Upon completion, the LCB_CALLBACK_SDEXISTS callback is invoked with a
 * response type of lcb_RESPBASE, with the status code indicating success
 * or failure.
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_sdexists3(lcb_t instance, const void *cookie, const lcb_CMDSDEXISTS *cmd);

typedef struct {
    LCB_SUBDOC_CMD_BASE;
    /** The value to use. This must be parseable as a JSON primitive */
    lcb_VALBUF value;
    /** The mode to use. See lcb_SUBDOCOP */
    unsigned mode;
} lcb_CMDSDSTORE;
/**
 * Store a given value in the given path within the document.
 * Upon completion, the LCB_CALLBACK_SDSTORE callback will be invoked
 * with a response type of lcb_RESPBASE.
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_sdstore3(lcb_t instance, const void *cookie, const lcb_CMDSDSTORE *cmd);

/**
 * Remove a given path from a document
 * Upon completion, the LCB_CALLBACK_SDREMOVE callback is invoked with a
 * response type of lcb_RESBASE
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_sdremove3(lcb_t instance, const void *cookie, const lcb_CMDSDREMOVE *cmd);

typedef struct {
    LCB_SUBDOC_CMD_BASE;
    lcb_S64 delta;
} lcb_CMDSDCOUNTER;
/**
 * Perform arithmetic on the given path, combining the value with the new value
 * and returning the counter's value
 * Upon completion, the LCB_CALLBACK_SDCOUNTER callback is invoked with a
 * response of type lcb_RESPGET, with the value being the new counter value.
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_sdcounter3(lcb_t instance, const void *cookie, const lcb_CMDSDCOUNTER *cmd);

typedef struct lcb_SDMULTICTX_st lcb_SDMULTICTX;

#define LCB_SDMULTI_MODE_LOOKUP 0
#define LCB_SDMULTI_MODE_MUTATE 1
typedef struct {
    LCB_CMD_BASE;
    int multimode;
} lcb_CMDSDMULTI;

/**
 * Create a new multi lookup or multi mutation sub-document context. Additional
 * path specifications may be added to the context using
 */
LIBCOUCHBASE_API
lcb_SDMULTICTX *
lcb_sdmultictx_new(lcb_t instance, const void *cookie,
    const lcb_CMDSDMULTI *cmd, lcb_error_t *err);

LIBCOUCHBASE_API
lcb_error_t
lcb_sdmultictx_addcmd(lcb_SDMULTICTX *ctx, unsigned op, const lcb_CMDSDBASE *cmd);

LIBCOUCHBASE_API
lcb_error_t
lcb_sdmultictx_done(lcb_SDMULTICTX *ctx);

LIBCOUCHBASE_API
void
lcb_sdmultictx_fail(lcb_SDMULTICTX *ctx);

/**
 * Response structure for multi lookups. If the top level response is successful
 * then the individual results may be retrieved using lcb_sdmlookup_next()
 */
typedef struct {
    LCB_RESP_BASE
    void *responses;
    /** Use with lcb_backbuf_ref/unref */
    void *bufh;
} lcb_RESPSDMLOOKUP;

/**
 * Structure for a single sub-document mutation or lookup result.
 * Note that #value and #nvalue are only valid if #status is ::LCB_SUCCESS
 */
typedef struct {
    /** Value for the mutation (only applicable for ::LCB_SUBDOC_COUNTER, currently) */
    const void *value;
    /** Length of the value */
    size_t nvalue;
    /** Status code */
    lcb_error_t status;

    /**
     * Request index which this result pertains to. This field only
     * makes sense for multi mutations where not all request specs are returned
     * in the result
     */
    lcb_U8 index;
} lcb_SDMULTI_ENTRY;

/**
 * Iterate over the results in a multi lookup operation
 * @param resp the response received from within the callback
 * @param[out] out structure to store the current result
 * @param iter internal iterator. First call should initialize this to 0
 */
LIBCOUCHBASE_API
int
lcb_sdmlookup_next(const lcb_RESPSDMLOOKUP *resp,
    lcb_SDMULTI_ENTRY *out, size_t *iter);

typedef struct {
    LCB_RESP_BASE
    void *responses;
} lcb_RESPSDMMUTATE;

/**
 * Iterate over the results in a multi-mutation operation
 * Note that unlike multi-lookup operations, not all commands will have a
 * response. The following rules apply:
 *
 * * If lcb_RESPSDMMUTATE::rc is ::LCB_SUCCESS then the results may contain zero
 *   or more entries, which apply to operations which return a payload.
 *
 * * If lcb_RESPSDMMUTATE::rc is not ::LCB_SUCCESS then the result will contain
 *   only a single entry with the error and the index of the failed operation.
 *
 * @param resp the response as received from the server
 * @param[out] out the result structure to populate
 * @param[in,out] iter internal iterator. First call should initialize to 0.
 * @return nonzero if the iterator is still valid (and thus `resp` has content).
 * 0 if there are no more entries (and thus `resp` does not have valid contents).
 */
LIBCOUCHBASE_API
int
lcb_sdmmutation_next(const lcb_RESPSDMMUTATE *resp,
    lcb_SDMULTI_ENTRY *out, size_t *iter);

/**@}*/
#ifdef __cplusplus
}
#endif
#endif
