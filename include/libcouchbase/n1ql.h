/*
 *     Copyright 2015 Couchbase, Inc.
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
 **/

#ifndef LCB_N1QL_API_H
#define LCB_N1QL_API_H
#include <libcouchbase/couchbase.h>
#include <libcouchbase/api3.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lcb_RESPN1QL_st lcb_RESPN1QL;

/**
 * Callback to be invoked for each row
 * @param The instance
 * @param Callback type. Currently unused.
 * @param The response.
 */
typedef void (*lcb_N1QLCALLBACK)(lcb_t, int, const lcb_RESPN1QL*);

typedef struct lcb_N1QLPARAMS_st lcb_N1QLPARAMS;
typedef struct lcb_CMDN1QL_st lcb_CMDN1QL;

/**
 * Create a new N1QL Parameters object. The returned object is an opaque
 * pointer which may be used to set various properties on a N1QL query. This
 * may then be used to populate relevant fields of an ::lcb_N1QLCMD
 * structure.
 */
LIBCOUCHBASE_API
lcb_N1QLPARAMS *
lcb_n1p_new(void);

/**
 * Reset the parameters structure so that it may be reused for a subsequent
 * query. Internally this resets the buffer positions to 0, but does not free
 * them, making this function optimal for issusing subsequent queries.
 * @param params the object to reset
 */
LIBCOUCHBASE_API
void
lcb_n1p_reset(lcb_N1QLPARAMS *params);

/**
 * Free the parameters structure. This should be done when it is no longer
 * needed
 * @param params the object to reset
 */
LIBCOUCHBASE_API
void
lcb_n1p_free(lcb_N1QLPARAMS *params);

/** Query is a statement string */
#define LCB_N1P_QUERY_STATEMENT 1

/** Query is a prepared statement returned via the `PREPARE` statement */
#define LCB_N1P_QUERY_PREPARED 2

/**
 * Sets the actual statement to be executed
 * @param params the params object
 * @param qstr the query string (either N1QL statement or prepared JSON)
 * @apram nqstr the length of the string. Set to -1 if NUL-terminated
 * @param type the type of statement. Can be either ::LCB_N1P_QUERY_STATEMENT
 * or ::LCB_N1P_QUERY_PREPARED
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1p_setquery(lcb_N1QLPARAMS *params, const char *qstr, size_t nqstr, int type);

#define lcb_n1p_setstmtz(params, qstr) \
    lcb_n1p_setquery(params, qstr, -1, LCB_N1P_QUERY_STATEMENT)

/**
 * Sets a named argument for the query.
 * @param params the object
 * @param name The argument name (e.g. `$age`)
 * @param n_name
 * @param value The argument value (e.g. `42`)
 * @param n_value
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1p_namedparam(lcb_N1QLPARAMS *params, const char *name, size_t n_name,
    const char *value, size_t nvalue);

#define lcb_n1p_namedparamz(params, name, value) \
    lcb_n1p_namedparam(params, name, -1, value, -1)

/**
 * Adds a _positional_ argument for the query
 * @param params the params object
 * @param value the argument
 * @param nvalue the length of the argument.
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1p_posparam(lcb_N1QLPARAMS *params, const char *value, size_t nvalue);

/**
 * Set a query option
 * @param params the params object
 * @param name the name of the option
 * @param n_name
 * @param value the value of the option
 * @param n_value
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1p_setopt(lcb_N1QLPARAMS *params, const char *name, size_t n_name,
    const char *value, size_t nvalue);

/**
 * Convenience function to set a string parameter with a string value
 * @param params the parameter object
 * @param key the NUL-terminated option name
 * @param value the NUL-terminated option value
 */
#define lcb_n1p_setoptz(params, key, value) \
    lcb_n1p_setopt(params, key, -1, value, -1)


/** No consistency constraints */
#define LCB_N1P_CONSISTENCY_NONE 0

/**
 * This is implicitly set by the lcb_n1p_synctok() family of functions. This
 * will ensure that mutations up to the vector indicated by the synctoken
 * passed to lcb_n1p_synctok() are used.
 */
#define LCB_N1P_CONSISTENCY_RYOW 1

/** Refresh the snapshot for each request */
#define LCB_N1P_CONSISTENCY_REQUEST 2

/** Refresh the snapshot for each statement */
#define LCB_N1P_CONSISTENCY_STATMENT 3

/**
 * Sets the consistency mode for the request.
 * By default results are read from a potentially stale snapshot of the data.
 * This may be good for most cases; however at times you want the absolutely
 * most recent data.
 * @param params the parameters object
 * @param mode one of the `LCB_N1P_CONSISTENT_*` constants.
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1p_setconsistency(lcb_N1QLPARAMS *params, int mode);


typedef struct {
    lcb_U64 uuid_;
    lcb_U64 seqno_;
    lcb_U16 vbid_;
} lcb_N1QLSCANVEC;

/**
 * Indicate that the query should synchronize its internal snapshot to reflect
 * the changes indicated by the given synctoken (`ss`). The synctoken may be
 * obtained via lcb_get_synctoken().See lcb_n1p_synctok_for() for a
 * convenience version of this function.
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1p_scanvec(lcb_N1QLPARAMS *params, const lcb_N1QLSCANVEC *sv);


/**
 * Wrapper around lcb_get_synctoken() and lcb_n1p_synctok(). This will
 * retrieve the latest mutation/vector for the given key on the cluster.
 * @param params the parameters object
 * @param instance the instance on which this mutation was performed
 * @param key the key
 * @param nkey the length of the key
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1p_synctok_for(lcb_N1QLPARAMS *params, lcb_t instance,
    const void *key, size_t nkey);

/**
 * Populates the given low-level lcb_CMDN1QL structure with the relevant fields
 * from the params structure. If this function returns successfuly, you must
 * ensure that the params object is not modified until the command is
 * submitted. Afterwards, you can use lcb_n1p_free() or lcb_n1p_reset() to
 * free/reuse the structure for subsequent requests
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1p_mkcmd(lcb_N1QLPARAMS *params, lcb_CMDN1QL *cmd);

/**Low-level N1QL Command structure */
struct lcb_CMDN1QL_st {
    lcb_U32 cmdflags;
    /**Query to be placed in the POST request. The library will not perform
     * any conversions or validation on this string, so it is up to the user
     * (or wrapping library) to ensure that the string is well formed.
     *
     * In general the string should either be JSON (in which case, the
     * #content_type field should be `application/json`) or url-encoded
     * (in which case the #content_type field should be
     * `application/x-www-form-urlencoded`)
     */
    const char *query;
    /**cbq-engine host:port. If left NULL, the address will be discovered via
     * the configuration */
    const char *host;

    /**Content type for query. Must be specified. */
    const char *content_type;

    size_t nquery;
    /** Callback to be invoked for each row */
    lcb_N1QLCALLBACK callback;
};

/**
 * Response for a N1QL query. This is delivered in the @ref lcb_N1QLCALLBACK
 * callback function for each result row received. The callback is also called
 * one last time when all
 */
struct lcb_RESPN1QL_st {
    LCB_RESP_BASE
    /**Current result row. If #rflags has the ::LCB_RESP_F_FINAL bit set, then
     * this field does not contain the actual row, but the remainder of the
     * data not included with the resultset; e.g. the JSON surrounding
     * the "results" field with any errors or metadata for the response.
     */
    const char *row;
    /** Length of the row */
    size_t nrow;
    /** Raw HTTP response, if applicable */
    const lcb_RESPHTTP *htresp;
};

/**
 * @volatile
 *
 * Execute a N1QL query.
 *
 * This function will send the query to a query server in the cluster (or if
 * lcb_CMDN1QL::host is set, to the given host), and will invoke the callback
 * (lcb_CMDN1QL::callback) for each result returned.
 *
 * @param instance The instance
 * @param cookie Pointer to application data
 * @param cmd the command
 * @return Scheduling success or failure.
 */
LIBCOUCHBASE_API
lcb_error_t
lcb_n1ql_query(lcb_t instance, const void *cookie, const lcb_CMDN1QL *cmd);

#ifdef __cplusplus
}
#endif
#endif
