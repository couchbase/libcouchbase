/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016-2021 Couchbase, Inc.
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

#ifndef LIBCOUCHBASE_CAPI_SUBDOC_HH
#define LIBCOUCHBASE_CAPI_SUBDOC_HH

#include <cstddef>
#include <cstdint>

#include "key_value_error_context.hh"

/**
 * @brief Sub-Document command codes
 *
 * These command codes should be applied as values to lcb_SDSPEC::sdcmd and
 * indicate which type of subdoc command the server should perform.
 */
enum lcb_SUBDOCOP {
    /**
     * Retrieve the value for a path
     */
    LCB_SDCMD_GET = 1,

    /**
     * Check if the value for a path exists. If the path exists then the error
     * code will be @ref LCB_SUCCESS
     */
    LCB_SDCMD_EXISTS,

    /**
     * Replace the value at the specified path. This operation can work
     * on any existing and valid path.
     */
    LCB_SDCMD_REPLACE,

    /**
     * Add the value at the given path, if the given path does not exist.
     * The penultimate path component must point to an array. The operation
     * may be used in conjunction with @ref LCB_SDSPEC_F_MKINTERMEDIATES to
     * create the parent dictionary (and its parents as well) if it does not
     * yet exist.
     */
    LCB_SDCMD_DICT_ADD,

    /**
     * Unconditionally set the value at the path. This logically
     * attempts to perform a @ref LCB_SDCMD_REPLACE, and if it fails, performs
     * an @ref LCB_SDCMD_DICT_ADD.
     */
    LCB_SDCMD_DICT_UPSERT,

    /**
     * Prepend the value(s) to the array indicated by the path. The path should
     * reference an array. When the @ref LCB_SDSPEC_F_MKINTERMEDIATES flag
     * is specified then the array may be created if it does not exist.
     *
     * Note that it is possible to add more than a single value to an array
     * in an operation (this is valid for this commnand as well as
     * @ref LCB_SDCMD_ARRAY_ADD_LAST and @ref LCB_SDCMD_ARRAY_INSERT). Multiple
     * items can be specified by placing a comma between then (the values should
     * otherwise be valid JSON).
     */
    LCB_SDCMD_ARRAY_ADD_FIRST,

    /**
     * Identical to @ref LCB_SDCMD_ARRAY_ADD_FIRST but places the item(s)
     * at the end of the array rather than at the beginning.
     */
    LCB_SDCMD_ARRAY_ADD_LAST,

    /**
     * Add the value to the array indicated by the path, if the value is not
     * already in the array. The @ref LCB_SDSPEC_F_MKINTERMEDIATES flag can
     * be specified to create the array if it does not already exist.
     *
     * Currently the value for this operation must be a JSON primitive (i.e.
     * no arrays or dictionaries) and the existing array itself must also
     * contain only primitives (otherwise a @ref LCB_ERR_SUBDOC_PATH_MISMATCH
     * error will be received).
     */
    LCB_SDCMD_ARRAY_ADD_UNIQUE,

    /**
     * Add the value at the given array index. Unlike other array operations,
     * the path specified should include the actual index at which the item(s)
     * should be placed, for example `array[2]` will cause the value(s) to be
     * the 3rd item(s) in the array.
     *
     * The array must already exist and the @ref LCB_SDSPEC_F_MKINTERMEDIATES
     * flag is not honored.
     */
    LCB_SDCMD_ARRAY_INSERT,

    /**
     * Increment or decrement an existing numeric path. If the number does
     * not exist, it will be created (though its parents will not, unless
     * @ref LCB_SDSPEC_F_MKINTERMEDIATES is specified).
     *
     * The value for this operation should be a valid JSON-encoded integer and
     * must be between `INT64_MIN` and `INT64_MAX`, inclusive.
     */
    LCB_SDCMD_COUNTER,

    /**
     * Remove an existing path in the document.
     */
    LCB_SDCMD_REMOVE,

    /**
     * Count the number of elements in an array or dictionary
     */
    LCB_SDCMD_GET_COUNT,

    /**
     * Retrieve the entire document
     */
    LCB_SDCMD_GET_FULLDOC,

    /**
     * Replace the entire document
     */
    LCB_SDCMD_SET_FULLDOC,

    /**
     * Remove the entire document
     */
    LCB_SDCMD_REMOVE_FULLDOC,

    LCB_SDCMD_MAX
};

/**
 * @brief Subdoc command specification.
 * This structure describes an operation and its path, and possibly its value.
 * This structure is provided in an array to the lcb_CMDSUBDOC::specs field.
 */
struct lcb_SDSPEC {
    /**
     * The command code, @ref lcb_SUBDOCOP. There is no default for this
     * value, and it therefore must be set.
     */
    std::uint32_t sdcmd;

    /**
     * Set of option flags for the command. Currently the only option known
     * is @ref LCB_SDSPEC_F_MKINTERMEDIATES
     */
    std::uint32_t options;

    /**
     * Path for the operation. This should be assigned using
     * @ref LCB_SDSPEC_SET_PATH. The contents of the path should be valid
     * until the operation is scheduled (lcb_subdoc3())
     */
    lcb_KEYBUF path;

    /**
     * Value for the operation. This should be assigned using
     * @ref LCB_SDSPEC_SET_VALUE. The contents of the value should be valid
     * until the operation is scheduled (i.e. lcb_subdoc3())
     */
    lcb_VALBUF value;
};

/**
 * Set the path for an @ref lcb_SDSPEC structure
 * @param s pointer to spec
 * @param p the path buffer
 * @param n the length of the path buffer
 */
#define LCB_SDSPEC_SET_PATH(s, p, n)                                                                                   \
    do {                                                                                                               \
        (s)->path.contig.bytes = p;                                                                                    \
        (s)->path.contig.nbytes = n;                                                                                   \
        (s)->path.type = LCB_KV_COPY;                                                                                  \
    } while (0);

/**
 * Set the value for the @ref lcb_SDSPEC structure
 * @param s pointer to spec
 * @param v the value buffer
 * @param n the length of the value buffer
 */
#define LCB_SDSPEC_SET_VALUE(s, v, n) LCB_CMD_SET_VALUE(s, v, n)

#define LCB_SDMULTI_MODE_INVALID 0
#define LCB_SDMULTI_MODE_LOOKUP 1
#define LCB_SDMULTI_MODE_MUTATE 2
/**
 * This command flag should be used if the document is to be created
 * if it does not exist.
 */
#define LCB_CMDSUBDOC_F_UPSERT_DOC (1u << 16u)

/**
 * This command flag should be used if the document must be created anew.
 * In this case, it will fail if it already exists
 */
#define LCB_CMDSUBDOC_F_INSERT_DOC (1u << 17u)

/**
 * Access a potentially deleted document. For internal Couchbase use
 */
#define LCB_CMDSUBDOC_F_ACCESS_DELETED (1u << 18u)

#define LCB_CMDSUBDOC_F_CREATE_AS_DELETED (1u << 19u)

struct lcb_SUBDOCSPECS_ {
    std::uint32_t options;

    lcb_SDSPEC *specs;
    /**
     * Number of entries in #specs
     */
    std::size_t nspecs;
};

struct lcb_CMDSUBDOC_ {
    /**Common flags for the command. These modify the command itself. Currently
     the lower 16 bits of this field are reserved, and the higher 16 bits are
     used for individual commands.*/
    std::uint32_t cmdflags;

    /**Specify the expiration time. This is either an absolute Unix time stamp
     or a relative offset from now, in seconds. If the value of this number
     is greater than the value of thirty days in seconds, then it is a Unix
     timestamp.

     This field is used in mutation operations (lcb_store3()) to indicate
     the lifetime of the item. It is used in lcb_get3() with the lcb_CMDGET::lock
     option to indicate the lock expiration itself. */
    std::uint32_t exptime;

    /**The known CAS of the item. This is passed to mutation to commands to
     ensure the item is only changed if the server-side CAS value matches the
     one specified here. For other operations (such as lcb_CMDENDURE) this
     is used to ensure that the item has been persisted/replicated to a number
     of servers with the value specified here. */
    std::uint64_t cas;

    /**< Collection ID */
    std::uint32_t cid;
    const char *scope;
    std::size_t nscope;
    const char *collection;
    std::size_t ncollection;
    /**The key for the document itself. This should be set via LCB_CMD_SET_KEY() */
    lcb_KEYBUF key;

    /** Operation timeout (in microseconds). When zero, the library will use default value. */
    std::uint32_t timeout;
    /** Parent tracing span */
    lcbtrace_SPAN *pspan;

    /**
     * An array of one or more command specifications. The storage
     * for the array need only persist for the duration of the
     * lcb_subdoc3() call.
     *
     * The specs array must be valid only through the invocation
     * of lcb_subdoc3(). As such, they can reside on the stack and
     * be re-used for scheduling multiple commands. See subdoc-simple.cc
     */
    const lcb_SDSPEC *specs;
    /**
     * Number of entries in #specs
     */
    std::size_t nspecs;
    /**
     * If the scheduling of the command failed, the index of the entry which
     * caused the failure will be written to this pointer.
     *
     * If the value is -1 then the failure took place at the command level
     * and not at the spec level.
     */
    int *error_index;
    /**
     * Operation mode to use. This can either be @ref LCB_SDMULTI_MODE_LOOKUP
     * or @ref LCB_SDMULTI_MODE_MUTATE.
     *
     * This field may be left empty, in which case the mode is implicitly
     * derived from the _first_ command issued.
     */
    std::uint32_t multimode;

    /**
     * @uncommitted
     * The level of durability required. Supported on Couchbase Server 6.5+
     */
    lcb_DURABILITY_LEVEL dur_level;
};

/**
 * Structure for a single sub-document mutation or lookup result.
 * Note that #value and #nvalue are only valid if #status is ::LCB_SUCCESS
 */
struct lcb_SDENTRY {
    /** Value for the mutation (only applicable for ::LCB_SDCMD_COUNTER, currently) */
    const void *value;
    /** Length of the value */
    std::size_t nvalue;
    /** Status code */
    lcb_STATUS status;

    /**
     * Request index which this result pertains to. This field only
     * makes sense for multi mutations where not all request specs are returned
     * in the result
     */
    std::uint8_t index;
};

/**
 * Response structure for multi lookups. If the top level response is successful
 * then the individual results may be retrieved using lcb_sdmlookup_next()
 */
struct lcb_RESPSUBDOC_ {
    lcb_KEY_VALUE_ERROR_CONTEXT ctx{};
    lcb_MUTATION_TOKEN mt{};
    /**
     Application-defined pointer passed as the `cookie` parameter when
     scheduling the command.
     */
    void *cookie;
    /** Response specific flags. see ::lcb_RESPFLAGS */
    std::uint16_t rflags;

    const void *responses;
    /** Use with lcb_backbuf_ref/unref */
    void *bufh;
    std::size_t nres;
    lcb_SDENTRY *res;
};

#endif // LIBCOUCHBASE_CAPI_SUBDOC_HH
