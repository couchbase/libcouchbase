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

#ifndef LIBCOUCHBASE_CAPI_STORE_HH
#define LIBCOUCHBASE_CAPI_STORE_HH

#include <cstddef>
#include <cstdint>

/**
 * @private
 */
struct lcb_CMDSTORE_ {
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
    size_t nscope;
    const char *collection;
    size_t ncollection;
    /**The key for the document itself. This should be set via LCB_CMD_SET_KEY() */
    lcb_KEYBUF key;

    /** Operation timeout (in microseconds). When zero, the library will use default value. */
    std::uint32_t timeout;
    /** Parent tracing span */
    lcbtrace_SPAN *pspan;

    /**
     * Value to store on the server. The value may be set using the
     * LCB_CMD_SET_VALUE() or LCB_CMD_SET_VALUEIOV() API
     */
    lcb_VALBUF value;

    /**
     * Format flags used by clients to determine the underlying encoding of
     * the value. This value is also returned during retrieval operations in the
     * lcb_RESPGET::itmflags field
     */
    std::uint32_t flags;

    /** Do not set this value for now */
    std::uint8_t datatype;

    /** Controls *how* the operation is perfomed. See the documentation for
     * @ref lcb_storage_t for the options. There is no default value for this
     * field.
     */
    lcb_STORE_OPERATION operation;

    std::uint8_t durability_mode;

    union {
        struct {
            /**
             * Number of nodes to persist to. If negative, will be capped at the maximum
             * allowable for the current cluster.
             * @see lcb_DURABILITYOPTSv0::persist_to
             */
            char persist_to;

            /**
             * Number of nodes to replicate to. If negative, will be capped at the maximum
             * allowable for the current cluster.
             * @see lcb_DURABILITYOPTSv0::replicate_to
             */
            char replicate_to;
        } poll;
        struct {
            /**
             * @uncommitted
             * The level of durability required. Supported on Couchbase Server 6.5+
             */
            lcb_DURABILITY_LEVEL dur_level;
        } sync;
    } durability;
};

/**
 * @private
 */
struct lcb_RESPSTORE_ {
    /**
     Application-defined pointer passed as the `cookie` parameter when
     scheduling the command.
     */
    lcb_KEY_VALUE_ERROR_CONTEXT ctx;
    void *cookie;
    /** Response specific flags. see ::lcb_RESPFLAGS */
    std::uint16_t rflags;

    /** The type of operation which was performed */
    lcb_STORE_OPERATION op;

    /** Internal durability response structure. */
    const lcb_RESPENDURE *dur_resp;

    /**If the #rc field is not @ref LCB_SUCCESS, this field indicates
     * what failed. If this field is nonzero, then the store operation failed,
     * but the durability checking failed. If this field is zero then the
     * actual storage operation failed. */
    int store_ok;
};

#endif // LIBCOUCHBASE_CAPI_STORE_HH
