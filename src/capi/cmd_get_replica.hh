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

#ifndef LIBCOUCHBASE_CAPI_GET_REPLICA_HH
#define LIBCOUCHBASE_CAPI_GET_REPLICA_HH

#include <cstddef>
#include <cstdint>

#include "key_value_error_context.hh"

struct lcb_RESPGETREPLICA_ {
    lcb_KEY_VALUE_ERROR_CONTEXT ctx{};
    /**
     Application-defined pointer passed as the `cookie` parameter when
     scheduling the command.
     */
    void *cookie;
    /** Response specific flags. see ::lcb_RESPFLAGS */
    std::uint16_t rflags;
    const void *value;  /**< Value buffer for the item */
    std::size_t nvalue; /**< Length of value */
    void *bufh;
    std::uint8_t datatype;  /**< @internal */
    std::uint32_t itmflags; /**< User-defined flags for the item */
};

/**@brief Select get-replica mode
 * @see lcb_rget3_cmd_t */
enum lcb_replica_t {
    /**Query all the replicas sequentially, retrieving the first successful
     * response */
    LCB_REPLICA_FIRST = 0x00,

    /**Query all the replicas concurrently, retrieving all the responses*/
    LCB_REPLICA_ALL = 0x01,

    /**Query the specific replica specified by the
     * lcb_rget3_cmd_t#index field */
    LCB_REPLICA_SELECT = 0x02
};

/**
 * @brief Command for requesting an item from a replica
 * @note The `options.exptime` and `options.cas` fields are ignored for this
 * command.
 *
 * This structure is similar to @ref lcb_RESPGET with the addition of an
 * `index` and `strategy` field which allow you to control and select how
 * many replicas are queried.
 *
 * @see lcb_rget3(), lcb_RESPGET
 */
struct lcb_CMDGETREPLICA_ {
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
     * Strategy for selecting a replica. The default is ::LCB_REPLICA_FIRST
     * which results in the client trying each replica in sequence until a
     * successful reply is found, and returned in the callback.
     *
     * ::LCB_REPLICA_FIRST evaluates to 0.
     *
     * Other options include:
     * <ul>
     * <li>::LCB_REPLICA_ALL - queries all replicas concurrently and dispatches
     * a callback for each reply</li>
     * <li>::LCB_REPLICA_SELECT - queries a specific replica indicated in the
     * #index field</li>
     * </ul>
     *
     * @note When ::LCB_REPLICA_ALL is selected, the callback will be invoked
     * multiple times, one for each replica. The final callback will have the
     * ::LCB_RESP_F_FINAL bit set in the lcb_RESPBASE::rflags field. The final
     * response will also contain the response from the last replica to
     * respond.
     */
    lcb_replica_t strategy;

    /**
     * Valid only when #strategy is ::LCB_REPLICA_SELECT, specifies the replica
     * index number to query. This should be no more than `nreplicas-1`
     * where `nreplicas` is the number of replicas the bucket is configured with.
     */
    int index;
};

#endif // LIBCOUCHBASE_CAPI_GET_REPLICA_HH
