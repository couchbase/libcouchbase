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

#ifndef LIBCOUCHBASE_CAPI_PING_HH
#define LIBCOUCHBASE_CAPI_PING_HH

#include <cstddef>
#include <cstdint>

#include "key_value_error_context.hh"

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
    std::uint32_t services; /**< bitmap for services to ping */
    std::uint32_t options;  /**< extra options, e.g. for result representation */
    const char *id;         /**< optional, zero-terminated string to identify the report */
    std::size_t nid;
};

/**
 * Entry describing the status of the service in the cluster.
 * It is part of lcb_RESPING structure.
 *
 * @committed
 */
typedef struct lcb_PINGSVC_ {
    lcb_PING_SERVICE type; /**< type of the service */
    /* TODO: rename to "remote" */
    const char *server{nullptr}; /**< server host:port */
    std::uint64_t latency{0};    /**< latency in nanoseconds */
    lcb_STATUS rc{LCB_SUCCESS};  /**< raw return code of the operation */
    const char *local{nullptr};  /**< server host:port */
    const char *id{nullptr};     /**< service identifier (unique in scope of lcb_INSTANCE *connection instance) */
    const char *scope{nullptr};  /**< optional scope name (typically equals to the bucket name) */
    lcb_PING_STATUS status{LCB_PING_STATUS_OK}; /**< status of the operation */
} lcb_PINGSVC;

/**
 * Structure for PING responses.
 *
 * @committed
 */
struct lcb_RESPPING_ {
    lcb_KEY_VALUE_ERROR_CONTEXT ctx{};
    /**
     Application-defined pointer passed as the `cookie` parameter when
     scheduling the command.
     */
    void *cookie{nullptr};
    /** Response specific flags. see ::lcb_RESPFLAGS */
    std::uint16_t rflags{0};
    /** String containing the `host:port` of the server which sent this response */
    const char *server;
    std::size_t nservices{0};       /**< number of the nodes, replied to ping */
    lcb_PINGSVC *services{nullptr}; /**< the nodes, replied to ping, if any */
    std::size_t njson{0};           /**< length of JSON string (when #LCB_PINGOPT_F_JSON was specified) */
    const char *json{nullptr};      /**< pointer to JSON string */
    std::string id;
};

#endif // LIBCOUCHBASE_CAPI_PING_HH
