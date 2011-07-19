/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc.
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

/**
 * This file contains the functions to tap the cluster
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

struct libcouchbase_tap_filter_st {
    /** Represents the oldest entry (from epoch) you're interested in */
    uint64_t backfill;
    /** If true, notifies the tap server that we don't care about values */
    bool keys_only;
};

/**
 * Create an instance of a libcouchbase tap filter (libcouchbase_tap_filter_t).
 */
LIBCOUCHBASE_API
libcouchbase_tap_filter_t libcouchbase_tap_filter_create()
{
    libcouchbase_tap_filter_t ret;

    if ((ret = calloc(1, sizeof(*ret))) == NULL) {
        return NULL;
    }

    // Set the defaults.
    ret->backfill = 0;
    ret->keys_only = false;

    return ret;
}

/**
 * Destroy (and release all allocated resources) an instance of a libcouchbase
 * tap filter (libcouchbase_tap_filter_t). Using the instance after calling
 * destroy will most likely cause your application to crash.
 * @param instance the instance to destroy.
 */
LIBCOUCHBASE_API
void libcouchbase_tap_filter_destroy(libcouchbase_tap_filter_t instance)
{
    memset(instance, 0xff, sizeof(*instance));
    free(instance);
}

/**
 * Set the backfill value for your tap stream.
 * @param instance the tap filter instance to modify.
 * @param backfill the oldest entry (from epoch) you're interested in.
 */
LIBCOUCHBASE_API
void libcouchbase_tap_filter_set_backfill(libcouchbase_tap_filter_t instance,
                                          uint64_t backfill)
{
    instance->backfill = backfill;
}

/**
 * Get the backfill value for your tap stream.
 * @param instance the tap filter instance to retrieve the value from.
 */
LIBCOUCHBASE_API
uint64_t libcouchbase_tap_filter_get_backfill(libcouchbase_tap_filter_t instance)
{
    return instance->backfill;
}

/**
 * Set whether you are interested in keys and values, or only keys in your
 * tap stream.
 * @param instance the tap filter instance to modify.
 * @param keys_only true if you are only interested in keys, false if
 *                  you also want values.
 */
LIBCOUCHBASE_API
void libcouchbase_tap_filter_set_keys_only(libcouchbase_tap_filter_t instance,
                                           bool keys_only)
{
    instance->keys_only = keys_only;
}

/**
 * Get whether you are interested in keys and values, or only keys in your
 * tap stream.
 * @param instance the tap filter instance to retrieve the value from.
 */
LIBCOUCHBASE_API
bool libcouchbase_tap_filter_get_keys_only(libcouchbase_tap_filter_t instance)
{
    return instance->keys_only;
}

static void tap_vbucket_state_listener(libcouchbase_server_t *server)
{
    libcouchbase_t instance = server->instance;
    libcouchbase_tap_filter_t filter = instance->tap.filter;
    // Locate this index:
    size_t idx;
    size_t bodylen;
    uint16_t total = 0;
    protocol_binary_request_tap_connect req;
    int ii;
    uint16_t val;
    uint32_t flags = TAP_CONNECT_FLAG_LIST_VBUCKETS;
    uint64_t backfill = 0;
    uint64_t backfilln;
    size_t backfill_size = 0;

    for (idx = 0; idx < instance->nservers; ++idx) {
        if (server == instance->servers + idx) {
            break;
        }
    }
    assert(idx != instance->nservers);

    // Count the numbers of vbuckets for this server:
    for (ii = 0; ii < instance->nvbuckets; ++ii) {
        if (instance->vb_server_map[ii] == idx) {
            ++total;
        }
    }

    if (filter != NULL) {
        if (filter->backfill != 0) {
            flags |= TAP_CONNECT_FLAG_BACKFILL;
            backfill = htonll(filter->backfill);
            backfill_size = sizeof(backfill);
        }

        if (filter->keys_only) {
            flags |= TAP_CONNECT_REQUEST_KEYS_ONLY;
        }
    }

    bodylen = ((size_t)total * 2 + 6) + backfill_size;
    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_TAP_CONNECT;
    req.message.header.request.extlen = 4;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = htonl((uint32_t)bodylen);
    req.message.body.flags = htonl(flags);

    libcouchbase_server_start_packet(server, req.bytes, sizeof(req.bytes));

    // Write the backfill value.
    if (filter && filter->backfill != 0) {
        backfilln = htonll(backfill);
        libcouchbase_server_write_packet(server, &backfilln, sizeof(backfilln));
    }

    // Write the vbucket list.
    val = htons(total);
    libcouchbase_server_write_packet(server, &val, sizeof(val));
    for (ii = 0; ii < instance->nvbuckets; ++ii) {
        if (instance->vb_server_map[ii] == idx) {
            val = htons((uint16_t)ii);
            libcouchbase_server_write_packet(server, &val, sizeof(val));
        }
    }
    libcouchbase_server_end_packet(server);

    libcouchbase_server_send_packets(server);
}

LIBCOUCHBASE_API
void libcouchbase_tap_cluster(libcouchbase_t instance,
                              libcouchbase_tap_filter_t filter,
                              bool block)
{
    // connect to the upstream server.
    instance->vbucket_state_listener = tap_vbucket_state_listener;
    instance->tap.filter = filter;

    /* Start the event loop and dump everything */
    if (block) {
        event_base_loop(instance->ev_base, 0);
    }
}
