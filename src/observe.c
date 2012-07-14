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

#include "internal.h"

struct observe_st
{
    int allocated;
    protocol_binary_request_no_extras req;
    ringbuffer_t body;
    libcouchbase_size_t nbody;
};

static void destroy_request(struct observe_st *req)
{
    if (req->allocated) {
        ringbuffer_destruct(&req->body);
        req->allocated = 0;
    }
}

static int init_request(struct observe_st *req)
{
    memset(&req->req, 0, sizeof(req->req));
    if (!ringbuffer_initialize(&req->body, 512)) {
        return 0;
    }
    req->allocated = 1;
    return 1;
}

static void destroy_requests(struct observe_st *req, libcouchbase_size_t nreq)
{
    libcouchbase_size_t ii;

    for (ii = 0; ii < nreq; ++ii) {
        destroy_request(req + ii);
    }
    free(req);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_observe(libcouchbase_t instance,
                                          const void *command_cookie,
                                          libcouchbase_size_t num_keys,
                                          const void *const *keys,
                                          const libcouchbase_size_t *nkey)
{
    int vbid, idx, jj;
    libcouchbase_size_t ii;
    libcouchbase_uint32_t opaque;
    struct observe_st *requests;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
    }

    if (instance->dist_type != VBUCKET_DISTRIBUTION_VBUCKET) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NOT_SUPPORTED);
    }

    /* the list of pointers to body buffers for each server */
    requests = calloc(instance->nservers, sizeof(struct observe_st));
    opaque = ++instance->seqno;
    for (ii = 0; ii < num_keys; ++ii) {
        vbid = vbucket_get_vbucket_by_key(instance->vbucket_config, keys[ii], nkey[ii]);
        for (jj = -1; jj < instance->nreplicas; ++jj) {
            struct observe_st *rr;
            /* it will increment jj to get server index, so (-1 + 1) = 0 (master) */
            idx = vbucket_get_replica(instance->vbucket_config, vbid, jj);
            if ((idx < 0 || idx > (int)instance->nservers)) {
                /* the config says that there is no server yet at that position (-1) */
                if (jj == -1) {
                    /* master node must be available */
                    destroy_requests(requests, instance->nservers);
                    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NETWORK_ERROR);
                } else {
                    continue;
                }
            }
            rr = requests + idx;
            if (!rr->allocated) {
                if (!init_request(rr)) {
                    destroy_requests(requests, instance->nservers);
                    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_CLIENT_ENOMEM);
                }
                rr->req.message.header.request.magic = PROTOCOL_BINARY_REQ;
                rr->req.message.header.request.opcode = CMD_OBSERVE;
                rr->req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
                rr->req.message.header.request.opaque = opaque;
            }

            {
                libcouchbase_uint16_t vb = htons(vbid);
                libcouchbase_uint16_t len = htons((libcouchbase_uint16_t)nkey[ii]);
                ringbuffer_ensure_capacity(&rr->body, sizeof(vb) + sizeof(len) + nkey[ii]);
                rr->nbody += ringbuffer_write(&rr->body, &vb, sizeof(vb));
                rr->nbody += ringbuffer_write(&rr->body, &len, sizeof(len));
                rr->nbody += ringbuffer_write(&rr->body, keys[ii], nkey[ii]);
            }
        }
    }

    for (ii = 0; ii < instance->nservers; ++ii) {
        struct observe_st *rr = requests + ii;
        libcouchbase_server_t *server = instance->servers + ii;

        if (rr->allocated) {
            rr->req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)rr->nbody);
            libcouchbase_server_start_packet(server, command_cookie, rr->req.bytes, sizeof(rr->req.bytes));
            if (ringbuffer_is_continous(&rr->body, RINGBUFFER_READ, rr->nbody)) {
                libcouchbase_server_write_packet(server, ringbuffer_get_read_head(&rr->body), rr->nbody);
            } else {
                char *tmp = malloc(ringbuffer_get_nbytes(&rr->body));
                if (!tmp) {
                    /* FIXME by this time some of requests might be scheduled */
                    destroy_requests(requests, instance->nservers);
                    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_CLIENT_ENOMEM);
                } else {
                    ringbuffer_read(&rr->body, tmp, rr->nbody);
                    libcouchbase_server_write_packet(server, tmp, rr->nbody);
                }
            }
            libcouchbase_server_end_packet(server);
            libcouchbase_server_send_packets(server);
        }
    }

    destroy_requests(requests, instance->nservers);
    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}
