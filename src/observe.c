/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2012 Couchbase, Inc.
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

struct observe_st {
    int allocated;
    protocol_binary_request_no_extras req;
    ringbuffer_t body;
    lcb_size_t nbody;
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

static void destroy_requests(struct observe_st *req, lcb_size_t nreq)
{
    lcb_size_t ii;

    for (ii = 0; ii < nreq; ++ii) {
        destroy_request(req + ii);
    }
    free(req);
}

LIBCOUCHBASE_API
lcb_error_t lcb_observe(lcb_t instance,
                        const void *command_cookie,
                        lcb_size_t num,
                        const lcb_observe_cmd_t *const *items)
{
    int vbid, idx, jj;
    lcb_size_t ii;
    lcb_uint32_t opaque;
    struct observe_st *requests;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        switch (instance->type) {
        case LCB_TYPE_CLUSTER:
            return lcb_synchandler_return(instance, LCB_EBADHANDLE);
        case LCB_TYPE_BUCKET:
        default:
            return lcb_synchandler_return(instance, LCB_CLIENT_ETMPFAIL);
        }
    }

    if (instance->dist_type != VBUCKET_DISTRIBUTION_VBUCKET) {
        return lcb_synchandler_return(instance, LCB_NOT_SUPPORTED);
    }

    /* the list of pointers to body buffers for each server */
    requests = calloc(instance->nservers, sizeof(struct observe_st));
    opaque = ++instance->seqno;
    for (ii = 0; ii < num; ++ii) {
        const void *key = items[ii]->v.v0.key;
        lcb_size_t nkey = items[ii]->v.v0.nkey;
        const void *hashkey = items[ii]->v.v0.hashkey;
        lcb_size_t nhashkey = items[ii]->v.v0.nhashkey;

        if (nhashkey == 0) {
            hashkey = key;
            nhashkey = nkey;
        }

        vbid = vbucket_get_vbucket_by_key(instance->vbucket_config, hashkey,
                                          nhashkey);
        for (jj = -1; jj < instance->nreplicas; ++jj) {
            struct observe_st *rr;
            /* it will increment jj to get server index, so (-1 + 1) = 0 (master) */
            idx = vbucket_get_replica(instance->vbucket_config, vbid, jj);
            if ((idx < 0 || idx > (int)instance->nservers)) {
                /* the config says that there is no server yet at that position (-1) */
                if (jj == -1) {
                    /* master node must be available */
                    destroy_requests(requests, instance->nservers);
                    return lcb_synchandler_return(instance, LCB_NETWORK_ERROR);
                } else {
                    continue;
                }
            }
            rr = requests + idx;
            if (!rr->allocated) {
                if (!init_request(rr)) {
                    destroy_requests(requests, instance->nservers);
                    return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
                }
                rr->req.message.header.request.magic = PROTOCOL_BINARY_REQ;
                rr->req.message.header.request.opcode = CMD_OBSERVE;
                rr->req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
                rr->req.message.header.request.opaque = opaque;
            }

            {
                lcb_uint16_t vb = htons((lcb_uint16_t)vbid);
                lcb_uint16_t len = htons((lcb_uint16_t)nkey);
                ringbuffer_ensure_capacity(&rr->body, sizeof(vb) + sizeof(len) + nkey);
                rr->nbody += ringbuffer_write(&rr->body, &vb, sizeof(vb));
                rr->nbody += ringbuffer_write(&rr->body, &len, sizeof(len));
                rr->nbody += ringbuffer_write(&rr->body, key, nkey);
            }
        }
    }

    for (ii = 0; ii < instance->nservers; ++ii) {
        struct observe_st *rr = requests + ii;
        lcb_server_t *server = instance->servers + ii;

        if (rr->allocated) {
            char *tmp;
            rr->req.message.header.request.bodylen = ntohl((lcb_uint32_t)rr->nbody);
            lcb_server_start_packet(server, command_cookie, rr->req.bytes, sizeof(rr->req.bytes));
            if (ringbuffer_is_continous(&rr->body, RINGBUFFER_READ, rr->nbody)) {
                tmp = ringbuffer_get_read_head(&rr->body);
                TRACE_OBSERVE_BEGIN(&rr->req, server->authority, tmp, rr->nbody);
                lcb_server_write_packet(server, tmp, rr->nbody);
            } else {
                tmp = malloc(ringbuffer_get_nbytes(&rr->body));
                if (!tmp) {
                    /* FIXME by this time some of requests might be scheduled */
                    destroy_requests(requests, instance->nservers);
                    return lcb_synchandler_return(instance, LCB_CLIENT_ENOMEM);
                } else {
                    ringbuffer_read(&rr->body, tmp, rr->nbody);
                    TRACE_OBSERVE_BEGIN(&rr->req, server->authority, tmp, rr->nbody);
                    lcb_server_write_packet(server, tmp, rr->nbody);
                }
            }
            lcb_server_end_packet(server);
            lcb_server_send_packets(server);
        }
    }

    destroy_requests(requests, instance->nservers);
    return lcb_synchandler_return(instance, LCB_SUCCESS);
}
