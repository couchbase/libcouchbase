/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2012 Couchbase, Inc.
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

static lcb_size_t
get_value_size(mc_PACKET *packet)
{
    if (packet->flags & MCREQ_F_VALUE_IOV) {
        return packet->u_value.multi.total_length;
    } else {
        return packet->u_value.single.size;
    }
}

static lcb_error_t
get_esize_and_opcode(
        lcb_storage_t ucmd, lcb_uint8_t *opcode, lcb_uint8_t *esize)
{
    if (ucmd == LCB_SET) {
        *opcode = PROTOCOL_BINARY_CMD_SET;
        *esize = 8;
    } else if (ucmd == LCB_ADD) {
        *opcode = PROTOCOL_BINARY_CMD_ADD;
        *esize = 8;
    } else if (ucmd == LCB_REPLACE) {
        *opcode = PROTOCOL_BINARY_CMD_REPLACE;
        *esize = 8;
    } else if (ucmd == LCB_APPEND) {
        *opcode = PROTOCOL_BINARY_CMD_APPEND;
        *esize = 0;
    } else if (ucmd == LCB_PREPEND) {
        *opcode = PROTOCOL_BINARY_CMD_PREPEND;
        *esize = 0;
    } else {
        return LCB_EINVAL;
    }
    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
lcb_error_t
lcb_store3(lcb_t instance, const void *cookie, const lcb_store3_cmd_t *cmd)
{
    mc_PIPELINE *pipeline;
    mc_PACKET *packet;
    mc_REQDATA *rdata;
    mc_CMDQUEUE *cq = &instance->cmdq;
    int hsize;
    lcb_error_t err;

    protocol_binary_request_set scmd;
    protocol_binary_request_header *hdr = &scmd.message.header;

    err = get_esize_and_opcode(
            cmd->operation, &hdr->request.opcode, &hdr->request.extlen);
    if (err != LCB_SUCCESS) {
        return err;
    }

    hsize = hdr->request.extlen + sizeof(*hdr);

    err = mcreq_basic_packet(
            cq, (const lcb_cmd_t *)cmd, hdr, hdr->request.extlen,
            &packet, &pipeline);

    if (err != LCB_SUCCESS) {
        return err;
    }

    mcreq_reserve_value(pipeline, packet, &cmd->value);

    rdata = &packet->u_rdata.reqdata;
    rdata->cookie = cookie;
    rdata->start = gethrtime();

    scmd.message.body.expiration = htonl(cmd->options.exptime);
    scmd.message.body.flags = htonl(cmd->flags);
    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.cas = cmd->options.cas;
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr->request.opaque = packet->opaque;
    hdr->request.bodylen = htonl(
            hdr->request.extlen + ntohs(hdr->request.keylen)
            + get_value_size(packet));

    memcpy(SPAN_BUFFER(&packet->kh_span), scmd.bytes, hsize);
    mcreq_sched_add(pipeline, packet);
    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
lcb_error_t
lcb_store(lcb_t instance, const void *cookie, lcb_size_t num,
          const lcb_store_cmd_t * const * items)
{
    unsigned ii;
    lcb_error_t err = LCB_SUCCESS;
    for (ii = 0; ii < num; ii++) {
        const lcb_store_cmd_t *src = items[ii];
        lcb_store3_cmd_t dst;
        memset(&dst, 0, sizeof(dst));

        dst.key.contig.bytes = src->v.v0.key;
        dst.key.contig.nbytes = src->v.v0.nkey;
        dst.hashkey.contig.bytes = src->v.v0.hashkey;
        dst.hashkey.contig.nbytes = src->v.v0.nhashkey;
        dst.value.u_buf.contig.bytes = src->v.v0.bytes;
        dst.value.u_buf.contig.nbytes = src->v.v0.nbytes;
        dst.operation = src->v.v0.operation;
        dst.flags = src->v.v0.flags;
        dst.datatype = src->v.v0.datatype;
        dst.options.cas = src->v.v0.cas;
        dst.options.exptime = src->v.v0.exptime;
        err = lcb_store3(instance, cookie, &dst);
        if (err != LCB_SUCCESS) {
            mcreq_sched_fail(&instance->cmdq);
            return err;
        }
    }
    mcreq_sched_leave(&instance->cmdq, 1);
    return LCB_SUCCESS;
}
