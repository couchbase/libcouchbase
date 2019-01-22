/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2018 Couchbase, Inc.
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
#include "trace.h"

LIBCOUCHBASE_API
lcb_error_t lcb_remove3(lcb_t instance, const void *cookie, const lcb_CMDREMOVE *cmd)
{
    mc_CMDQUEUE *cq = &instance->cmdq;
    mc_PIPELINE *pl;
    mc_PACKET *pkt;
    lcb_error_t err;
    protocol_binary_request_delete req = {0};
    protocol_binary_request_header *hdr = &req.message.header;
    int new_durability_supported = LCBT_SUPPORT_SYNCREPLICATION(instance);
    lcb_U8 ffextlen = 0;
    size_t hsize;

    if (LCB_KEYBUF_IS_EMPTY(&cmd->key)) {
        return LCB_EMPTY_KEY;
    }

    if (cmd->dur_level) {
        if (new_durability_supported) {
            hdr->request.magic = PROTOCOL_BINARY_AREQ;
            ffextlen = 4;
        } else {
            return LCB_NOT_SUPPORTED;
        }
    }

    err = mcreq_basic_packet(cq, (const lcb_CMDBASE *)cmd, hdr, 0, ffextlen, &pkt, &pl, MCREQ_BASICPACKET_F_FALLBACKOK);
    if (err != LCB_SUCCESS) {
        return err;
    }
    hsize = hdr->request.extlen + sizeof(*hdr) + ffextlen;

    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.opcode = PROTOCOL_BINARY_CMD_DELETE;
    hdr->request.cas = lcb_htonll(cmd->cas);
    hdr->request.opaque = pkt->opaque;
    hdr->request.bodylen = htonl(ffextlen + hdr->request.extlen + (lcb_uint32_t)ntohs(hdr->request.keylen));
    if (cmd->dur_level && new_durability_supported) {
        req.message.body.alt.meta = (1 << 4) | 3;
        req.message.body.alt.level = cmd->dur_level;
        req.message.body.alt.timeout = htons(cmd->dur_timeout);
    }

    pkt->u_rdata.reqdata.cookie = cookie;
    pkt->u_rdata.reqdata.start = gethrtime();
    memcpy(SPAN_BUFFER(&pkt->kh_span), hdr->bytes, hsize);
    LCBTRACE_KV_START(instance->settings, cmd, LCBTRACE_OP_REMOVE, pkt->opaque, pkt->u_rdata.reqdata.span);
    TRACE_REMOVE_BEGIN(instance, hdr, cmd);
    LCB_SCHED_ADD(instance, pl, pkt);
    return LCB_SUCCESS;
}
