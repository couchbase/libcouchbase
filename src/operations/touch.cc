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
lcb_error_t lcb_touch3(lcb_t instance, const void *cookie, const lcb_CMDTOUCH *cmd)
{
    protocol_binary_request_touch tcmd;
    protocol_binary_request_header *hdr = &tcmd.message.header;
    int new_durability_supported = LCBT_SUPPORT_SYNCREPLICATION(instance);
    mc_PIPELINE *pl;
    mc_PACKET *pkt;
    lcb_error_t err;
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

    err = mcreq_basic_packet(&instance->cmdq, (const lcb_CMDBASE *)cmd, hdr, 4, ffextlen, &pkt, &pl,
                             MCREQ_BASICPACKET_F_FALLBACKOK);
    if (err != LCB_SUCCESS) {
        return err;
    }
    hsize = hdr->request.extlen + sizeof(*hdr) + ffextlen;

    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.opcode = PROTOCOL_BINARY_CMD_TOUCH;
    hdr->request.cas = 0;
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr->request.opaque = pkt->opaque;
    hdr->request.bodylen = htonl(4 + ffextlen + ntohs(hdr->request.keylen));
    if (cmd->dur_level && new_durability_supported) {
        tcmd.message.body.alt.meta = (1 << 4) | 3;
        tcmd.message.body.alt.level = cmd->dur_level;
        tcmd.message.body.alt.timeout = htons(cmd->dur_timeout);
        tcmd.message.body.alt.expiration = htonl(cmd->exptime);
    } else {
        tcmd.message.body.norm.expiration = htonl(cmd->exptime);
    }

    memcpy(SPAN_BUFFER(&pkt->kh_span), tcmd.bytes, hsize);
    pkt->u_rdata.reqdata.cookie = cookie;
    pkt->u_rdata.reqdata.start = gethrtime();
    LCB_SCHED_ADD(instance, pl, pkt);
    LCBTRACE_KV_START(instance->settings, cmd, LCBTRACE_OP_TOUCH, pkt->opaque, pkt->u_rdata.reqdata.span);
    TRACE_TOUCH_BEGIN(instance, hdr, cmd);
    return LCB_SUCCESS;
}
