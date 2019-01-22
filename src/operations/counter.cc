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
lcb_error_t lcb_counter3(lcb_t instance, const void *cookie, const lcb_CMDCOUNTER *cmd)
{
    mc_CMDQUEUE *q = &instance->cmdq;
    mc_PIPELINE *pipeline;
    mc_PACKET *packet;
    mc_REQDATA *rdata;
    lcb_error_t err;
    int new_durability_supported = LCBT_SUPPORT_SYNCREPLICATION(instance);
    lcb_U8 ffextlen = 0;
    size_t hsize;

    protocol_binary_request_incr acmd;
    protocol_binary_request_header *hdr = &acmd.message.header;

    if (LCB_KEYBUF_IS_EMPTY(&cmd->key)) {
        return LCB_EMPTY_KEY;
    }
    if (cmd->cas || (cmd->create == 0 && cmd->exptime != 0)) {
        return LCB_OPTIONS_CONFLICT;
    }

    if (cmd->dur_level) {
        if (new_durability_supported) {
            hdr->request.magic = PROTOCOL_BINARY_AREQ;
            ffextlen = 4;
        } else {
            return LCB_NOT_SUPPORTED;
        }
    }

    err = mcreq_basic_packet(q, (const lcb_CMDBASE *)cmd, hdr, 20, ffextlen, &packet, &pipeline,
                             MCREQ_BASICPACKET_F_FALLBACKOK);
    if (err != LCB_SUCCESS) {
        return err;
    }
    hsize = hdr->request.extlen + sizeof(*hdr) + ffextlen;

    rdata = &packet->u_rdata.reqdata;
    rdata->cookie = cookie;
    rdata->start = gethrtime();
    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr->request.cas = 0;
    hdr->request.opaque = packet->opaque;
    hdr->request.bodylen = htonl(ffextlen + hdr->request.extlen + ntohs(hdr->request.keylen));

    uint32_t *exp;
    uint64_t *delta;
    if (cmd->dur_level && new_durability_supported) {
        acmd.message.body.alt.meta = (1 << 4) | 3;
        acmd.message.body.alt.level = cmd->dur_level;
        acmd.message.body.alt.timeout = htons(cmd->dur_timeout);
        acmd.message.body.alt.initial = lcb_htonll(cmd->initial);
        exp = &acmd.message.body.alt.expiration;
        delta = &acmd.message.body.alt.delta;
    } else {
        acmd.message.body.norm.initial = lcb_htonll(cmd->initial);
        exp = &acmd.message.body.norm.expiration;
        delta = &acmd.message.body.norm.delta;
    }
    if (!cmd->create) {
        memset(exp, 0xff, sizeof(*exp));
    } else {
        *exp = htonl(cmd->exptime);
    }

    if (cmd->delta < 0) {
        hdr->request.opcode = PROTOCOL_BINARY_CMD_DECREMENT;
        *delta = lcb_htonll((lcb_uint64_t)(cmd->delta * -1));
    } else {
        hdr->request.opcode = PROTOCOL_BINARY_CMD_INCREMENT;
        *delta = lcb_htonll(cmd->delta);
    }

    memcpy(SPAN_BUFFER(&packet->kh_span), acmd.bytes, hsize);
    LCBTRACE_KV_START(instance->settings, cmd, LCBTRACE_OP_COUNTER, packet->opaque, rdata->span);
    TRACE_ARITHMETIC_BEGIN(instance, hdr, cmd);
    LCB_SCHED_ADD(instance, pipeline, packet);
    return LCB_SUCCESS;
}
