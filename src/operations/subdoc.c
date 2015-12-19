/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc.
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

/* We can still support subdocument paths along with non-copiable values
 * with the caveat that the path be encoded as part of the value (as the
 * first IOV).
 *
 */
#define SDTYPE_PLAIN 0
#define SDTYPE_COUNTER 1
#define SDTYPE_STORE 2

static lcb_error_t
sd_packet_common(lcb_t instance, const void *cookie, const lcb_CMDSDBASE *cmd,
    int sdtype, protocol_binary_request_subdocument *request,
    mc_PACKET **packet_p, mc_PIPELINE **pipeline_p)
{
    lcb_error_t rc;
    mc_PIPELINE *pipeline = NULL;
    mc_PACKET *packet = NULL;
    mc_REQDATA *rdata = NULL;
    lcb_VALBUF valbuf = { 0 };
    const lcb_VALBUF *valbuf_p = &valbuf;
    lcb_IOV tmpiov[2];
    char numbuf[24] = { 0 };

    lcb_FRAGBUF *fbuf = &valbuf.u_buf.multi;
    protocol_binary_request_header *hdr = &request->message.header;

    if (!cmd->key.contig.nbytes) {
        /* Path can be empty! */
        return LCB_EMPTY_KEY;
    }

    valbuf.vtype = LCB_KV_IOVCOPY;
    fbuf->iov = tmpiov;
    fbuf->niov = 1;
    fbuf->total_length = 0;
    tmpiov[0].iov_base = (void *)cmd->path;
    tmpiov[0].iov_len = cmd->npath;

    if (sdtype == SDTYPE_STORE) {
        const lcb_CMDSDSTORE *scmd = (const lcb_CMDSDSTORE*)cmd;
        if (scmd->value.vtype == LCB_KV_COPY) {
            fbuf->niov = 2;
            /* Subdoc value is the second IOV */
            tmpiov[1].iov_base = (void *)scmd->value.u_buf.contig.bytes;
            tmpiov[1].iov_len = scmd->value.u_buf.contig.nbytes;
        } else {
            /* Assume properly formatted packet */
            valbuf_p = &scmd->value;
        }
    } else if (sdtype == SDTYPE_COUNTER) {
        const lcb_CMDSDCOUNTER *ccmd = (const lcb_CMDSDCOUNTER *)cmd;
        size_t nbuf = sprintf(numbuf, "%lld", ccmd->delta);
        fbuf->niov = 2;
        tmpiov[1].iov_base = numbuf;
        tmpiov[1].iov_len = nbuf;
    }

    rc = mcreq_basic_packet(&instance->cmdq,
        (const lcb_CMDBASE*)cmd,
        hdr, 3, &packet, &pipeline, MCREQ_BASICPACKET_F_FALLBACKOK);

    if (rc != LCB_SUCCESS) {
        return rc;
    }

    rc = mcreq_reserve_value(pipeline, packet, valbuf_p);
    if (rc != LCB_SUCCESS) {
        return rc;
    }

    rdata = MCREQ_PKT_RDATA(packet);
    rdata->cookie = cookie;
    rdata->start = gethrtime();

    hdr->request.magic = PROTOCOL_BINARY_REQ;
    hdr->request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr->request.extlen = packet->extlen;
    hdr->request.opaque = packet->opaque;
    hdr->request.cas = cmd->cas;
    hdr->request.bodylen = htonl(hdr->request.extlen +
        ntohs(hdr->request.keylen) + get_value_size(packet));

    request->message.extras.pathlen = htons(cmd->npath);

    if (cmd->cmdflags & LCB_CMDSUBDOC_F_MKINTERMEDIATES) {
        request->message.extras.subdoc_flags = SUBDOC_FLAG_MKDIR_P;
    } else {
        request->message.extras.subdoc_flags = 0;
    }

    *packet_p = packet;
    *pipeline_p = pipeline;
    return rc;
}

/* Handles the basic creation of the packet and value assignment.
 * This dispatches to sd_packet_common which actually handles the
 * encoding of the command
 */
static lcb_error_t
sd_common(lcb_t instance, const void *cookie, const lcb_CMDSDBASE *cmd,
          uint8_t op, int type)
{
    mc_PACKET *packet;
    mc_PIPELINE *pipeline;
    lcb_error_t err;

    protocol_binary_request_subdocument scmd;
    protocol_binary_request_header *hdr = &scmd.message.header;

    err = sd_packet_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        type, &scmd, &packet, &pipeline);

    if (err != LCB_SUCCESS) {
        return err;
    }

    hdr->request.opcode = op;
    memcpy(SPAN_BUFFER(&packet->kh_span), scmd.bytes, sizeof scmd.bytes);
    mcreq_sched_add(pipeline, packet);
    return LCB_SUCCESS;

}

/* Gets the opcode for the given mode. Returns 0xff if mode is invalid */
static uint8_t
sdmode_to_opcode(unsigned mode)
{
    if (mode == LCB_SUBDOC_REPLACE) {
        return PROTOCOL_BINARY_CMD_SUBDOC_REPLACE;
    } else if (mode == LCB_SUBDOC_DICT_ADD) {
        return PROTOCOL_BINARY_CMD_SUBDOC_DICT_ADD;
    } else if (mode == LCB_SUBDOC_DICT_UPSERT) {
        return PROTOCOL_BINARY_CMD_SUBDOC_DICT_UPSERT;
    } else if (mode == LCB_SUBDOC_ARRAY_ADD_FIRST) {
        return PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_FIRST;
    } else if (mode == LCB_SUBDOC_ARRAY_ADD_LAST) {
        return PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_LAST;
    } else if (mode == LCB_SUBDOC_ARRAY_ADD_UNIQUE) {
        return PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_ADD_UNIQUE;
    } else {
        return 0xff;
    }
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdget3(lcb_t instance, const void *cookie, const lcb_CMDSDGET *cmd)
{
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        PROTOCOL_BINARY_CMD_SUBDOC_GET, SDTYPE_PLAIN);
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdexists3(lcb_t instance, const void *cookie, const lcb_CMDSDEXISTS *cmd)
{
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        PROTOCOL_BINARY_CMD_SUBDOC_EXISTS, SDTYPE_PLAIN);
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdremove3(lcb_t instance, const void *cookie, const lcb_CMDSDREMOVE *cmd)
{
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        PROTOCOL_BINARY_CMD_SUBDOC_DELETE, SDTYPE_PLAIN);
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdstore3(lcb_t instance, const void *cookie, const lcb_CMDSDSTORE *cmd)
{
    uint8_t op = sdmode_to_opcode(cmd->mode);
    if (op == 0xff) {
        return LCB_EINVAL;
    }
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        op, SDTYPE_STORE);
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdcounter3(lcb_t instance, const void *cookie, const lcb_CMDSDCOUNTER *cmd)
{
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        PROTOCOL_BINARY_CMD_SUBDOC_COUNTER, SDTYPE_COUNTER);
}
