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
#include <vector>
#include <string>
#include <include/libcouchbase/api3.h>

static lcb_size_t
get_value_size(mc_PACKET *packet)
{
    if (packet->flags & MCREQ_F_HASVALUE) {
        if (packet->flags & MCREQ_F_VALUE_IOV) {
            return packet->u_value.multi.total_length;
        } else {
            return packet->u_value.single.size;
        }
    } else {
        return 0;
    }
}

namespace SubdocCmdTraits {
enum Options {
    EMPTY_PATH = 1<<0,
    ALLOW_EXPIRY = 1<<1,
    HAS_VALUE = 1<<2,
    ALLOW_MKDIRP = 1<<3
};

struct Traits {
    const unsigned allow_empty_path;
    const unsigned allow_expiry;
    const unsigned has_value;
    const unsigned allow_mkdir_p;
    const uint8_t opcode;

    inline bool valid() const {
        return opcode != 0;
    }

    inline Traits(uint8_t op, unsigned options) :
        allow_empty_path(options & EMPTY_PATH),
        allow_expiry(options & ALLOW_EXPIRY),
        has_value(options & HAS_VALUE),
        allow_mkdir_p(options & ALLOW_MKDIRP),
        opcode(op) {}
};

static const Traits
Get(PROTOCOL_BINARY_CMD_SUBDOC_GET, 0);

static const Traits
Exists(PROTOCOL_BINARY_CMD_SUBDOC_EXISTS, 0);

static const Traits
DictAdd(PROTOCOL_BINARY_CMD_SUBDOC_DICT_ADD, ALLOW_EXPIRY|HAS_VALUE);

static const Traits
DictUpsert(PROTOCOL_BINARY_CMD_SUBDOC_DICT_UPSERT,
    ALLOW_EXPIRY|HAS_VALUE|ALLOW_MKDIRP);

static const Traits
Remove(PROTOCOL_BINARY_CMD_SUBDOC_DELETE, ALLOW_EXPIRY);

static const Traits
ArrayInsert(PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_INSERT,
    ALLOW_EXPIRY|HAS_VALUE);

static const Traits
Replace(PROTOCOL_BINARY_CMD_SUBDOC_REPLACE, ALLOW_EXPIRY|HAS_VALUE);

static const Traits
ArrayAddFirst(PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_FIRST,
    ALLOW_EXPIRY|HAS_VALUE|EMPTY_PATH|ALLOW_MKDIRP);

static const Traits
ArrayAddLast(PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_LAST,
    ALLOW_EXPIRY|HAS_VALUE|EMPTY_PATH|ALLOW_MKDIRP);

static const Traits
ArrayAddUnique(PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_ADD_UNIQUE,
    ALLOW_EXPIRY|HAS_VALUE|EMPTY_PATH|ALLOW_MKDIRP);

static const Traits
Counter(PROTOCOL_BINARY_CMD_SUBDOC_COUNTER, ALLOW_EXPIRY|HAS_VALUE|ALLOW_MKDIRP);

static const Traits
Invalid(0, 0);

const Traits&
find(unsigned mode)
{
    switch (mode) {
    case LCB_SUBDOC_REPLACE:
        return Replace;
    case LCB_SUBDOC_DICT_ADD:
        return DictAdd;
    case LCB_SUBDOC_DICT_UPSERT:
        return DictUpsert;
    case LCB_SUBDOC_ARRAY_ADD_FIRST:
        return ArrayAddFirst;
    case LCB_SUBDOC_ARRAY_ADD_LAST:
        return ArrayAddLast;
    case LCB_SUBDOC_ARRAY_ADD_UNIQUE:
        return ArrayAddUnique;
    case LCB_SUBDOC_ARRAY_INSERT:
        return ArrayInsert;
    case LCB_SUBDOC_GET:
        return Get;
    case LCB_SUBDOC_EXISTS:
        return Exists;
    case LCB_SUBDOC_REMOVE:
        return Remove;
    case LCB_SUBDOC_COUNTER:
        return Counter;
    default:
        return Invalid;
    }
}
}

static lcb_error_t
sd_packet_common(lcb_t instance, const void *cookie, const lcb_CMDSDBASE *cmd,
    bool has_value, protocol_binary_request_subdocument *request,
    mc_PACKET **packet_p, mc_PIPELINE **pipeline_p)
{
    lcb_error_t rc;
    mc_PIPELINE *pipeline = NULL;
    mc_PACKET *packet = NULL;
    mc_REQDATA *rdata = NULL;
    lcb_VALBUF valbuf = { LCB_KV_COPY };
    const lcb_VALBUF *valbuf_p = &valbuf;
    lcb_IOV tmpiov[2];

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

    if (has_value) {
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
          const SubdocCmdTraits::Traits& traits, bool has_value)
{
    mc_PACKET *packet;
    mc_PIPELINE *pipeline;
    lcb_error_t err;

    if (!cmd->npath && !traits.allow_empty_path) {
        return LCB_EINVAL;
    }

    protocol_binary_request_subdocument scmd;
    protocol_binary_request_header *hdr = &scmd.message.header;

    err = sd_packet_common(
            instance, cookie, cmd, has_value, &scmd, &packet, &pipeline);

    if (err != LCB_SUCCESS) {
        return err;
    }

    hdr->request.opcode = traits.opcode;
    memcpy(SPAN_BUFFER(&packet->kh_span), scmd.bytes, sizeof scmd.bytes);
    mcreq_sched_add(pipeline, packet);
    return LCB_SUCCESS;

}


LIBCOUCHBASE_API
lcb_error_t
lcb_sdget3(lcb_t instance, const void *cookie, const lcb_CMDSDGET *cmd)
{
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        SubdocCmdTraits::Get, false);
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdexists3(lcb_t instance, const void *cookie, const lcb_CMDSDEXISTS *cmd)
{
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        SubdocCmdTraits::Exists, false);
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdremove3(lcb_t instance, const void *cookie, const lcb_CMDSDREMOVE *cmd)
{
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd,
        SubdocCmdTraits::Remove, false);
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdstore3(lcb_t instance, const void *cookie, const lcb_CMDSDSTORE *cmd)
{
    const SubdocCmdTraits::Traits& trait = SubdocCmdTraits::find(cmd->mode);
    if (!trait.valid()) {
        return LCB_EINVAL;
    }
    return sd_common(instance, cookie, (const lcb_CMDSDBASE*)cmd, trait, true);
}

static lcb_error_t
counter_to_store(const lcb_CMDSDCOUNTER *counter, lcb_CMDSDSTORE *store, char buf[32])
{
    store->cmdflags = counter->cmdflags;
    store->key = counter->key;
    store->_hashkey = counter->_hashkey;
    store->exptime = counter->exptime;
    store->cas = counter->cas;
    store->mode = LCB_SUBDOC_COUNTER;
    store->path = counter->path;
    store->npath = counter->npath;

    size_t nbuf = sprintf(buf, "%lld", counter->delta);
    LCB_CMD_SET_VALUE(store, buf, nbuf);
    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdcounter3(lcb_t instance, const void *cookie, const lcb_CMDSDCOUNTER *cmd)
{
    lcb_CMDSDSTORE scmd = { 0 };
    char buf[32];
    lcb_error_t rc = counter_to_store(cmd, &scmd, buf);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    return lcb_sdstore3(instance, cookie, &scmd);
}

struct lcb_SDMULTICTX_st {
    lcb_t instance;
    int mode;
    mc_PACKET *pkt;
    mc_PIPELINE *pipeline;
    protocol_binary_request_header hdr;
    std::vector<char> extra_body;

    ~lcb_SDMULTICTX_st() {
        if (pkt != NULL) {
            mcreq_wipe_packet(pipeline, pkt);
            mcreq_release_packet(pipeline, pkt);
        }
    }

    template <typename T> void add_field(T itm, size_t len) {
        const char *b = reinterpret_cast<const char *>(&itm);
        extra_body.insert(extra_body.end(), b, b + len);
    }

    void add_buf(const void *bytes, size_t n) {
        const char *b = reinterpret_cast<const char*>(bytes);
        extra_body.insert(extra_body.end(), b, b + n);
    }

    inline lcb_error_t add_spec(const SubdocCmdTraits::Traits& trait,
        const lcb_CMDSDBASE *cmd, const lcb_VALBUF *vb = NULL);

    inline lcb_error_t addcmd(unsigned op, const lcb_CMDSDBASE *cmd);

    inline lcb_error_t done();
};

lcb_error_t
lcb_SDMULTICTX_st::add_spec(const SubdocCmdTraits::Traits& trait, const lcb_CMDSDBASE *cmd,
    const lcb_VALBUF *vb)
{
    // opcode
    add_field(trait.opcode, 1);

    // flags
    lcb_U8 sdflags = 0;
    if (cmd->cmdflags & LCB_CMDSUBDOC_F_MKINTERMEDIATES) {
        sdflags = SUBDOC_FLAG_MKDIR_P;
    }
    add_field(sdflags, 1);

    if (!cmd->npath && !trait.allow_empty_path) {
        return LCB_EMPTY_KEY;
    }

    // Path length
    add_field(static_cast<lcb_U16>(htons(cmd->npath)), 2);

    // Body length (if needed)
    if (vb != NULL) {
        if (vb->vtype != LCB_KV_COPY) {
            return LCB_EINVAL;
        }
        add_field(static_cast<lcb_U32>(htonl(vb->u_buf.contig.nbytes)), 4);
    }

    // Add the actual path

    // Add the body, if present
    if (cmd->npath) {
        add_buf(cmd->path, cmd->npath);
    }
    if (vb != NULL && vb->u_buf.contig.nbytes) {
        add_buf(vb->u_buf.contig.bytes, vb->u_buf.contig.nbytes);
    }
    return LCB_SUCCESS;
}

lcb_error_t
lcb_SDMULTICTX_st::addcmd(unsigned op, const lcb_CMDSDBASE *cmd)
{
    const SubdocCmdTraits::Traits& trait = SubdocCmdTraits::find(op);
    if (!trait.valid()) {
        return LCB_EINVAL;
    }

    // Add the opcode to the spec:
    if (op == LCB_SUBDOC_GET || op == LCB_SUBDOC_EXISTS) {
        if (mode != LCB_SDMULTI_MODE_LOOKUP) {
            return LCB_OPTIONS_CONFLICT;
        }
        return add_spec(trait, cmd);
    }

    if (mode != LCB_SDMULTI_MODE_MUTATE) {
        return LCB_OPTIONS_CONFLICT;
    }

    if (trait.opcode == LCB_SUBDOC_REMOVE) {
        return add_spec(trait, cmd);

    } else if (op == LCB_SUBDOC_COUNTER) {
        const lcb_CMDSDCOUNTER *ccmd = reinterpret_cast<const lcb_CMDSDCOUNTER*>(cmd);
        lcb_CMDSDSTORE scmd = { 0 };
        char buf[32];
        lcb_error_t rc = counter_to_store(ccmd, &scmd, buf);
        if (rc != LCB_SUCCESS) {
            return rc;
        }
        return add_spec(trait, cmd, &scmd.value);
    } else {
        const lcb_CMDSDSTORE *scmd = reinterpret_cast<const lcb_CMDSDSTORE*>(cmd);
        return add_spec(trait, cmd, &scmd->value);
    }
}

lcb_error_t
lcb_SDMULTICTX_st::done()
{
    if (extra_body.empty()) {
        delete this;
        return LCB_EINVAL;
    }

    lcb_VALBUF vb = { LCB_KV_COPY };
    vb.u_buf.contig.bytes = &extra_body[0];
    vb.u_buf.contig.nbytes = extra_body.size();

    lcb_error_t rc = mcreq_reserve_value(pipeline, pkt, &vb);
    if (rc != LCB_SUCCESS) {
        delete this;
        return rc;
    }

    // Get the body size
    hdr.request.bodylen = htonl(ntohs(hdr.request.keylen) + extra_body.size());
    memcpy(SPAN_BUFFER(&pkt->kh_span), hdr.bytes, sizeof hdr.bytes);
    mcreq_sched_add(pipeline, pkt);

    pkt = NULL;
    pipeline = NULL;
    delete this;

    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
lcb_SDMULTICTX *
lcb_sdmultictx_new(lcb_t instance, const void *cookie,
    const lcb_CMDSDMULTI *cmd, lcb_error_t *err)
{
    *err = LCB_SUCCESS;
    lcb_SDMULTICTX *ctx = NULL;
    lcb_U8 opcode;

    if (!cmd->key.contig.nbytes) {
        *err = LCB_EMPTY_KEY;
        return NULL;
    }
    if (cmd->multimode == LCB_SDMULTI_MODE_LOOKUP) {
        opcode = PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP;
    } else if (cmd->multimode == LCB_SDMULTI_MODE_MUTATE) {
        opcode = PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION;
    } else {
        *err = LCB_EINVAL;
        return NULL;
    }

    ctx = new lcb_SDMULTICTX();
    ctx->instance = instance;
    ctx->mode = cmd->multimode;

    *err = mcreq_basic_packet(&instance->cmdq,
        reinterpret_cast<const lcb_CMDBASE*>(cmd), &ctx->hdr, 0,
        &ctx->pkt, &ctx->pipeline, MCREQ_BASICPACKET_F_FALLBACKOK);

    if (*err != LCB_SUCCESS) {
        delete ctx;
        return NULL;
    }

    ctx->hdr.request.magic = PROTOCOL_BINARY_REQ;
    ctx->hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    ctx->hdr.request.extlen = ctx->pkt->extlen;
    ctx->hdr.request.opaque = ctx->pkt->opaque;
    ctx->hdr.request.cas = cmd->cas;
    ctx->hdr.request.opcode = opcode;

    MCREQ_PKT_RDATA(ctx->pkt)->cookie = cookie;

    return ctx;
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdmultictx_addcmd(lcb_SDMULTICTX *ctx, unsigned op, const lcb_CMDSDBASE *cmd)
{
    return ctx->addcmd(op, cmd);
}

LIBCOUCHBASE_API
lcb_error_t
lcb_sdmultictx_done(lcb_SDMULTICTX *ctx)
{
    return ctx->done();
}

LIBCOUCHBASE_API
void
lcb_sdmultictx_fail(lcb_SDMULTICTX *ctx)
{
    delete ctx;
}
