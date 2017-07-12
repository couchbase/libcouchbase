/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014 Couchbase, Inc.
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
#include "packetutils.h"
#include "mc/mcreq.h"
#include "mc/compress.h"
#include "trace.h"

#define LOGARGS(obj, lvl) (obj)->settings, "handler", LCB_LOG_##lvl, __FILE__, __LINE__

using lcb::MemcachedResponse;

template <typename T>
class ResponsePack {
public:
    T resp;
    lcb_MUTATION_TOKEN mt;
    const char *value;
    lcb_SIZE nvalue;
    char *err_ref;
    char *err_ctx;

    ~ResponsePack() {
        free(err_ref);
        free(err_ctx);
    }

    static const lcb_MUTATION_TOKEN*
    get_mt(const lcb_RESPBASE *rb) {
        const ResponsePack *rp = reinterpret_cast<const ResponsePack*>(rb);
        return &rp->mt;
    }

    static const char*
    get_err_ctx(const lcb_RESPBASE *rb) {
        const ResponsePack *rp = reinterpret_cast<const ResponsePack*>(rb);
        if (rp->resp.rflags & LCB_RESP_F_ERRINFO) {
            if (rp->err_ctx) {
                return rp->err_ctx;
            } else {
                parse_enhanced_error(rp);
                return rp->err_ctx;
            }
        }
        return NULL;
    }

    static const char*
    get_err_ref(const lcb_RESPBASE *rb) {
        const ResponsePack *rp = reinterpret_cast<const ResponsePack*>(rb);
        if (rp->resp.rflags & LCB_RESP_F_ERRINFO) {
            if (rp->err_ref) {
                return rp->err_ref;
            } else {
                parse_enhanced_error(rp);
                return rp->err_ref;
            }
        }
        return NULL;
    }

 private:

    static void
    parse_enhanced_error(const ResponsePack *rp) {
        ResponsePack *mrp = const_cast<ResponsePack *>(rp);
        lcb_error_t rc = MemcachedResponse::parse_enhanced_error(mrp->value, mrp->nvalue, &mrp->err_ref, &mrp->err_ctx);
        if (rc != LCB_SUCCESS) {
            mrp->resp.rflags &= ~LCB_RESP_F_ERRINFO;
        }
    }
};

LIBCOUCHBASE_API
lcb_error_t
lcb_errmap_default(lcb_t instance, lcb_uint16_t in)
{
    switch (in) {
    case PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET:
        return LCB_ETIMEDOUT;
    case PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE:
        return LCB_AUTH_CONTINUE;
    case PROTOCOL_BINARY_RESPONSE_EBUSY:
        return LCB_EBUSY;
    case PROTOCOL_BINARY_RESPONSE_ETMPFAIL:
        return LCB_ETMPFAIL;

    case PROTOCOL_BINARY_RESPONSE_EINTERNAL:
    default:
        if (instance) {
            lcb_log(LOGARGS(instance, ERROR), "Got unhandled memcached error 0x%X", in);
        } else {
            fprintf(stderr, "COUCHBASE: Unhandled memcached status=0x%x\n", in);
        }
        return LCB_UNKNOWN_MEMCACHED_ERROR;
    }
}

static lcb_error_t
map_error(lcb_t instance, int in)
{
    switch (in) {
    case PROTOCOL_BINARY_RESPONSE_SUCCESS:
        return LCB_SUCCESS;
    case PROTOCOL_BINARY_RESPONSE_KEY_ENOENT:
        return LCB_KEY_ENOENT;
    case PROTOCOL_BINARY_RESPONSE_E2BIG:
        return LCB_E2BIG;
    case PROTOCOL_BINARY_RESPONSE_ENOMEM:
        return LCB_ENOMEM;
    case PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS:
        return LCB_KEY_EEXISTS;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_ENOENT:
        return LCB_SUBDOC_PATH_ENOENT;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_MISMATCH:
        return LCB_SUBDOC_PATH_MISMATCH;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_EINVAL:
        return LCB_SUBDOC_PATH_EINVAL;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_E2BIG:
        return LCB_SUBDOC_PATH_E2BIG;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_DOC_E2DEEP:
        return LCB_SUBDOC_DOC_E2DEEP;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_VALUE_ETOODEEP:
        return LCB_SUBDOC_VALUE_E2DEEP;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_VALUE_CANTINSERT:
        return LCB_SUBDOC_VALUE_CANTINSERT;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_DOC_NOTJSON:
        return LCB_SUBDOC_DOC_NOTJSON;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_NUM_ERANGE:
        return LCB_SUBDOC_NUM_ERANGE;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_DELTA_ERANGE:
        return LCB_SUBDOC_BAD_DELTA;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_PATH_EEXISTS:
        return LCB_SUBDOC_PATH_EEXISTS;
    case PROTOCOL_BINARY_RESPONSE_SUBDOC_MULTI_PATH_FAILURE:
        return LCB_SUBDOC_MULTI_FAILURE;
    case PROTOCOL_BINARY_RESPONSE_EINVAL:
        return LCB_EINVAL_MCD;
    case PROTOCOL_BINARY_RESPONSE_NOT_STORED:
        return LCB_NOT_STORED;
    case PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL:
        return LCB_DELTA_BADVAL;
    case PROTOCOL_BINARY_RESPONSE_AUTH_ERROR:
        return LCB_AUTH_ERROR;
    case PROTOCOL_BINARY_RESPONSE_ERANGE:
        return LCB_ERANGE;
    case PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND:
        return LCB_UNKNOWN_COMMAND;
    case PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED:
        return LCB_NOT_SUPPORTED;
    case PROTOCOL_BINARY_RESPONSE_EACCESS:
        return LCB_NOT_AUTHORIZED;
    default:
        if (instance != NULL) {
            return instance->callbacks.errmap(instance, in);
        } else {
            return lcb_errmap_default(NULL, in);
        }
    }
}

static lcb_RESPCALLBACK
find_callback(lcb_t instance, lcb_CALLBACKTYPE type)
{
    lcb_RESPCALLBACK cb = instance->callbacks.v3callbacks[type];
    if (!cb) {
        cb = lcb_find_callback(instance, type);
    }
    return cb;
}


/**
 * This file contains the mapping of various protocol response codes for
 * a given command. Each handler receives the following parameters:
 *
 * @param pipeline the pipeline (or "Server") upon which the request was sent
 * (and response was received)
 *
 * @param request the original request (including associated data). The request
 *  may be used to determine additional information about it, such as the
 *  user-defined "Cookie", number of related requests remaining, and more.
 *
 * @param response the response which was received. This is an opaque
 *  representation of a memcached response packet
 *
 * @param immerr in the case of an abnormal failure (i.e. network failure) the
 *  handler will be invoked with this callback set to a non-success value. The
 *  'info' structure will still contain a valid (albeit empty and cryptic)
 *  header. If the user depends on special data being found in the payload then
 *  the handler must check that this variable is set to LCB_SUCCESS before
 *  continuing. Also note that a negative reply may also be present within
 *  the response itself; however this is not the purpose of this parameter.
 *
 * @return request status
 *  The return value should indicate whether outstanding responses remain
 *  to be received for this request, or if this request is deemed to be
 *  satisfied.
 */

template <typename T>
void make_error(lcb_t instance, T* resp,
                const MemcachedResponse *response, lcb_error_t imm) {
    if (imm) {
        resp->rc = imm;
        resp->rflags |= LCB_RESP_F_CLIENTGEN;
    } else if (response->status() == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        resp->rc = LCB_SUCCESS;
    } else {
        resp->rc = map_error(instance, response->status());
    }
}

template <typename T>
void handle_error_info(const MemcachedResponse* mc_resp, ResponsePack<T>* rp)
{
    if (mc_resp->status() != PROTOCOL_BINARY_RESPONSE_SUCCESS
        && mc_resp->datatype() & PROTOCOL_BINARY_DATATYPE_JSON
        && mc_resp->vallen() > 0) {
        rp->resp.rflags |= LCB_RESP_F_ERRINFO;
        rp->value = mc_resp->value();
        rp->nvalue = mc_resp->vallen();
    }
}

template <typename T>
void init_resp(lcb_t instance, const MemcachedResponse* mc_resp,
               const mc_PACKET *req, lcb_error_t immerr, T *resp) {
    make_error(instance, resp, mc_resp, immerr);
    resp->cas = mc_resp->cas();
    resp->cookie = const_cast<void*>(MCREQ_PKT_COOKIE(req));
    mcreq_get_key(req, &resp->key, &resp->nkey);
}

/**
 * Handles the propagation and population of the 'mutation token' information.
 * @param mc_resp The response packet
 * @param req The request packet (used to get the vBucket)
 * @param tgt Pointer to mutation token which should be populated.
 */
static void
handle_mutation_token(lcb_t instance, const MemcachedResponse *mc_resp,
    const mc_PACKET *req, lcb_MUTATION_TOKEN *stok)
{
    const char *sbuf;
    uint16_t vbid;
    if (mc_resp->extlen() == 0) {
        return; /* No extras */
    }

    if (!instance->dcpinfo && LCBT_SETTING(instance, dur_mutation_tokens)) {
        size_t nvb = LCBT_VBCONFIG(instance)->nvb;
        if (nvb) {
            instance->dcpinfo = new lcb_MUTATION_TOKEN[nvb];
            memset(instance->dcpinfo, 0, sizeof(*instance->dcpinfo) * nvb);
        }
    }

    sbuf = mc_resp->body<const char*>();
    vbid = mcreq_get_vbucket(req);
    stok->vbid_ = vbid;
    memcpy(&stok->uuid_, sbuf, 8);
    memcpy(&stok->seqno_, sbuf + 8, 8);

    stok->uuid_ = lcb_ntohll(stok->uuid_);
    stok->seqno_ = lcb_ntohll(stok->seqno_);

    if (instance->dcpinfo) {
        instance->dcpinfo[vbid] = *stok;
    }
}

static lcb_t get_instance(mc_PIPELINE *pipeline) {
    return reinterpret_cast<lcb_t>(pipeline->parent->cqdata);
}

template <typename T>
void invoke_callback(const mc_PACKET *pkt,
    lcb_t instance, T* resp, lcb_CALLBACKTYPE cbtype)
{
    if (!(pkt->flags & MCREQ_F_INVOKED)) {
        resp->cookie = const_cast<void*>(MCREQ_PKT_COOKIE(pkt));
        const lcb_RESPBASE *base = reinterpret_cast<const lcb_RESPBASE*>(resp);
        if ((pkt->flags & MCREQ_F_PRIVCALLBACK) == 0) {
            find_callback(instance, cbtype)(instance, cbtype, base);
        } else {
            (*(lcb_RESPCALLBACK*)resp->cookie)(instance, cbtype, base);
        }
    }
}

template <typename T>
void invoke_callback(const mc_PACKET *pkt, mc_PIPELINE *pipeline, T *resp,
    lcb_CALLBACKTYPE cbtype)
{
    invoke_callback(pkt, get_instance(pipeline), cbtype, resp);
}

/**
 * Optionally decompress an incoming payload.
 * @param o The instance
 * @param resp The response received
 * @param[out] bytes pointer to the final payload
 * @param[out] nbytes pointer to the size of the final payload
 * @param[out] freeptr pointer to free. This should be initialized to `NULL`.
 * If temporary dynamic storage is required this will be set to the allocated
 * pointer upon return. Otherwise it will be set to NULL. In any case it must
 */
static void
maybe_decompress(lcb_t o,
    const MemcachedResponse* respkt, lcb_RESPGET *rescmd, void **freeptr)
{
    lcb_U8 dtype = 0;
    if (!respkt->vallen()) {
        return;
    }

    if (respkt->datatype() & PROTOCOL_BINARY_DATATYPE_JSON) {
        dtype = LCB_VALUE_F_JSON;
    }

    if (respkt->datatype() & PROTOCOL_BINARY_DATATYPE_COMPRESSED) {
        if (LCBT_SETTING(o, compressopts) & LCB_COMPRESS_IN) {
            /* if we inflate, we don't set the flag */
            mcreq_inflate_value(
                respkt->value(), respkt->vallen(),
                &rescmd->value, &rescmd->nvalue, freeptr);

        } else {
            /* user doesn't want inflation. signal it's compressed */
            dtype |= LCB_VALUE_F_SNAPPYCOMP;
        }
    }
    rescmd->datatype = dtype;
}

static void
H_get(mc_PIPELINE *pipeline, mc_PACKET *request, MemcachedResponse* response,
      lcb_error_t immerr)
{
    ResponsePack<lcb_RESPGET> w = {{ 0 }};
    lcb_RESPGET& resp = w.resp;

    lcb_t o = get_instance(pipeline);
    init_resp(o, response, request, immerr, &resp);
    handle_error_info(response, &w);
    resp.rflags |= LCB_RESP_F_FINAL;

    if (resp.rc == LCB_SUCCESS) {
        const protocol_binary_response_get *get =
                reinterpret_cast<const protocol_binary_response_get*>(
                        response->ephemeral_start());
        resp.datatype = response->datatype();
        resp.itmflags = ntohl(get->message.body.flags);
        resp.value = response->value();
        resp.nvalue = response->vallen();
        resp.bufh = response->bufseg();
    }

    void *freeptr = NULL;
    maybe_decompress(o, response, &resp, &freeptr);
    TRACE_GET_END(response, &resp);
    invoke_callback(request, o, &resp, LCB_CALLBACK_GET);
    free(freeptr);
}

static void
H_getreplica(mc_PIPELINE *pipeline, mc_PACKET *request,
             MemcachedResponse *response, lcb_error_t immerr)
{
    ResponsePack<lcb_RESPGET> w = {{ 0 }};
    lcb_RESPGET& resp = w.resp;
    lcb_t instance = get_instance(pipeline);
    void *freeptr = NULL;
    mc_REQDATAEX *rd = request->u_rdata.exdata;

    init_resp(instance, response, request, immerr, &resp);
    handle_error_info(response, &w);

    if (resp.rc == LCB_SUCCESS) {
        const protocol_binary_response_get *get =
                reinterpret_cast<const protocol_binary_response_get*>(
                        response->ephemeral_start());
        resp.itmflags = ntohl(get->message.body.flags);
        resp.datatype = response->datatype();
        resp.value = response->value();
        resp.nvalue = response->vallen();
        resp.bufh = response->bufseg();
    }

    maybe_decompress(instance, response, &resp, &freeptr);
    rd->procs->handler(pipeline, request, resp.rc, &resp);
    free(freeptr);
}

static void
H_subdoc(mc_PIPELINE *pipeline, mc_PACKET *request,
         MemcachedResponse *response, lcb_error_t immerr)
{
    lcb_t o = get_instance(pipeline);
    ResponsePack<lcb_RESPSUBDOC> w = {{ 0 }};
    lcb_CALLBACKTYPE cbtype;
    init_resp(o, response, request, immerr, &w.resp);
    w.resp.rflags |= LCB_RESP_F_FINAL;

    /* For mutations, add the mutation token */
    switch (response->opcode()) {
    case PROTOCOL_BINARY_CMD_SUBDOC_GET:
    case PROTOCOL_BINARY_CMD_SUBDOC_EXISTS:
    case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP:
        cbtype = LCB_CALLBACK_SDLOOKUP;
        break;

    default:
        handle_mutation_token(o, response, request, &w.mt);
        w.resp.rflags |= LCB_RESP_F_EXTDATA;
        cbtype = LCB_CALLBACK_SDMUTATE;
        break;
    }

    if (response->opcode() == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP ||
            response->opcode() == PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION) {
        if (w.resp.rc == LCB_SUCCESS || w.resp.rc == LCB_SUBDOC_MULTI_FAILURE) {
            w.resp.responses = response;
        }
    } else {
        /* Single response */
        w.resp.rflags |= LCB_RESP_F_SDSINGLE;
        if (w.resp.rc == LCB_SUCCESS) {
            w.resp.responses = response;
        } else if (LCB_EIFSUBDOC(w.resp.rc)) {
            w.resp.responses = response;
            w.resp.rc = LCB_SUBDOC_MULTI_FAILURE;
        }
    }
    invoke_callback(request, o, &w.resp, cbtype);
}

static int
sdlookup_next(const MemcachedResponse *response, lcb_SDENTRY *ent, size_t *iter)
{
    const char *buf;
    uint16_t rc;
    uint32_t vlen;

    if (*iter == response->vallen()) {
        return 0;
    }

    buf = response->value();
    buf += *iter;

    memcpy(&rc, buf, 2);
    memcpy(&vlen, buf + 2, 4);

    rc = ntohs(rc);
    vlen = ntohl(vlen);

    ent->status = map_error(NULL, rc);
    ent->nvalue = vlen;

    if (ent->status == LCB_SUCCESS) {
        ent->value = buf + 6;
    } else {
        ent->value = NULL;
        ent->nvalue = 0;
    }

    *iter += (6 + vlen);
    return 1;
}

static int
sdmutate_next(const MemcachedResponse *response, lcb_SDENTRY *ent, size_t *iter)
{
    const char *buf, *buf_end;
    uint16_t rc;
    uint32_t vlen;

    if (*iter == response->vallen()) {
        return 0;
    }

    buf_end = (const char *)response->value() + response->vallen();
    buf = ((const char *)(response->value())) + *iter;

    #define ADVANCE_BUF(sz) \
        buf += sz; \
        *iter += sz; \
        assert(buf <= buf_end); \

    /* Index */
    ent->index = *(lcb_U8*)buf;
    ADVANCE_BUF(1);

    /* Status */
    memcpy(&rc, buf, 2);
    ADVANCE_BUF(2);

    rc = ntohs(rc);
    ent->status = map_error(NULL, rc);

    if (rc == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        memcpy(&vlen, buf, 4);
        ADVANCE_BUF(4);

        vlen = ntohl(vlen);
        ent->nvalue = vlen;
        ent->value = buf;
        ADVANCE_BUF(vlen);

    } else {
        ent->value = NULL;
        ent->nvalue = 0;
    }

    return 1;
    #undef ADVANCE_BUF
}

LIBCOUCHBASE_API
int
lcb_sdresult_next(const lcb_RESPSUBDOC *resp, lcb_SDENTRY *ent, size_t *iter)
{
    size_t iter_s = 0;
    const MemcachedResponse *response =
                reinterpret_cast<const MemcachedResponse*>(resp->responses);
    if (!response) {
        return 0;
    }
    if (!iter) {
        /* Single response */
        iter = &iter_s;
    }

    switch (response->opcode()) {
    case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP:
        return sdlookup_next(response, ent, iter);
    case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION:
        return sdmutate_next(response, ent, iter);
    default:
        if (*iter) {
            return 0;
        }
        *iter = 1;

        if (resp->rc == LCB_SUCCESS || resp->rc == LCB_SUBDOC_MULTI_FAILURE) {
            ent->status = map_error(NULL, response->status());
            ent->value = response->value();
            ent->nvalue = response->vallen();
            ent->index = 0;
            return 1;
        } else {
            return 0;
        }
    }
}

static void
H_delete(mc_PIPELINE *pipeline, mc_PACKET *packet, MemcachedResponse *response,
         lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    ResponsePack<lcb_RESPREMOVE> w = { { 0 } };
    w.resp.rflags |= LCB_RESP_F_EXTDATA | LCB_RESP_F_FINAL;
    init_resp(root, response, packet, immerr, &w.resp);
    handle_error_info(response, &w);
    handle_mutation_token(root, response, packet, &w.mt);
    TRACE_REMOVE_END(response, &w.resp);
    invoke_callback(packet, root, &w.resp, LCB_CALLBACK_REMOVE);
}

static void
H_observe(mc_PIPELINE *pipeline, mc_PACKET *request, MemcachedResponse *response,
          lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    uint32_t ttp;
    uint32_t ttr;
    size_t pos;
    lcbvb_CONFIG* config;
    const char *end, *ptr;
    mc_REQDATAEX *rd = request->u_rdata.exdata;
    lcb_RESPOBSERVE resp = { 0 };
    make_error(root, &resp, response, immerr);

    if (resp.rc != LCB_SUCCESS) {
        if (! (request->flags & MCREQ_F_INVOKED)) {
            rd->procs->handler(pipeline, request, resp.rc, NULL);
        }
        return;
    }

    /** The CAS field is split into TTP/TTR values */
    uint64_t tmpcas = lcb_htonll(response->cas());
    ptr = reinterpret_cast<char*>(&tmpcas);
    memcpy(&ttp, ptr, sizeof(ttp));
    memcpy(&ttr, ptr + sizeof(ttp), sizeof(ttp));

    ttp = ntohl(ttp);
    ttr = ntohl(ttr);

    /** Actual payload sequence of (vb, nkey, key). Repeats multiple times */
    ptr = response->body<const char *>();
    end = ptr + response->bodylen();
    config = pipeline->parent->config;

    for (pos = 0; ptr < end; pos++) {
        uint64_t cas;
        uint8_t obs;
        uint16_t nkey, vb;
        const char *key;

        memcpy(&vb, ptr, sizeof(vb));
        vb = ntohs(vb);
        ptr += sizeof(vb);
        memcpy(&nkey, ptr, sizeof(nkey));
        nkey = ntohs(nkey);
        ptr += sizeof(nkey);
        key = (const char *)ptr;
        ptr += nkey;
        obs = *((lcb_uint8_t *)ptr);
        ptr += sizeof(obs);
        memcpy(&cas, ptr, sizeof(cas));
        ptr += sizeof(cas);

        resp.key = key;
        resp.nkey = nkey;
        resp.cas = lcb_ntohll(cas);
        resp.status = obs;
        resp.ismaster = pipeline->index == lcbvb_vbmaster(config, vb);
        resp.ttp = 0;
        resp.ttr = 0;
        TRACE_OBSERVE_PROGRESS(response, &resp);
        if (! (request->flags & MCREQ_F_INVOKED)) {
            rd->procs->handler(pipeline, request, resp.rc, &resp);
        }
    }
    TRACE_OBSERVE_END(response);
}

static void
H_observe_seqno(mc_PIPELINE *pipeline, mc_PACKET *request,
                MemcachedResponse *response, lcb_error_t immerr) {
    lcb_t root = get_instance(pipeline);
    lcb_RESPOBSEQNO resp = { 0 };
    init_resp(root, response, request, immerr, &resp);

    resp.server_index = pipeline->index;

    if (resp.rc == LCB_SUCCESS) {
        const uint8_t *data = response->body<const uint8_t*>();
        bool is_failover = *data != 0;

        data++;
        #define COPY_ADV(dstfld, n, conv_fn) \
                memcpy(&resp.dstfld, data, n); \
                data += n; \
                resp.dstfld = conv_fn(resp.dstfld);

        COPY_ADV(vbid, 2, ntohs);
        COPY_ADV(cur_uuid, 8, lcb_ntohll);
        COPY_ADV(persisted_seqno, 8, lcb_ntohll);
        COPY_ADV(mem_seqno, 8, lcb_ntohll);
        if (is_failover) {
            COPY_ADV(old_uuid, 8, lcb_ntohll);
            COPY_ADV(old_seqno, 8, lcb_ntohll);
        }
        #undef COPY_ADV

        /* Get the server for this command. Note that since this is a successful
         * operation, the server is never a dummy */
    }
    invoke_callback(request, root, &resp, LCB_CALLBACK_OBSEQNO);
}

static void
H_store(mc_PIPELINE *pipeline, mc_PACKET *request, MemcachedResponse *response,
        lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    ResponsePack<lcb_RESPSTORE> w = { { 0 } };
    uint8_t opcode;
    init_resp(root, response, request, immerr, &w.resp);
    handle_error_info(response, &w);
    if (!immerr) {
        opcode = response->opcode();
    } else {
        protocol_binary_request_header hdr;
        mcreq_read_hdr(request, &hdr);
        opcode = hdr.request.opcode;
    }
    if (opcode == PROTOCOL_BINARY_CMD_ADD) {
        w.resp.op = LCB_ADD;
    } else if (opcode == PROTOCOL_BINARY_CMD_REPLACE) {
        w.resp.op = LCB_REPLACE;
    } else if (opcode == PROTOCOL_BINARY_CMD_APPEND) {
        w.resp.op = LCB_APPEND;
    } else if (opcode == PROTOCOL_BINARY_CMD_PREPEND) {
        w.resp.op = LCB_PREPEND;
    } else if (opcode == PROTOCOL_BINARY_CMD_SET) {
        w.resp.op = LCB_SET;
    }
    w.resp.rflags |= LCB_RESP_F_EXTDATA | LCB_RESP_F_FINAL;
    handle_mutation_token(root, response, request, &w.mt);
    TRACE_STORE_END(response, &w.resp);
    if (request->flags & MCREQ_F_REQEXT) {
        request->u_rdata.exdata->procs->handler(pipeline, request, immerr, &w.resp);
    } else {
        invoke_callback(request, root, &w.resp, LCB_CALLBACK_STORE);
    }
}

static void
H_arithmetic(mc_PIPELINE *pipeline, mc_PACKET *request,
             MemcachedResponse *response, lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    ResponsePack<lcb_RESPCOUNTER> w = { { 0 } };
    init_resp(root, response, request, immerr, &w.resp);

    if (w.resp.rc == LCB_SUCCESS) {
        memcpy(&w.resp.value, response->value(), sizeof(w.resp.value));
        w.resp.value = lcb_ntohll(w.resp.value);
        w.resp.rflags |= LCB_RESP_F_EXTDATA;
        handle_mutation_token(root, response, request, &w.mt);
    } else {
        handle_error_info(response, &w);
    }
    w.resp.rflags |= LCB_RESP_F_FINAL;
    w.resp.cas = response->cas();
    TRACE_ARITHMETIC_END(response, &w.resp);
    invoke_callback(request, root, &w.resp, LCB_CALLBACK_COUNTER);
}

static void
H_stats(mc_PIPELINE *pipeline, mc_PACKET *request,
        MemcachedResponse *response, lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    lcb_RESPSTATS resp = { 0 };
    mc_REQDATAEX *exdata;

    make_error(root, &resp, response, immerr);
    resp.version = 0;

    exdata = request->u_rdata.exdata;
    if (resp.rc != LCB_SUCCESS || response->keylen() == 0) {
        /* Call the handler without a response, this indicates that this server
         * has finished responding */
        exdata->procs->handler(pipeline, request, resp.rc, NULL);
        return;
    }

    if ((resp.nkey = response->keylen())) {
        resp.key = response->key();
        if ((resp.value = response->value())) {
            resp.nvalue = response->vallen();
        }
    }

    exdata->procs->handler(pipeline, request, resp.rc, &resp);
}

static void
H_verbosity(mc_PIPELINE *pipeline, mc_PACKET *request,
            MemcachedResponse *response, lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    lcb_RESPBASE dummy = { 0 };
    mc_REQDATAEX *exdata = request->u_rdata.exdata;
    make_error(root, &dummy, response, immerr);

    exdata->procs->handler(pipeline, request, dummy.rc, NULL);
}

static void
H_version(mc_PIPELINE *pipeline, mc_PACKET *request,
          MemcachedResponse *response, lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    lcb_RESPMCVERSION resp = { 0 };
    mc_REQDATAEX *exdata = request->u_rdata.exdata;

    make_error(root, &resp, response, immerr);

    if (response->bodylen()) {
        resp.mcversion = response->body<const char *>();
        resp.nversion = response->bodylen();
    }


    exdata->procs->handler(pipeline, request, resp.rc, &resp);
}

static void
H_touch(mc_PIPELINE *pipeline, mc_PACKET *request, MemcachedResponse *response,
        lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    ResponsePack<lcb_RESPTOUCH> w = {{ 0 }};
    lcb_RESPTOUCH& resp = w.resp;
    init_resp(root, response, request, immerr, &resp);
    handle_error_info(response, &w);
    resp.rflags |= LCB_RESP_F_FINAL;
    TRACE_TOUCH_END(response, &resp);
    invoke_callback(request, root, &resp, LCB_CALLBACK_TOUCH);
}

static void
H_flush(mc_PIPELINE *pipeline, mc_PACKET *request, MemcachedResponse *response,
        lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    lcb_RESPFLUSH resp = { 0 };
    mc_REQDATAEX *exdata = request->u_rdata.exdata;
    make_error(root, &resp, response, immerr);
    exdata->procs->handler(pipeline, request, resp.rc, &resp);
}

static void
H_unlock(mc_PIPELINE *pipeline, mc_PACKET *request, MemcachedResponse *response,
         lcb_error_t immerr)
{
    lcb_t root = get_instance(pipeline);
    ResponsePack<lcb_RESPUNLOCK> w = {{ 0 }};
    lcb_RESPUNLOCK& resp = w.resp;
    init_resp(root, response, request, immerr, &resp);
    handle_error_info(response, &w);
    resp.rflags |= LCB_RESP_F_FINAL;
    TRACE_UNLOCK_END(response, &resp);
    invoke_callback(request, root, &resp, LCB_CALLBACK_UNLOCK);
}

static void
H_config(mc_PIPELINE *pipeline, mc_PACKET *request, MemcachedResponse *response,
         lcb_error_t immerr)
{
    /** We just jump to the normal config handler */
    lcb_RESPBASE dummy;
    mc_REQDATAEX *exdata = request->u_rdata.exdata;
    make_error(get_instance(pipeline), &dummy, response, immerr);

    exdata->procs->handler(pipeline, request, dummy.rc, response);
}

static void
record_metrics(mc_PIPELINE *pipeline, mc_PACKET *req, MemcachedResponse *)
{
    lcb_t instance = get_instance(pipeline);
    if (instance->kv_timings) {
        lcb_histogram_record(instance->kv_timings,
            gethrtime() - MCREQ_PKT_RDATA(req)->start);
    }
}

static void
dispatch_ufwd_error(mc_PIPELINE *pipeline, mc_PACKET *req, lcb_error_t immerr)
{
    lcb_PKTFWDRESP resp = { 0 };
    lcb_t instance = static_cast<lcb::Server*>(pipeline)->get_instance();
    assert(immerr != LCB_SUCCESS);
    resp.version = 0;
    instance->callbacks.pktfwd(instance, MCREQ_PKT_COOKIE(req), immerr, &resp);
}

int
mcreq_dispatch_response(
        mc_PIPELINE *pipeline, mc_PACKET *req, MemcachedResponse *res,
        lcb_error_t immerr)
{
    record_metrics(pipeline, req, res);

    if (req->flags & MCREQ_F_UFWD) {
        dispatch_ufwd_error(pipeline, req, immerr);
        return 0;
    }


#define INVOKE_OP(handler) \
    handler(pipeline, req, res, immerr); \
    return 0; \
    break;

    switch (res->opcode()) {
    case PROTOCOL_BINARY_CMD_GET:
    case PROTOCOL_BINARY_CMD_GAT:
    case PROTOCOL_BINARY_CMD_GET_LOCKED:
        INVOKE_OP(H_get);

    case PROTOCOL_BINARY_CMD_ADD:
    case PROTOCOL_BINARY_CMD_REPLACE:
    case PROTOCOL_BINARY_CMD_SET:
    case PROTOCOL_BINARY_CMD_APPEND:
    case PROTOCOL_BINARY_CMD_PREPEND:
        INVOKE_OP(H_store);

    case PROTOCOL_BINARY_CMD_INCREMENT:
    case PROTOCOL_BINARY_CMD_DECREMENT:
        INVOKE_OP(H_arithmetic);

    case PROTOCOL_BINARY_CMD_SUBDOC_GET:
    case PROTOCOL_BINARY_CMD_SUBDOC_EXISTS:
    case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_ADD_UNIQUE:
    case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_FIRST:
    case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_PUSH_LAST:
    case PROTOCOL_BINARY_CMD_SUBDOC_ARRAY_INSERT:
    case PROTOCOL_BINARY_CMD_SUBDOC_DICT_ADD:
    case PROTOCOL_BINARY_CMD_SUBDOC_DICT_UPSERT:
    case PROTOCOL_BINARY_CMD_SUBDOC_REPLACE:
    case PROTOCOL_BINARY_CMD_SUBDOC_DELETE:
    case PROTOCOL_BINARY_CMD_SUBDOC_COUNTER:
    case PROTOCOL_BINARY_CMD_SUBDOC_GET_COUNT:
    case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_LOOKUP:
    case PROTOCOL_BINARY_CMD_SUBDOC_MULTI_MUTATION:
        INVOKE_OP(H_subdoc);

    case PROTOCOL_BINARY_CMD_OBSERVE:
        INVOKE_OP(H_observe);

    case PROTOCOL_BINARY_CMD_GET_REPLICA:
        INVOKE_OP(H_getreplica);

    case PROTOCOL_BINARY_CMD_UNLOCK_KEY:
        INVOKE_OP(H_unlock);

    case PROTOCOL_BINARY_CMD_DELETE:
        INVOKE_OP(H_delete);

    case PROTOCOL_BINARY_CMD_TOUCH:
        INVOKE_OP(H_touch);

    case PROTOCOL_BINARY_CMD_OBSERVE_SEQNO:
        INVOKE_OP(H_observe_seqno);

    case PROTOCOL_BINARY_CMD_STAT:
        INVOKE_OP(H_stats);

    case PROTOCOL_BINARY_CMD_FLUSH:
        INVOKE_OP(H_flush);

    case PROTOCOL_BINARY_CMD_VERSION:
        INVOKE_OP(H_version);

    case PROTOCOL_BINARY_CMD_VERBOSITY:
        INVOKE_OP(H_verbosity);

#if 0
    case PROTOCOL_BINARY_CMD_NOOP:
        INVOKE_OP(H_noop);
#endif

    case PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG:
        INVOKE_OP(H_config);

    default:
        fprintf(stderr, "COUCHBASE: Received unknown opcode=0x%x\n", res->opcode());
        return -1;
    }
}

const lcb_MUTATION_TOKEN *
lcb_resp_get_mutation_token(int cbtype, const lcb_RESPBASE *rb)
{
    const lcb_MUTATION_TOKEN *ss = NULL;
    if ((rb->rflags & LCB_RESP_F_EXTDATA) == 0) {
        return NULL;
    }

    switch (cbtype) {
    case LCB_CALLBACK_STORE:
        ss = ResponsePack<lcb_RESPSTORE>::get_mt(rb);
        break;

    case LCB_CALLBACK_COUNTER:
        ss = ResponsePack<lcb_RESPCOUNTER>::get_mt(rb);
        break;

    case LCB_CALLBACK_REMOVE:
        ss = ResponsePack<lcb_RESPREMOVE>::get_mt(rb);
        break;

    case LCB_CALLBACK_SDMUTATE:
        ss = ResponsePack<lcb_RESPSUBDOC>::get_mt(rb);
        break;

    default:
        return NULL;
    }

    if (ss->uuid_ == 0 && ss->seqno_ == 0) {
        return NULL;
    }
    return ss;
}

#define ERRINFO_CALLBACKS(X)                    \
    X(GET)                                      \
    X(STORE)                                    \
    X(COUNTER)                                  \
    X(TOUCH)                                    \
    X(REMOVE)                                   \
    X(UNLOCK)                                   \


LIBCOUCHBASE_API
const char *
lcb_resp_get_error_context(int cbtype, const lcb_RESPBASE *rb)
{
    if ((rb->rflags & LCB_RESP_F_ERRINFO) == 0) {
        return NULL;
    }

#define X(NAME) if (cbtype == LCB_CALLBACK_##NAME) { return ResponsePack<lcb_RESP##NAME>::get_err_ctx(rb); }
    ERRINFO_CALLBACKS(X);
#undef X
    return NULL;
}

LIBCOUCHBASE_API
const char *
lcb_resp_get_error_ref(int cbtype, const lcb_RESPBASE *rb)
{
    if ((rb->rflags & LCB_RESP_F_ERRINFO) == 0) {
        return NULL;
    }

#define X(NAME) if (cbtype == LCB_CALLBACK_##NAME) { return ResponsePack<lcb_RESP##NAME>::get_err_ref(rb); }
    ERRINFO_CALLBACKS(X);
#undef X
    return NULL;
}
