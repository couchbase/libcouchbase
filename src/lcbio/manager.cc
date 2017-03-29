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

#include "manager.h"
#include "hostlist.h"
#include "iotable.h"
#include "timer-ng.h"
#include "internal.h"

#define LOGARGS(mgr, lvl) mgr->settings, "lcbio_mgr", LCB_LOG_##lvl, __FILE__, __LINE__

typedef enum {
    CS_PENDING,
    CS_IDLE,
    CS_LEASED
} cinfo_state;

typedef enum {
    RS_PENDING,
    RS_ASSIGNED
} request_state;

typedef char mgr_KEY[NI_MAXSERV + NI_MAXHOST + 2];

using namespace lcb::io;

namespace lcb {
namespace io {

struct PoolHost {
    inline PoolHost(Pool*, const std::string&);
    inline void connection_available();
    inline void start_new_connection(uint32_t timeout);

    void ref() {
        refcount++;
    }

    void unref() {
        if (!--refcount) {
            delete this;
        }
    }

    inline void dump(FILE *fp) const;

    size_t num_pending() const {
        return LCB_CLIST_SIZE(&ll_pending);
    }
    size_t num_idle() const {
        return LCB_CLIST_SIZE(&ll_idle);
    }
    size_t num_requests() const {
        return LCB_CLIST_SIZE(&requests);
    }
    size_t num_leased() const {
        return n_total - (num_idle() + num_pending());
    }

    lcb_clist_t ll_idle; /* idle connections */
    lcb_clist_t ll_pending; /* pending cinfo */
    lcb_clist_t requests; /* pending requests */
    const std::string key; /* host:port */
    Pool *parent;
    lcb::io::Timer<PoolHost, &PoolHost::connection_available> async;
    unsigned n_total; /* number of total connections */
    unsigned refcount;
};
}
}

struct CinfoNode : lcb_list_t {};

namespace lcb {
namespace io {
struct PoolConnInfo : lcbio_PROTOCTX, CinfoNode {
    inline PoolConnInfo(PoolHost *parent, uint32_t timeout);
    inline ~PoolConnInfo();
    inline void on_idle_timeout();
    inline void on_connected(lcbio_SOCKET *sock, lcb_error_t err);

    static PoolConnInfo *from_llnode(lcb_list_t *node) {
        return static_cast<PoolConnInfo*>(static_cast<CinfoNode*>(node));
    }

    static PoolConnInfo *from_sock(lcbio_SOCKET *sock) {
        lcbio_PROTOCTX *ctx = lcbio_protoctx_get(sock, LCBIO_PROTOCTX_POOL);
        return static_cast<PoolConnInfo*>(ctx);
    }

    PoolHost *parent;
    lcbio_SOCKET *sock;
    lcbio_pCONNSTART cs;
    lcb::io::Timer<PoolConnInfo, &PoolConnInfo::on_idle_timeout> idle_timer;
    int state;
};
}
}

struct ReqNode : lcb_list_t {};
namespace lcb {
namespace io {
struct PoolRequest : ReqNode {
    static PoolRequest *from_llnode(lcb_list_t *node) {
        return static_cast<PoolRequest*>(static_cast<ReqNode*>(node));
    }

    lcbio_CONNDONE_cb callback;
    void *arg;
    PoolHost *host;
    lcbio_pTIMER timer;
    int state;
    lcbio_SOCKET *sock;
    lcb_error_t err;
};
}
}

static const char *get_hehost(PoolHost *h) {
    if (!h) { return "NOHOST:NOPORT"; }
    return h->key.c_str();
}

/** Format string arguments for %p%s:%s */
#define HE_LOGID(h) get_hehost(h), (void*)h
#define HE_LOGFMT "<%s> (HE=%p) "

PoolConnInfo::~PoolConnInfo() {
    parent->n_total--;
    if (state == CS_IDLE) {
        lcb_clist_delete(&parent->ll_idle, this);

    } else if (state == CS_PENDING && cs) {
        lcbio_connect_cancel(cs);
    }

    if (sock) {
        // Ensure destructor is not called!
        dtor = NULL;
        lcbio_protoctx_delptr(sock, this, 0);
        lcbio_unref(sock);
    }
    parent->unref();
}

static void
cinfo_protoctx_dtor(lcbio_PROTOCTX *ctx)
{
    PoolConnInfo *info = reinterpret_cast<PoolConnInfo*>(ctx);
    info->sock = NULL;
    delete info;
}

Pool::Pool(lcb_settings* settings_, lcbio_pTABLE io_)
    : settings(settings_), io(io_),
      tmoidle(0), maxidle(0), maxtotal(0), refcount(1) {
}

Pool *lcbio_mgr_create(lcb_settings *settings, lcbio_TABLE *io) {
    return new Pool(settings, io);
}


typedef std::vector<PoolHost*> HeList;

void lcbio_mgr_destroy(Pool *mgr) {
    mgr->shutdown();
}

Pool::~Pool() {
}

void Pool::shutdown() {
    HeList hes;
    HostMap::iterator h_it;

    for (h_it = ht.begin(); h_it != ht.end(); ++h_it) {
        PoolHost *he = h_it->second;

        lcb_list_t *cur, *next;
        LCB_LIST_SAFE_FOR(cur, next, (lcb_list_t *)&he->ll_idle) {
            delete PoolConnInfo::from_llnode(cur);
        }

        LCB_LIST_SAFE_FOR(cur, next, (lcb_list_t *)&he->ll_pending) {
            delete PoolConnInfo::from_llnode(cur);
        }
        hes.push_back(he);
    }

    for (HeList::iterator it = hes.begin(); it != hes.end(); ++it) {
        PoolHost *he = *it;
        ht.erase(he->key);
        he->async.release();
        he->unref();
    }
    unref();
}

static void
invoke_request(PoolRequest *req)
{
    if (req->sock) {
        PoolConnInfo *info = PoolConnInfo::from_sock(req->sock);
        lcb_assert(info->state == CS_IDLE);
        info->state = CS_LEASED;
        req->state = RS_ASSIGNED;
        info->idle_timer.cancel();
        lcb_log(LOGARGS(info->parent->parent, DEBUG), HE_LOGFMT "Assigning R=%p SOCKET=%p",HE_LOGID(info->parent), (void*)req, (void*)req->sock);
    }

    if (req->timer) {
        lcbio_timer_destroy(req->timer);
        req->timer = NULL;
    }

    req->callback(req->sock, req->arg, req->err, 0);
    if (req->sock) {
        lcbio_unref(req->sock);
    }
    free(req);
}

/**
 * Called to notify that a connection has become available.
 */
void
PoolHost::connection_available() {
    while (LCB_CLIST_SIZE(&requests) && LCB_CLIST_SIZE(&ll_idle)) {
        lcb_list_t *reqitem = lcb_clist_shift(&requests);
        lcb_list_t *connitem = lcb_clist_pop(&ll_idle);

        PoolRequest* req = PoolRequest::from_llnode(reqitem);
        PoolConnInfo* info = PoolConnInfo::from_llnode(connitem);
        req->sock = info->sock;
        req->err = LCB_SUCCESS;
        invoke_request(req);
    }
}

/**
 * Connection callback invoked from lcbio_connect() when a result is received
 */
static void
on_connected(lcbio_SOCKET *sock, void *arg, lcb_error_t err, lcbio_OSERR)
{
    reinterpret_cast<PoolConnInfo*>(arg)->on_connected(sock, err);
}


void PoolConnInfo::on_connected(lcbio_SOCKET *sock_, lcb_error_t err) {
    lcb_assert(state == CS_PENDING);
    cs = NULL;

    lcb_log(LOGARGS(parent->parent, DEBUG), HE_LOGFMT "Received result for I=%p,C=%p; E=0x%x", HE_LOGID(parent), (void*)this, (void*)sock, err);
    lcb_clist_delete(&parent->ll_pending, this);

    if (err != LCB_SUCCESS) {
        /** If the connection failed, fail out all remaining requests */
        lcb_list_t *cur, *next;
        LCB_LIST_SAFE_FOR(cur, next, (lcb_list_t *)&parent->requests) {
            PoolRequest *req = PoolRequest::from_llnode(cur);
            lcb_clist_delete(&parent->requests, req);
            req->sock = NULL;
            req->err = err;
            invoke_request(req);
        }
        delete this;

    } else {
        state = CS_IDLE;
        sock = sock_;
        lcbio_ref(sock);
        lcbio_protoctx_add(sock, this);

        lcb_clist_append(&parent->ll_idle, this);
        idle_timer.rearm(parent->parent->tmoidle);
        parent->connection_available();
    }
}

PoolConnInfo::PoolConnInfo(PoolHost *he, uint32_t timeout)
    : parent(he), sock(NULL), cs(NULL), idle_timer(he->parent->io, this),
      state(CS_PENDING) {

    // protoctx fields
    id = LCBIO_PROTOCTX_POOL;
    dtor = cinfo_protoctx_dtor;

    lcb_host_t tmphost;
    lcb_error_t err = lcb_host_parsez(&tmphost, he->key.c_str(), 80);
    if (err != LCB_SUCCESS) {
        lcb_log(LOGARGS(he->parent, ERROR), HE_LOGFMT "Could not parse host! Will supply dummy host (I=%p)", HE_LOGID(he), (void*)this);
        strcpy(tmphost.host, "BADHOST");
        strcpy(tmphost.port, "BADPORT");
    }
    lcb_log(LOGARGS(he->parent, TRACE), HE_LOGFMT "New pool entry: I=%p", HE_LOGID(he), (void*)this);

    cs = lcbio_connect(he->parent->io, he->parent->settings, &tmphost,
                       timeout, ::on_connected, this);
}

void
PoolHost::start_new_connection(uint32_t tmo)
{
    PoolConnInfo *info = new PoolConnInfo(this, tmo);
    lcb_clist_append(&ll_pending, info);
    n_total++;
    refcount++;
}

static void
on_request_timeout(void *cookie)
{
    PoolRequest *req = reinterpret_cast<PoolRequest*>(cookie);
    lcb_clist_delete(&req->host->requests, req);
    req->err = LCB_ETIMEDOUT;
    invoke_request(req);
}

static void
async_invoke_request(void *cookie)
{
    PoolRequest *req = reinterpret_cast<PoolRequest*>(cookie);
    PoolConnInfo *cinfo = PoolConnInfo::from_sock(req->sock);
    cinfo->state = CS_IDLE;
    invoke_request(req);
}

PoolHost::PoolHost(Pool *parent_, const std::string& key_)
    : key(key_), parent(parent_), async(parent->io, this),
      n_total(0), refcount(1) {

    lcb_clist_init(&ll_idle);
    lcb_clist_init(&ll_pending);
    lcb_clist_init(&requests);
}

PoolRequest *lcbio_mgr_get(Pool *pool, lcb_host_t *dest, uint32_t timeout,
              lcbio_CONNDONE_cb handler, void *arg)
{
    return pool->get(*dest, timeout, handler, arg);
}

PoolRequest*
Pool::get(const lcb_host_t& dest, uint32_t timeout, lcbio_CONNDONE_cb cb,
               void *cbarg)
{
    PoolHost *he;
    lcb_list_t *cur;
    PoolRequest *req = reinterpret_cast<PoolRequest*>(calloc(1, sizeof(*req)));

    std::string key(dest.host);
    key.append(":").append(dest.port);

    req->callback = cb;
    req->arg = cbarg;

    HostMap::iterator m = ht.find(key);
    if (m == ht.end()) {
        he = new PoolHost(this, key);
        ht.insert(std::make_pair(key, he));
        ref();
    } else {
        he = m->second;
    }

    req->host = he;

    GT_POPAGAIN:

    cur = lcb_clist_pop(&he->ll_idle);
    if (cur) {
        int clstatus;
        PoolConnInfo *info = PoolConnInfo::from_llnode(cur);

        clstatus = lcbio_is_netclosed(info->sock, LCB_IO_SOCKCHECK_PEND_IS_ERROR);

        if (clstatus == LCB_IO_SOCKCHECK_STATUS_CLOSED) {
            lcb_log(LOGARGS(this, WARN), HE_LOGFMT "Pooled socket is dead. Continuing to next one", HE_LOGID(he));

            /* Set to CS_LEASED, since it's not inside any of our lists */
            info->state = CS_LEASED;
            delete info;
            goto GT_POPAGAIN;
        }

        info->idle_timer.cancel();
        req->sock = info->sock;
        req->state = RS_ASSIGNED;
        req->timer = lcbio_timer_new(io, req, async_invoke_request);
        info->state = CS_LEASED;
        lcbio_async_signal(req->timer);
        lcb_log(LOGARGS(this, INFO), HE_LOGFMT "Found ready connection in pool. Reusing socket and not creating new connection", HE_LOGID(he));

    } else {
        req->state = RS_PENDING;
        req->timer = lcbio_timer_new(io, req, on_request_timeout);
        lcbio_timer_rearm(req->timer, timeout);

        lcb_clist_append(&he->requests, req);
        if (he->num_pending() < he->num_requests()) {
            lcb_log(LOGARGS(this, DEBUG), HE_LOGFMT "Creating new connection because none are available in the pool", HE_LOGID(he));
            he->start_new_connection(timeout);

        } else {
            lcb_log(LOGARGS(this, DEBUG), HE_LOGFMT "Not creating a new connection. There are still pending ones", HE_LOGID(he));
        }
    }
    return req;
}

void
lcbio_mgr_cancel(PoolRequest *req)
{
    PoolHost *he = req->host;
    Pool *mgr = he->parent;
    if (req->timer) {
        lcbio_timer_destroy(req->timer);
        req->timer = NULL;
    }

    if (req->sock) {
        lcb_log(LOGARGS(mgr, DEBUG), HE_LOGFMT "Cancelling request=%p with existing connection", HE_LOGID(he), (void*)req);
        lcbio_mgr_put(req->sock);
        he->async.signal();

    } else {
        lcb_log(LOGARGS(mgr, DEBUG), HE_LOGFMT "Request=%p has no connection.. yet", HE_LOGID(he), (void*)req);
        lcb_clist_delete(&he->requests, req);
    }
    free(req);
}

void PoolConnInfo::on_idle_timeout() {
    lcb_log(LOGARGS(parent->parent, DEBUG), HE_LOGFMT "Idle connection expired", HE_LOGID(parent));
    lcbio_unref(sock);
}

void
lcbio_mgr_put(lcbio_SOCKET *sock)
{
    PoolHost *he;
    Pool *mgr;
    PoolConnInfo *info = PoolConnInfo::from_sock(sock);

    if (!info) {
        fprintf(stderr, "Requested put() for non-pooled (or detached) socket=%p\n", (void *)sock);
        lcbio_unref(sock);
        return;
    }

    he = info->parent;
    mgr = he->parent;

    if (he->num_idle() >= mgr->maxidle) {
        lcb_log(LOGARGS(mgr, INFO), HE_LOGFMT "Closing idle connection. Too many in quota", HE_LOGID(he));
        lcbio_unref(info->sock);
        return;
    }

    lcb_log(LOGARGS(mgr, INFO), HE_LOGFMT "Placing socket back into the pool. I=%p,C=%p", HE_LOGID(he), (void*)info, (void*)sock);
    info->idle_timer.rearm(mgr->tmoidle);
    lcb_clist_append(&he->ll_idle, info);
    info->state = CS_IDLE;
}

void
lcbio_mgr_discard(lcbio_SOCKET *sock)
{
    lcbio_unref(sock);
}

void
lcbio_mgr_detach(lcbio_SOCKET *sock)
{
    lcbio_protoctx_delid(sock, LCBIO_PROTOCTX_POOL, 1);
}


#define CONN_INDENT "    "

static void
write_he_list(const lcb_clist_t *ll, FILE *out)
{
    lcb_list_t *llcur;
    LCB_LIST_FOR(llcur, (lcb_list_t *)ll) {
        PoolConnInfo *info = PoolConnInfo::from_llnode(llcur);
        fprintf(out, "%sCONN [I=%p,C=%p ",
                CONN_INDENT, (void *)info, (void *)&info->sock);

        if (info->sock->io->model == LCB_IOMODEL_EVENT) {
            fprintf(out, "SOCKFD=%d", (int)info->sock->u.fd);
        } else {
            fprintf(out, "SOCKDATA=%p", (void *)info->sock->u.sd);
        }
        fprintf(out, " STATE=0x%x", info->state);
        fprintf(out, "]\n");
    }

}

void
PoolHost::dump(FILE *out) const {
    lcb_list_t *llcur;
    fprintf(out, "HOST=%s", key.c_str());
    fprintf(out, "Requests=%lu, Idle=%lu, Pending=%lu, Leased=%lu\n",
            num_requests(), num_idle(), num_pending(), num_leased());

    fprintf(out, CONN_INDENT "Idle Connections:\n");
    write_he_list(&ll_idle, out);
    fprintf(out, CONN_INDENT "Pending Connections: \n");
    write_he_list(&ll_pending, out);
    fprintf(out, CONN_INDENT "Pending Requests:\n");

    LCB_LIST_FOR(llcur, (lcb_list_t *)&requests) {
        PoolRequest *req = PoolRequest::from_llnode(llcur);
        union {
            lcbio_CONNDONE_cb cb;
            void *ptr;
        } u_cb;

        u_cb.cb = req->callback;

        fprintf(out, "%sREQ [R=%p, Callback=%p, Data=%p, State=0x%x]\n",
                CONN_INDENT, (void *)req, u_cb.ptr, (void *)req->arg,
                req->state);
    }

    fprintf(out, "\n");

}

/**
 * Dumps the connection manager state to stderr
 */
LCB_INTERNAL_API void lcbio_mgr_dump(Pool *mgr, FILE *out) {
    mgr->dump(out);
}

void Pool::dump(FILE *out) const {
    if (out == NULL) {
        out = stderr;
    }
    HostMap::const_iterator ii;
    for (ii = ht.begin(); ii != ht.end(); ++ii) {
        ii->second->dump(out);
    }
}
