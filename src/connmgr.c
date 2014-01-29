#include "internal.h"
#include "hostlist.h"
#include "connmgr.h"

#define LOGARGS(mgr, lvl) \
    mgr->settings, "connmgr", LCB_LOG_##lvl, __FILE__, __LINE__

typedef enum {
    CS_PENDING,
    CS_IDLE,
    CS_LEASED
} cinfo_state;

typedef enum {
    RS_UNINIT = 0,
    RS_PENDING,
    RS_ASSIGNED
} request_state;

typedef struct connmgr_cinfo_st {
    lcb_list_t llnode;
    struct connmgr_hostent_st *parent;
    struct lcb_connection_st connection;
    lcb_timer_t idle_timer;
    int state;
} connmgr_cinfo;

static void destroy_cinfo(connmgr_cinfo *info)
{
    if (info->state == CS_IDLE) {
        lcb_list_delete(&info->llnode);
    }

    if (info->idle_timer) {
        lcb_timer_destroy(NULL, info->idle_timer);
    }

    lcb_connection_cleanup(&info->connection);

    free(info);
}

static connmgr_hostent * he_from_conn(connmgr_t *mgr, lcb_connection_t conn)
{
    connmgr_cinfo *ci = conn->poolinfo;
    (void)mgr;

    lcb_assert(ci);
    return ci->parent;
}

connmgr_t *connmgr_create(lcb_settings *settings, lcb_io_opt_t io)
{
    connmgr_t *pool = calloc(1, sizeof(*pool));
    if (!pool) {
        return NULL;
    }

    if ((pool->ht = lcb_hashtable_nc_new(32)) == NULL) {
        free(pool);
        return NULL;
    }

    pool->settings = settings;
    pool->io = io;
    return pool;
}

static void iterfunc(const void *k,
                     lcb_size_t nk,
                     const void *v,
                     lcb_size_t nv,
                     void *arg)
{
    lcb_list_t *he_list = (lcb_list_t *)arg;
    connmgr_hostent *he = (connmgr_hostent *)v;
    lcb_list_t *cur, *next;

    LCB_LIST_SAFE_FOR(cur, next, &he->conns) {
        connmgr_cinfo *info = LCB_LIST_ITEM(cur, connmgr_cinfo, llnode);
        destroy_cinfo(info);
    }

    memset(&he->conns, 0, sizeof(he->conns));
    lcb_list_append(he_list, &he->conns);

    (void)k;
    (void)nk;
    (void)nv;
}

void connmgr_destroy(connmgr_t *mgr)
{
    lcb_list_t hes;
    lcb_list_t *cur, *next;
    lcb_list_init(&hes);

    genhash_iter(mgr->ht, iterfunc, &hes);

    LCB_LIST_SAFE_FOR(cur, next, &hes) {
        connmgr_hostent *he = LCB_LIST_ITEM(cur, connmgr_hostent, conns);
        genhash_delete(mgr->ht, he->key, strlen(he->key));
        lcb_list_delete(&he->conns);
        free(he);
    }

    genhash_free(mgr->ht);
    free(mgr);
}

static void invoke_request(connmgr_request *req)
{
    if (req->timer) {
        lcb_timer_destroy(NULL, req->timer);
    }

    req->callback(req);
}

/**
 * Called to notify that a connection has become available.
 */
static void connection_available(connmgr_hostent *he)
{
    while (! (LCB_LIST_IS_EMPTY(&he->requests) || LCB_LIST_IS_EMPTY(&he->conns))) {
        connmgr_request *req;
        connmgr_cinfo *info;
        lcb_list_t *reqitem, *connitem;

        reqitem = lcb_list_shift(&he->requests);
        connitem = lcb_list_pop(&he->conns);

        req = LCB_LIST_ITEM(reqitem, connmgr_request, llnode);
        info = LCB_LIST_ITEM(connitem, connmgr_cinfo, llnode);

        req->conn = &info->connection;
        info->state = CS_LEASED;
        he->n_leased++;
        he->n_requests--;

        lcb_log(LOGARGS(he->parent, INFO),
                "Assigning R=%p,c=%p", req, req->conn);

        invoke_request(req);
    }
}

static void on_connected(lcb_connection_t conn, lcb_error_t err)
{
    connmgr_cinfo *info = (connmgr_cinfo *)conn->poolinfo;
    connmgr_hostent *he = info->parent;
    he->n_pending--;
    lcb_assert(info->state == CS_PENDING);

    lcb_log(LOGARGS(he->parent, INFO),
            "Received result for I=%p,C=%p; E=0x%x", info, conn, err);

    if (err != LCB_SUCCESS) {
        /** If the connection failed, fail out all remaining requests */
        lcb_list_t *cur, *next;
        lcb_list_delete(&info->llnode);

        LCB_LIST_SAFE_FOR(cur, next, &he->requests) {
            connmgr_request *req = LCB_LIST_ITEM(cur, connmgr_request, llnode);
            lcb_list_delete(cur);

            req->conn = NULL;
            he->n_requests--;
            invoke_request(req);
        }

        destroy_cinfo(info);

    } else {
        connection_available(info->parent);
    }
}

static void start_new_connection(connmgr_hostent *he, lcb_uint32_t tmo)
{
    lcb_host_t tmphost;
    lcb_error_t err;
    lcb_conn_params params;

    connmgr_cinfo *info = calloc(1, sizeof(*info));
    info->state = CS_PENDING;
    info->parent = he;
    info->connection.poolinfo = info;

    lcb_connection_init(&info->connection,
                        he->parent->io,
                        he->parent->settings);

    params.handler = on_connected;
    params.timeout = tmo;
    err = lcb_host_parsez(&tmphost, he->key, 80);
    lcb_assert(err == LCB_SUCCESS);
    params.destination = &tmphost;
    lcb_list_append(&he->conns, &info->llnode);
    lcb_log(LOGARGS(he->parent, INFO),
            "Starting connection on I=%p,C=%p", info, &info->connection);
    lcb_connection_start(&info->connection, &params,
                         LCB_CONNSTART_ASYNCERR|LCB_CONNSTART_NOCB);
    he->n_pending++;
    he->n_total++;
}

static void on_request_timeout(lcb_timer_t tm, lcb_t instance,
                               const void *cookie)
{
    connmgr_request *req = (connmgr_request *)cookie;
    lcb_list_delete(&req->llnode);
    req->he->n_requests--;
    invoke_request(req);

    (void)tm;
    (void)instance;
}

static void async_invoke_request(lcb_timer_t tm, lcb_t instance, const void *cookie)
{

    connmgr_request *req = (connmgr_request *)cookie;
    invoke_request(req);
    (void)tm;
    (void)instance;
}

void connmgr_get(connmgr_t *pool, connmgr_request *req, lcb_uint32_t timeout)
{
    connmgr_hostent *he;
    lcb_list_t *cur, *next;

    if (req->state != RS_UNINIT) {
        lcb_log(LOGARGS(pool, INFO),
                "Request %p/%s already in progress..", req, req->key);
        return;
    }

    lcb_log(LOGARGS(pool, DEBUG), "Got request R=%p,%s", req, req->key);

    he = genhash_find(pool->ht, req->key, strlen(req->key));
    if (!he) {
        he = calloc(1, sizeof(*he));
        he->parent = pool;
        strcpy(he->key, req->key);

        lcb_list_init(&he->conns);
        lcb_list_init(&he->requests);

        /** Not copied */
        genhash_store(pool->ht, he->key, strlen(he->key), he, 0);
    }


    req->conn = NULL;
    req->he = he;

    LCB_LIST_SAFE_FOR(cur, next, &he->conns) {
        connmgr_cinfo *info = LCB_LIST_ITEM(cur, connmgr_cinfo, llnode);
        if (info->state != CS_IDLE) {
            /** Not available for use */
            continue;
        }

        lcb_list_delete(&info->llnode);
        if (info->idle_timer) {
            lcb_timer_destroy(NULL, info->idle_timer);
            info->idle_timer = NULL;
        }
        req->conn = &info->connection;
        info->state = CS_LEASED;
        he->n_leased++;
        break;
    }

    if (req->conn) {
        lcb_error_t err;
        req->state = RS_ASSIGNED;
        req->timer = lcb_async_create(pool->io, req, async_invoke_request, &err);
        lcb_log(LOGARGS(pool, INFO), "Pairing connection with request..");

    } else {
        req->state = RS_PENDING;
        he->n_requests++;
        req->timer = lcb_timer_create_simple(pool->io,
                                             req,
                                             timeout,
                                             on_request_timeout);
        lcb_list_append(&he->requests, &req->llnode);
        if (he->n_pending < he->n_requests) {
            start_new_connection(he, timeout);
        }
    }
}

/**
 * Invoked when a new socket is available for allocation within the
 * request queue.
 */
static void async_available_notify(lcb_timer_t tm,
                                   lcb_t instance,
                                   const void *cookie)
{
    connmgr_hostent *he = (connmgr_hostent *)cookie;
    lcb_timer_destroy(instance, tm);
    he->async = NULL;
    connection_available(he);
}

void connmgr_cancel(connmgr_t *mgr, connmgr_request *req)
{
    connmgr_hostent *he = req->he;
    if (req->state == RS_UNINIT) {
        lcb_log(LOGARGS(mgr, DEBUG), "Not cancelling uninit request");
        return;
    }

    if (req->timer) {
        lcb_timer_destroy(NULL, req->timer);
        req->timer = NULL;
    }

    if (req->conn) {
        lcb_log(LOGARGS(mgr, DEBUG), "Cancelling request with existing connection");
        connmgr_put(mgr, req->conn);
        if (!he->async) {
            lcb_error_t err;
            he->async = lcb_async_create(mgr->io, he,
                                         async_available_notify, &err);
        }

    } else {
        lcb_log(LOGARGS(mgr, DEBUG), "Request has no connection.. yet");
        he->n_requests--;
        lcb_list_delete(&req->llnode);
    }
}

static void io_error(lcb_connection_t conn)
{
    connmgr_cinfo *info = conn->poolinfo;
    lcb_assert(info);
    lcb_assert(info->state != CS_LEASED);

    if (info->state == CS_IDLE) {
        lcb_log(LOGARGS(info->parent->parent, INFO),
                "Pooled idle connection %p expired", conn);
    }

    if (info->idle_timer) {
        lcb_timer_destroy(NULL, info->idle_timer);
        info->idle_timer = NULL;
    }

    info->parent->n_total--;

    destroy_cinfo(info);
}

static void io_read(lcb_connection_t conn)
{
    io_error(conn);
}


static void on_idle_timeout(lcb_timer_t tm, lcb_t instance, const void *cookie)
{
    connmgr_cinfo *info = (connmgr_cinfo *)cookie;

    lcb_log(LOGARGS(info->parent->parent, DEBUG),
            "Idle connection %p to %s expired",
            &info->connection, info->parent->key);

    io_error(&info->connection);
    (void)tm;
    (void)instance;
}


void connmgr_put(connmgr_t *mgr, lcb_connection_t conn)
{
    struct lcb_io_use_st use;
    connmgr_hostent *he;
    connmgr_cinfo *info = conn->poolinfo;

    lcb_assert(conn->state == LCB_CONNSTATE_CONNECTED);
    lcb_assert(conn->poolinfo != NULL);

    he = he_from_conn(mgr, conn);
    if (he->n_total - (he->n_pending + he->n_leased) >= mgr->max_idle) {
        if (he->n_requests <= he->n_total - he->n_leased) {
            lcb_log(LOGARGS(mgr, INFO),
                    "Closing idle connection. Too many in quota");
            connmgr_discard(mgr, conn);
            return;
        }
    }

    lcb_log(LOGARGS(mgr, INFO),
            "Reclaiming connection I=%p,Cu=%p,Cp=%p (%s)",
            info, conn, &info->connection, he->key);

    he->n_leased--;
    lcb_connuse_easy(&use, info, io_read, io_error);
    lcb_connection_transfer_socket(conn, &info->connection, &use);
    lcb_sockrw_set_want(&info->connection, 0, 1);
    lcb_sockrw_apply_want(&info->connection);
    lcb_list_append(&he->conns, &info->llnode);
    info->state = CS_IDLE;
    info->idle_timer = lcb_timer_create_simple(mgr->io, info,
                                               mgr->idle_timeout,
                                               on_idle_timeout);
}

void connmgr_discard(connmgr_t *pool, lcb_connection_t conn)
{
    connmgr_cinfo *cinfo = conn->poolinfo;

    lcb_log(LOGARGS(pool, DEBUG), "Discarding connection %p", conn);
    lcb_assert(cinfo);
    lcb_connection_cleanup(conn);
    cinfo->parent->n_leased--;
    cinfo->parent->n_total--;
    destroy_cinfo(cinfo);
}

LCB_INTERNAL_API
void connmgr_req_init(connmgr_request *req, const char *host, const char *port,
                      connmgr_callback_t callback)
{
    memset(req, 0, sizeof(*req));
    req->callback = callback;
    sprintf(req->key, "%s:%s", host, port);
}
