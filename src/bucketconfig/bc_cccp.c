#include "internal.h"
#include "clconfig.h"
#include "packetutils.h"
#include "simplestring.h"
#include "mcserver.h"

#define LOGARGS(cccp, lvl) \
    cccp->base.parent->settings, "cccp", LCB_LOG_##lvl, __FILE__, __LINE__

#define LOG(cccp, lvl, msg) lcb_log(LOGARGS(cccp, lvl), msg)

typedef struct {
    clconfig_provider base;
    struct lcb_connection_st connection;
    hostlist_t nodes;
    clconfig_info *config;
    int server_active;
    int disabled;
} cccp_provider;

static void io_error_handler(lcb_connection_t);
static void io_read_handler(lcb_connection_t);
static void request_config(cccp_provider *);
static void socket_connected(lcb_connection_t, lcb_error_t);
static void socket_timeout(lcb_connection_t, lcb_error_t);

static lcb_error_t mcio_error(cccp_provider *cccp)
{
    lcb_error_t err;
    char *errinfo;
    struct lcb_io_use_st use;

    lcb_connection_t conn = &cccp->connection;

    LOG(cccp, ERR, "Got I/O Error");
    lcb_connection_close(conn);

    if (conn->protoctx) {
        lcb_negotiation_destroy((struct negotiation_context*)conn->protoctx);
        conn->protoctx = NULL;
    }

    conn->on_connect_complete = socket_connected;
    err = lcb_connection_next_node(conn, cccp->nodes, &errinfo);

    lcb_connuse_easy(&use, cccp,
                     PROVIDER_SETTING(&cccp->base, config_timeout),
                     io_read_handler, io_error_handler, socket_timeout);

    lcb_connection_use(conn, &use);

    if (err != LCB_SUCCESS) {
        lcb_connection_cancel_timer(conn);
        lcb_confmon_provider_failed(&cccp->base, err);
        cccp->server_active = 0;
        return err;
    }

    return LCB_SUCCESS;
}

static void socket_timeout(lcb_connection_t conn, lcb_error_t err)
{
    cccp_provider *cccp = conn->data;
    (void)err;

    mcio_error(cccp);
}

static void negotiation_done(struct negotiation_context *ctx, lcb_error_t err)
{
    cccp_provider *cccp = ctx->data;
    struct lcb_io_use_st use;

    if (err != LCB_SUCCESS) {
        LOG(cccp, ERR, "CCCP SASL negotiation failed");
        mcio_error(cccp);
    } else {
        LOG(cccp, DEBUG, "CCCP SASL negotiation done");
        lcb_connuse_easy(&use, cccp,
                         PROVIDER_SETTING(&cccp->base, config_timeout),
                         io_read_handler, io_error_handler, socket_timeout);
        lcb_connection_use(&cccp->connection, &use);
        request_config(cccp);
    }
}

static void socket_connected(lcb_connection_t conn, lcb_error_t err)
{
    cccp_provider *cccp = conn->data;
    struct lcb_nibufs_st nistrs;
    LOG(cccp, DEBUG, "CCCP Socket connected");

    if (err != LCB_SUCCESS) {
        mcio_error(cccp);
        return;
    }

    if (!lcb_get_nameinfo(conn, &nistrs)) {
        mcio_error(cccp);
        return;
    }

    if (cccp->base.parent->settings->username || 1) {
        struct negotiation_context *ctx;

        ctx = lcb_negotiation_create(conn, cccp->base.parent->settings,
                                     nistrs.remote, nistrs.local, &err);
        if (!ctx) {
            mcio_error(cccp);
        }

        ctx->complete = negotiation_done;
        ctx->data = cccp;
        conn->protoctx = ctx;
        conn->protoctx_dtor = (protoctx_dtor_t)lcb_negotiation_destroy;

    } else {
        request_config(cccp);
    }
}


void lcb_clconfig_cccp_set_nodes(clconfig_provider *pb, hostlist_t mcnodes)
{
    unsigned int ii;
    cccp_provider *cccp = (cccp_provider *)pb;
    lcb_assert(pb->type == LCB_CLCONFIG_CCCP);
    for (ii = 0; ii < mcnodes->nentries; ii++) {
        hostlist_add_host(cccp->nodes, mcnodes->entries + ii);
    }
    if (mcnodes->nentries) {
        pb->enabled = 1;
    }
}

/** Update the configuration from a server. */
lcb_error_t lcb_cccp_update(clconfig_provider *provider,
                            const char *host,
                            lcb_string *data)
{
    VBUCKET_CONFIG_HANDLE vbc;
    clconfig_info *new_config;
    cccp_provider *cccp = (cccp_provider *)provider;
    vbc = vbucket_config_create();

    if (!vbc) {
        return LCB_CLIENT_ENOMEM;
    }

    if (vbucket_config_parse2(vbc, LIBVBUCKET_SOURCE_MEMORY, data->base, host)) {
        vbucket_config_destroy(vbc);
        return LCB_PROTOCOL_ERROR;
    }

    new_config = lcb_clconfig_create(vbc, data, LCB_CLCONFIG_CCCP);

    if (!new_config) {
        vbucket_config_destroy(vbc);
        return LCB_CLIENT_ENOMEM;
    }

    if (cccp->config) {
        lcb_clconfig_decref(cccp->config);
    }

    /** TODO: Figure out the comparison vector */
    new_config->cmpclock = gethrtime();
    cccp->config = new_config;
    lcb_confmon_set_next(provider->parent, new_config, 0);
    return LCB_SUCCESS;
}

static lcb_error_t cccp_get(clconfig_provider *pb)
{
    lcb_error_t err;
    char *errinfo;
    struct lcb_io_use_st use;
    cccp_provider *cccp = (cccp_provider *)pb;
    lcb_connection_t conn = &cccp->connection;


    if (cccp->server_active) {
        return LCB_BUSY;
    }

    conn->on_connect_complete = socket_connected;
    err = lcb_connection_cycle_nodes(conn, cccp->nodes, &errinfo);

    if (err != LCB_SUCCESS) {
        lcb_confmon_provider_failed(pb, LCB_CONNECT_ERROR);
        return err;
    }

    lcb_connuse_easy(&use, cccp, PROVIDER_SETTING(pb, config_timeout),
                     io_read_handler, io_error_handler, socket_timeout);
    lcb_connection_use(&cccp->connection, &use);
    cccp->server_active = 1;
    return LCB_SUCCESS;
}

static clconfig_info *cccp_get_cached(clconfig_provider *pb)
{
    cccp_provider *cccp = (cccp_provider *)pb;
    return cccp->config;
}

static lcb_error_t cccp_pause(clconfig_provider *pb)
{
    cccp_provider *cccp = (cccp_provider *)pb;
    if (!cccp->server_active) {
        return LCB_SUCCESS;
    }

    cccp->server_active = 0;
    lcb_connection_close(&cccp->connection);
    lcb_connection_cancel_timer(&cccp->connection);
    return LCB_SUCCESS;
}

static void cccp_cleanup(clconfig_provider *pb)
{
    cccp_provider *cccp = (cccp_provider *)pb;
    struct negotiation_context *ctx = cccp->connection.protoctx;
    cccp->connection.protoctx = NULL;

    if (ctx) {
        lcb_negotiation_destroy(ctx);
    }

    lcb_connection_close(&cccp->connection);
    lcb_connection_cleanup(&cccp->connection);

    if (cccp->config) {
        lcb_clconfig_decref(cccp->config);
    }
    if (cccp->nodes) {
        hostlist_destroy(cccp->nodes);
    }
    free(cccp);
}

static void nodes_updated(clconfig_provider *provider, hostlist_t nodes,
                          VBUCKET_CONFIG_HANDLE vbc)
{
    int ii;
    cccp_provider *cccp = (cccp_provider *)provider;
    if (!vbc) {
        return;
    }
    if (vbucket_config_get_num_servers(vbc) < 1) {
        return;
    }

    hostlist_clear(cccp->nodes);
    for (ii = 0; ii < vbucket_config_get_num_servers(vbc); ii++) {
        const char *mcaddr = vbucket_config_get_server(vbc, ii);
        hostlist_add_stringz(cccp->nodes, mcaddr, 11210);
    }

    (void)nodes;
}

static void io_error_handler(lcb_connection_t conn)
{
    mcio_error((cccp_provider *)conn->data);
}

static void io_read_handler(lcb_connection_t conn)
{
    packet_info pi;
    cccp_provider *cccp = conn->data;
    lcb_string jsonstr;
    lcb_error_t err;
    int rv;

    memset(&pi, 0, sizeof(pi));

    rv = lcb_packet_read_ringbuffer(&pi, conn->input);

    if (rv < 0) {
        LOG(cccp, ERR, "Couldn't parse packet!?");
        mcio_error(cccp);
        return;

    } else if (rv == 0) {
        lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
        lcb_sockrw_apply_want(conn);
        return;
    }

    if (PACKET_STATUS(&pi) != PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        lcb_log(LOGARGS(cccp, ERR),
                "CCCP Packet responded with 0x%x; nkey=%d, nbytes=%lu, cmd=0x%x, seq=0x%x",
                PACKET_STATUS(&pi),
                PACKET_NKEY(&pi),
                PACKET_NBODY(&pi),
                PACKET_OPCODE(&pi),
                PACKET_OPAQUE(&pi));

        mcio_error(cccp);
        return;
    }

    if (!PACKET_NBODY(&pi)) {
        mcio_error(cccp);
        return;
    }

    if (lcb_string_init(&jsonstr)) {
        mcio_error(cccp);
        return;
    }

    if (lcb_string_append(&jsonstr, PACKET_BODY(&pi), PACKET_NBODY(&pi))) {
        mcio_error(cccp);
        return;
    }

    err = lcb_cccp_update(&cccp->base, conn->host, &jsonstr);
    lcb_string_release(&jsonstr);
    lcb_packet_release_ringbuffer(&pi, conn->input);
    if (err != LCB_SUCCESS) {
        mcio_error(cccp);

    } else {
        lcb_sockrw_set_want(conn, 0, 1);
        lcb_sockrw_apply_want(conn);
        lcb_connection_cancel_timer(conn);
    }
}

static void request_config(cccp_provider *cccp)
{
    protocol_binary_request_set_cluster_config req;
    lcb_connection_t conn = &cccp->connection;
    ringbuffer_t *buf = conn->output;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = CMD_GET_CLUSTER_CONFIG;
    req.message.header.request.opaque = 0xF00D;

    if (!buf) {
        if ((buf = calloc(1, sizeof(*buf))) == NULL) {
            mcio_error(cccp);
            return;
        }
        conn->output = buf;
    }

    if (!ringbuffer_ensure_capacity(buf, sizeof(req.bytes))) {
        mcio_error(cccp);
    }

    ringbuffer_write(buf, req.bytes, sizeof(req.bytes));
    lcb_sockrw_set_want(conn, LCB_WRITE_EVENT, 1);
    lcb_sockrw_apply_want(conn);
}

clconfig_provider * lcb_clconfig_create_cccp(lcb_confmon *mon)
{
    cccp_provider *cccp = calloc(1, sizeof(*cccp));
    cccp->nodes = hostlist_create();
    cccp->base.type = LCB_CLCONFIG_CCCP;
    cccp->base.refresh = cccp_get;
    cccp->base.get_cached = cccp_get_cached;
    cccp->base.pause = cccp_pause;
    cccp->base.shutdown = cccp_cleanup;
    cccp->base.nodes_updated = nodes_updated;
    cccp->base.parent = mon;
    cccp->base.enabled = 0;

    if (!cccp->nodes) {
        free(cccp);
        return NULL;
    }


    if (lcb_connection_init(&cccp->connection,
                            cccp->base.parent->settings->io,
                            cccp->base.parent->settings) != LCB_SUCCESS) {
        free(cccp);
        return NULL;
    }

    return &cccp->base;
}

void lcb_clconfig_cccp_disable(clconfig_provider *provider)
{
    cccp_provider *cccp = (cccp_provider *)provider;
    cccp->disabled = 1;
}
