#include "internal.h"
#include "hostlist.h"
#include "logging.h"

#define LOGARGS(conn, lvl) \
    conn->settings, "conncycle", LCB_LOG_##lvl, __FILE__, __LINE__

#define LOG(conn, lvl, msg) lcb_log(LOGARGS(conn, lvl), msg)

lcb_error_t lcb_connection_next_node(lcb_connection_t conn,
                                     hostlist_t hostlist, char **errinfo)
{
    lcb_host_t *next_host = NULL;
    lcb_connection_close(conn);

    while ( (next_host = hostlist_shift_next(hostlist, 0))) {
        lcb_connection_result_t connres;

        if (lcb_connection_setup_host(conn, next_host) != 0) {
            continue;
        }

        connres = lcb_connection_start(conn, LCB_CONNSTART_NOCB);

        if (connres != LCB_CONN_INPROGRESS) {
            lcb_connection_close(conn);
        }

        return LCB_SUCCESS;
    }

    *errinfo = "No valid hosts remain";
    return LCB_CONNECT_ERROR;
}

lcb_error_t lcb_connection_cycle_nodes(lcb_connection_t conn,
                                        hostlist_t hostlist,
                                        char **errinfo)
{
    lcb_size_t total = hostlist->nentries;
    lcb_size_t ii;

    for (ii = 0; ii < total; ii++) {
        lcb_connection_result_t connres;
        lcb_host_t *host = hostlist_shift_next(hostlist, 1);
        lcb_assert(host != NULL);

        if (lcb_connection_setup_host(conn, host) != 0) {
            LOG(conn, ERR, "Couldn't set up host");
            continue;
        }

        connres = lcb_connection_start(conn, LCB_CONNSTART_NOCB);
        if (connres != LCB_CONN_INPROGRESS) {
            LOG(conn, ERR, "Couldn't start connection");
            lcb_connection_close(conn);
        }
        return LCB_SUCCESS;
    }

    LOG(conn, ERR, "Couldn't connect to any of the nodes");
    *errinfo = "None of the nodes are valid";
    return LCB_CONNECT_ERROR;
}

int lcb_connection_setup_host(lcb_connection_t conn, lcb_host_t *host)
{
    int rv;
    strcpy(conn->host, host->host);
    strcpy(conn->port, host->port);
    rv = lcb_connection_getaddrinfo(conn, 1);
    return rv;
}
