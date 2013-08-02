/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2012 Couchbase, Inc.
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
/**
 * ioctl/fcntl-like interface for libcouchbase configuration properties
 */

typedef lcb_error_t (*ctl_handler)(int, lcb_t, int, void*);


static lcb_uint32_t* get_timeout_field(lcb_t instance, int cmd)
{
    switch (cmd) {

    case LCB_CNTL_OP_TIMEOUT:
        return &instance->timeout.usec;

    case LCB_CNTL_VIEW_TIMEOUT:
        return &instance->views_timeout;

    case LCB_CNTL_DURABILITY_INTERVAL:
        return &instance->durability_interval;

    case LCB_CNTL_DURABILITY_TIMEOUT:
        return &instance->durability_timeout;

    case LCB_CNTL_HTTP_TIMEOUT:
        return &instance->http_timeout;

    default:
        return NULL;
    }
}

static lcb_error_t timeout_common(int mode,
                                  lcb_t instance, int cmd, void *arg)
{
    lcb_uint32_t *ptr;
    lcb_uint32_t *user = arg;

    ptr = get_timeout_field(instance, cmd);
    if (!ptr) {
        return LCB_EINVAL;
    }
    if (mode == LCB_CNTL_GET) {
        *user = *ptr;
    } else {
        *ptr = *user;
    }
    return LCB_SUCCESS;
}

static lcb_error_t bufsize_common(int mode, lcb_t instance, int cmd, void *arg)
{
    lcb_size_t *ptr;
    lcb_size_t *user = arg;

    switch (cmd) {
    case LCB_CNTL_WBUFSIZE:
        ptr = &instance->wbufsize;
        break;

    case LCB_CNTL_RBUFSIZE:
        ptr = &instance->rbufsize;
        break;

    default:
        return LCB_EINVAL;
    }

    if (mode == LCB_CNTL_GET) {
        *user = *ptr;
        return LCB_SUCCESS;

    } else {
        if (!*user) {
            return LCB_EINVAL;
        }
        *ptr = *user;
        return LCB_SUCCESS;
    }
}

static lcb_error_t get_vbconfig(int mode, lcb_t instance, int cmd, void *arg)
{
    if (mode != LCB_CNTL_GET) {
        return LCB_NOT_SUPPORTED;
    }
    *(VBUCKET_CONFIG_HANDLE*)arg = instance->vbucket_config;

    (void)cmd;
    return LCB_SUCCESS;
}

static lcb_error_t get_htype(int mode, lcb_t instance, int cmd, void *arg)
{
    if (mode != LCB_CNTL_GET) {
        return LCB_NOT_SUPPORTED;
    }

    *(lcb_type_t*)arg = instance->type;

    (void)cmd;
    return LCB_SUCCESS;
}

static lcb_error_t get_kvb(int mode, lcb_t instance, int cmd, void *arg)
{
    struct lcb_cntl_vbinfo_st *vbi = arg;

    if (mode != LCB_CNTL_GET) {
        return LCB_NOT_SUPPORTED;
    }

    if (instance->vbucket_config) {
        return LCB_CLIENT_ETMPFAIL;
    }

    if (vbi->version != 0) {
        return LCB_EINVAL;
    }

    vbucket_map(instance->vbucket_config,
                vbi->v.v0.key,
                vbi->v.v0.nkey,
                &vbi->v.v0.vbucket,
                &vbi->v.v0.server_index);

    (void)cmd;
    return LCB_SUCCESS;
}

static lcb_error_t get_iops(int mode, lcb_t instance, int cmd, void *arg)
{
    if (mode != LCB_CNTL_GET) {
        return LCB_NOT_SUPPORTED;
    }

    *(lcb_io_opt_t*)arg = instance->io;
    (void)cmd;
    return LCB_SUCCESS;
}

static lcb_error_t conninfo(int mode, lcb_t instance, int cmd, void *arg)
{
    lcb_connection_t conn;
    struct lcb_cntl_server_st *si = arg;

    if (mode != LCB_CNTL_GET) {
        return LCB_NOT_SUPPORTED;
    }

    if (si->version != 0) {
        return LCB_EINVAL;

    }

    if (cmd == LCB_CNTL_MEMDNODE_INFO) {
        lcb_server_t* server;
        int ix = si->v.v0.index;

        if (ix < 0 || ix > (int)instance->nservers) {
            return LCB_EINVAL;
        }

        server = instance->servers + ix;
        if (!server) {
            return LCB_NETWORK_ERROR;
        }
        conn = &server->connection;

    } else if (cmd == LCB_CNTL_CONFIGNODE_INFO) {
        conn = &instance->connection;

    } else {
        return LCB_EINVAL;
    }

    si->v.v0.connected = conn->state == LCB_CONNSTATE_CONNECTED;
    si->v.v0.host = conn->host;
    si->v.v0.port = conn->port;

    switch (instance->io->version) {
    case 0:
        si->v.v0.sock.sockfd = conn->sockfd;
        break;

    case 1:
        si->v.v0.sock.sockptr = conn->sockptr;
        break;

    default:
        return LCB_NOT_SUPPORTED;
    }

    return LCB_SUCCESS;
}

static lcb_error_t syncmode(int mode, lcb_t instance, int cmd, void *arg)
{
    lcb_syncmode_t *user = arg;

    if (mode == LCB_CNTL_SET) {
        instance->syncmode = *user;
    } else {
        *user = instance->syncmode;
    }

    (void)cmd;
    return LCB_SUCCESS;
}

static lcb_error_t ippolicy(int mode, lcb_t instance, int cmd, void *arg)
{
    lcb_ipv6_t *user = arg;

    if (mode == LCB_CNTL_SET) {
        instance->ipv6 = *user;
    } else {
        *user = instance->ipv6;
    }

    (void)cmd;
    return LCB_SUCCESS;
}

static lcb_error_t confthresh(int mode, lcb_t instance, int cmd, void *arg)
{
    lcb_size_t *user = arg;

    if (mode == LCB_CNTL_SET) {
        instance->weird_things_threshold = *user;
    } else {
        *user = instance->weird_things_threshold;
    }

    (void)cmd;
    return LCB_SUCCESS;
}

static ctl_handler handlers[] = {
    timeout_common, /* LCB_CNTL_OP_TIMEOUT */
    timeout_common, /* LCB_CNTL_VIEW_TIMEOUT */
    bufsize_common, /* LCB_CNTL_RBUFSIZE */
    bufsize_common, /* LCB_CNTL_WBUFSIZE */
    get_htype,      /* LCB_CNTL_HANDLETYPE */
    get_vbconfig,   /* LCB_CNTL_VBCONFIG */
    get_iops,       /* LCB_CNTL_IOPS */
    get_kvb,        /* LCB_CNTL_VBMAP */
    conninfo,       /* LCB_CNTL_MEMDNODE_INFO */
    conninfo,       /* LCB_CNTL_CONFIGNODE_INFO */
    syncmode,       /* LCB_CNTL_SYNCMODE */
    ippolicy,       /* LCB_CNTL_IP6POLICY */
    confthresh      /* LCB_CNTL_CONFERRTHRESH */,
    timeout_common, /* LCB_CNTL_DURABILITY_INTERVAL */
    timeout_common, /* LCB_CNTL_DURABILITY_TIMEOUT */
    timeout_common, /* LCB_CNTL_HTTP_TIMEOUT */
};


LIBCOUCHBASE_API
lcb_error_t lcb_cntl(lcb_t instance, int mode, int cmd, void *arg)
{
    ctl_handler handler;
    if (cmd > LCB_CNTL__MAX) {
        return LCB_NOT_SUPPORTED;
    }

    handler = handlers[cmd];

    if (!handler) {
        return LCB_NOT_SUPPORTED;
    }

    return handler(mode, instance, cmd, arg);
}

/**
 * These APIs are moved from behavior.c and implemented atop of lcb_cntl
 */
LIBCOUCHBASE_API
void lcb_behavior_set_syncmode(lcb_t instance, lcb_syncmode_t val)
{
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_SYNCMODE, &val);
}

LIBCOUCHBASE_API
lcb_syncmode_t lcb_behavior_get_syncmode(lcb_t instance)
{
    lcb_syncmode_t ret;
    lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_SYNCMODE, &ret);
    return ret;
}

LIBCOUCHBASE_API
void lcb_behavior_set_ipv6(lcb_t instance, lcb_ipv6_t mode)
{
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_IP6POLICY, &mode);
}

LIBCOUCHBASE_API
lcb_ipv6_t lcb_behavior_get_ipv6(lcb_t instance)
{
    lcb_ipv6_t ret;
    lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_IP6POLICY, &ret);
    return ret;
}

LIBCOUCHBASE_API
void lcb_behavior_set_config_errors_threshold(lcb_t instance, lcb_size_t num_events)
{
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_CONFERRTHRESH, &num_events);
}

LIBCOUCHBASE_API
lcb_size_t lcb_behavior_get_config_errors_threshold(lcb_t instance)
{
    lcb_size_t ret;
    lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_CONFERRTHRESH, &ret);
    return ret;
}

/**
 * The following is from timeout.c
 */
LIBCOUCHBASE_API
void lcb_set_timeout(lcb_t instance, lcb_uint32_t usec)
{
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &usec);
}

LIBCOUCHBASE_API
lcb_uint32_t lcb_get_timeout(lcb_t instance)
{
    lcb_uint32_t ret;
    lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_OP_TIMEOUT, &ret);
    return ret;
}

LIBCOUCHBASE_API
void lcb_set_view_timeout(lcb_t instance, lcb_uint32_t usec)
{
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_VIEW_TIMEOUT, &usec);
}

LIBCOUCHBASE_API
lcb_uint32_t lcb_get_view_timeout(lcb_t instance)
{
    lcb_uint32_t ret;
    lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_VIEW_TIMEOUT, &ret);
    return ret;
}
