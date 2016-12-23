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

#include <lcbio/lcbio.h>
#include <lcbio/timer-ng.h>
#include <libcouchbase/vbucket.h>
#include "clconfig.h"

#define LOGARGS(mcr, lvlbase) mcr->parent->settings, "mcraw", LCB_LOG_##lvlbase, __FILE__, __LINE__
#define LOGFMT "(MCRAW=%p)> "
#define LOGID(mcr) (void *)mcr

/* Raw memcached provider */

struct McRawProvider : clconfig_provider {
    /* Current (user defined) configuration */
    clconfig_info *config;
    lcbio_pTIMER async;

    McRawProvider(lcb_confmon*);
    ~McRawProvider();
};


static void
async_update(void *arg)
{
    McRawProvider *mcr = reinterpret_cast<McRawProvider*>(arg);
    if (!mcr->config) {
        lcb_log(LOGARGS(mcr, WARN), "No current config set. Not setting configuration");
        return;
    }
    lcb_confmon_provider_success(mcr, mcr->config);
}

static clconfig_info* get_cached(clconfig_provider *pb) {
    return static_cast<McRawProvider*>(pb)->config;
}
static lcb_error_t get_refresh(clconfig_provider *pb) {
    lcbio_async_signal(static_cast<McRawProvider*>(pb)->async);
    return LCB_SUCCESS;
}
static lcb_error_t pause_mcr(clconfig_provider *) {
    return LCB_SUCCESS;
}

static void configure_nodes(clconfig_provider *pb, const hostlist_t hl)
{
    McRawProvider *mcr = static_cast<McRawProvider*>(pb);
    lcbvb_SERVER *servers;
    lcbvb_CONFIG *newconfig;
    unsigned ii, nsrv;

    nsrv = hostlist_size(hl);

    if (!nsrv) {
        lcb_log(LOGARGS(mcr, FATAL), "No nodes provided");
        return;
    }

    servers = reinterpret_cast<lcbvb_SERVER*>(calloc(nsrv, sizeof(*servers)));
    for (ii = 0; ii < nsrv; ii++) {
        int itmp;
        const lcb_host_t *curhost = hostlist_get(hl, ii);
        lcbvb_SERVER *srv = servers + ii;

        /* just set the memcached port and hostname */
        srv->hostname = (char *)curhost->host;
        sscanf(curhost->port, "%d", &itmp);
        srv->svc.data = itmp;
        if (pb->parent->settings->sslopts) {
            srv->svc_ssl.data = itmp;
        }
    }

    newconfig = lcbvb_create();
    lcbvb_genconfig_ex(newconfig, "NOBUCKET", "deadbeef", servers, nsrv, 0, 2);
    lcbvb_make_ketama(newconfig);
    newconfig->revid = -1;

    if (mcr->config) {
        lcb_clconfig_decref(mcr->config);
        mcr->config = NULL;
    }
    mcr->config = lcb_clconfig_create(newconfig, LCB_CLCONFIG_MCRAW);
    mcr->config->cmpclock = gethrtime();
}

lcb_error_t
lcb_clconfig_mcraw_update(clconfig_provider *pb, const char *nodes)
{
    lcb_error_t err;
    McRawProvider *mcr = static_cast<McRawProvider*>(pb);
    hostlist_t hl = hostlist_create();
    err = hostlist_add_stringz(hl, nodes, LCB_CONFIG_MCCOMPAT_PORT);
    if (err != LCB_SUCCESS) {
        hostlist_destroy(hl);
        return err;
    }

    configure_nodes(pb, hl);
    hostlist_destroy(hl);
    lcbio_async_signal(mcr->async);
    return LCB_SUCCESS;
}

static void mcraw_shutdown(clconfig_provider *pb) {
    delete static_cast<McRawProvider*>(pb);
}

McRawProvider::~McRawProvider() {
    if (config) {
        lcb_clconfig_decref(config);
    }
    if (async) {
        lcbio_timer_destroy(async);
    }
}

clconfig_provider * lcb_clconfig_create_mcraw(lcb_confmon *parent) {
    return new McRawProvider(parent);
}

McRawProvider::McRawProvider(lcb_confmon *parent)
    : config(NULL), async(lcbio_timer_new(parent->iot, this, async_update)) {
    memset(static_cast<clconfig_provider*>(this), 0, sizeof(clconfig_provider));

    clconfig_provider::parent = parent;
    clconfig_provider::type = LCB_CLCONFIG_MCRAW;
    clconfig_provider::get_cached = get_cached;
    clconfig_provider::refresh = get_refresh;
    clconfig_provider::pause = pause_mcr;
    clconfig_provider::configure_nodes = configure_nodes;
    clconfig_provider::shutdown = mcraw_shutdown;
}
