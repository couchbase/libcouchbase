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

    /* Overrides */
    clconfig_info* get_cached();
    lcb_error_t refresh();
    void configure_nodes(const lcb::Hostlist& l);
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

clconfig_info* McRawProvider::get_cached() {
    return config;
}

lcb_error_t McRawProvider::refresh() {
    lcbio_async_signal(async);
    return LCB_SUCCESS;
}

void McRawProvider::configure_nodes(const lcb::Hostlist& hl)
{
    lcbvb_SERVER *servers;
    lcbvb_CONFIG *newconfig;
    unsigned nsrv = hl.size();

    if (!nsrv) {
        lcb_log(LOGARGS(this, FATAL), "No nodes provided");
        return;
    }

    servers = reinterpret_cast<lcbvb_SERVER*>(calloc(nsrv, sizeof(*servers)));
    for (size_t ii = 0; ii < nsrv; ii++) {
        const lcb_host_t& curhost = hl[ii];
        lcbvb_SERVER *srv = servers + ii;

        /* just set the memcached port and hostname */
        srv->hostname = (char *)curhost.host;
        srv->svc.data = std::atoi(curhost.port);
        if (parent->settings->sslopts) {
            srv->svc_ssl.data = srv->svc.data;
        }
    }

    newconfig = lcbvb_create();
    lcbvb_genconfig_ex(newconfig, "NOBUCKET", "deadbeef", servers, nsrv, 0, 2);
    lcbvb_make_ketama(newconfig);
    newconfig->revid = -1;

    if (config) {
        lcb_clconfig_decref(config);
        config = NULL;
    }
    config = lcb_clconfig_create(newconfig, LCB_CLCONFIG_MCRAW);
    config->cmpclock = gethrtime();
}

lcb_error_t
lcb_clconfig_mcraw_update(clconfig_provider *pb, const char *nodes)
{
    lcb_error_t err;
    McRawProvider *mcr = static_cast<McRawProvider*>(pb);
    lcb::Hostlist hl;
    err = hl.add(nodes, LCB_CONFIG_MCCOMPAT_PORT);
    if (err != LCB_SUCCESS) {
        return err;
    }

    pb->configure_nodes(hl);
    lcbio_async_signal(mcr->async);
    return LCB_SUCCESS;
}

McRawProvider::~McRawProvider() {
    if (config) {
        lcb_clconfig_decref(config);
    }
    if (async) {
        lcbio_timer_destroy(async);
    }
}

clconfig_provider_st* lcb::clconfig::new_mcraw_provider(lcb_confmon* parent) {
    return new McRawProvider(parent);
}

McRawProvider::McRawProvider(lcb_confmon *parent_)
    : clconfig_provider_st(parent_, LCB_CLCONFIG_MCRAW),
      config(NULL), async(lcbio_timer_new(parent->iot, this, async_update)) {
}
