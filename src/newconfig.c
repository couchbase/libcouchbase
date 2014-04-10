/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2013 Couchbase, Inc.
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
#include "bucketconfig/clconfig.h"
#include "vb-aliases.h"

#define LOGARGS(instance, lvl) \
    instance->settings, "bconf", LCB_LOG_##lvl, __FILE__, __LINE__

#define LOG(instance, lvl, msg) lcb_log(LOGARGS(instance, lvl), msg)

static int allocate_new_servers(lcb_t instance, clconfig_info *config);

static void
log_vbdiff(lcb_t instance, VBUCKET_CONFIG_DIFF *diff)
{
    char **curserver;
    lcb_log(LOGARGS(instance, INFO),
            "Config Diff: [ vBuckets Modified=%d ], [Sequence Changed=%d]",
            diff->n_vb_changes, diff->sequence_changed);

    if (diff->servers_added) {
        for (curserver = diff->servers_added; *curserver; curserver++) {
            lcb_log(LOGARGS(instance, INFO), "Detected server %s added",
                    *curserver);
        }
    }
    if (diff->servers_removed) {
        for (curserver = diff->servers_removed; *curserver; curserver++) {
            lcb_log(LOGARGS(instance, INFO), "Detected server %s removed",
                    *curserver);
        }
    }
}


static int
iterwipe_cb(mc_CMDQUEUE *cq, mc_PIPELINE *oldpl, mc_PACKET *oldpkt, void *arg)
{
    protocol_binary_request_header hdr;
    mc_PIPELINE *newpl;
    mc_PACKET *newpkt;
    int newix;

    memcpy(&hdr, SPAN_BUFFER(&oldpkt->kh_span), sizeof(hdr.bytes));
    if (hdr.request.opcode == CMD_OBSERVE ||
            hdr.request.opcode == PROTOCOL_BINARY_CMD_STAT ||
            hdr.request.opcode == CMD_GET_CLUSTER_CONFIG) {
        /** Need special handling */
        return MCREQ_KEEP_PACKET;
    }

    /** Find the new server for vBucket mapping */
    newix = vbucket_get_master(cq->config, ntohs(hdr.request.vbucket));
    if (newix < 0 || newix > (int)cq->npipelines) {
        /** Need to fail this one out! */
        return MCREQ_KEEP_PACKET;
    }

    newpl = cq->pipelines[newix];

    /** Otherwise, copy over the packet and find the new vBucket to map to */
    newpkt = mcreq_dup_packet(oldpkt);
    newpkt->flags &= ~MCREQ_STATE_FLAGS;
    mcreq_reenqueue_packet(newpl, newpkt);
    mcreq_packet_handled(oldpl, oldpkt);

    (void)arg;

    return MCREQ_REMOVE_PACKET;
}


static int
replace_config(lcb_t instance, clconfig_info *old_config,
               clconfig_info *next_config)
{
    VBUCKET_CONFIG_DIFF *diff;
    VBUCKET_DISTRIBUTION_TYPE dist_t;
    mc_PIPELINE **old;
    unsigned ii, nold;
    int *is_clean;


    diff = vbucket_compare(old_config->vbc, next_config->vbc);

    if (diff) {
        log_vbdiff(instance, diff);
    }

    if (diff == NULL ||
            (diff->sequence_changed == 0 && diff->n_vb_changes == 0)) {
        lcb_log(LOGARGS(instance, DEBUG),
            "Ignoring config update. No server changes; DIFF=%p", diff);
        vbucket_free_diff(diff);
        return LCB_CONFIGURATION_UNCHANGED;
    }

    old = mcreq_queue_take_pipelines(&instance->cmdq, &nold);
    dist_t = VB_DISTTYPE(next_config->vbc);
    vbucket_free_diff(diff);

    if (allocate_new_servers(instance, next_config) != 0) {
        return -1;
    }

    is_clean = calloc(nold, sizeof(*is_clean));

    for (ii = 0; ii < nold; ii++) {
        mc_PIPELINE *pl = old[ii];
        is_clean[ii] = mcserver_is_clean((mc_SERVER *)pl);

        if (dist_t == VBUCKET_DISTRIBUTION_VBUCKET) {
            mcreq_iterwipe(&instance->cmdq, pl, iterwipe_cb, NULL);
        }
    }

    for (ii = 0; ii < nold; ii++) {
        mc_PIPELINE *pl = old[ii];
        mc_SERVER *server = (mc_SERVER *)pl;
        mcserver_fail_chain(server, LCB_MAP_CHANGED);
        mcserver_close(server, is_clean[ii]);
    }

    for (ii = 0; ii < instance->cmdq.npipelines; ii++) {
        mc_PIPELINE *pl = instance->cmdq.pipelines[ii];
        pl->flush_start(pl);
    }

    free(is_clean);
    free(old);
    return LCB_CONFIGURATION_CHANGED;
}

static int
allocate_new_servers(lcb_t instance, clconfig_info *config)
{
    unsigned ii;
    unsigned nservers;
    mc_PIPELINE **servers;
    mc_CMDQUEUE *q = &instance->cmdq;

    nservers = VB_NSERVERS(config->vbc);
    servers = malloc(sizeof(*servers) * nservers);
    if (!servers) {
        return -1;
    }

    for (ii = 0; ii < nservers; ii++) {
        mc_SERVER *srv = mcserver_alloc(instance, ii);
        servers[ii] = &srv->pipeline;
        if (!srv) {
            return -1;
        }
    }

    mcreq_queue_add_pipelines(q, servers, nservers, config->vbc);
    return 0;
}

void lcb_update_vbconfig(lcb_t instance, clconfig_info *config)
{
    lcb_size_t ii;
    int change_status;
    clconfig_info *old_config;
    mc_CMDQUEUE *q = &instance->cmdq;

    old_config = instance->cur_configinfo;
    instance->cur_configinfo = config;
    instance->dist_type = VB_DISTTYPE(config->vbc);
    lcb_clconfig_incref(config);
    instance->nreplicas = (lcb_uint16_t)VB_NREPLICAS(config->vbc);
    q->config = instance->cur_configinfo->vbc;
    q->instance = instance;

    if (old_config) {
        change_status = replace_config(instance, old_config, config);
        if (change_status == -1) {
            LOG(instance, ERR, "Couldn't replace config");
            return;
        }

        lcb_clconfig_decref(old_config);

    } else {
        if (allocate_new_servers(instance, config) != 0) {
            return;
        }
        change_status = LCB_CONFIGURATION_NEW;
    }

    /* Notify anyone interested in this event... */
    if (change_status != LCB_CONFIGURATION_UNCHANGED) {
        if (instance->vbucket_state_listener != NULL) {
            for (ii = 0; ii < q->npipelines; ii++) {
                lcb_server_t *server = (lcb_server_t *)q->pipelines[ii];
                instance->vbucket_state_listener(server);
            }
        }
    }

    instance->callbacks.configuration(instance, change_status);
    lcb_maybe_breakout(instance);
}
