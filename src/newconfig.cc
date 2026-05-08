/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2020 Couchbase, Inc.
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
#include "vbucket/aliases.h"
#include "sllist-inl.h"

#define LOGARGS(instance, lvl) (instance)->settings, "newconfig", LCB_LOG_##lvl, __FILE__, __LINE__
#define LOG(instance, lvlbase, msg) lcb_log(instance->settings, "newconfig", LCB_LOG_##lvlbase, __FILE__, __LINE__, msg)

#define SERVER_FMT LCB_LOG_SPEC("%s:%s") " (%p)"
#define SERVER_ARGS(s)                                                                                                 \
    (s)->settings->log_redaction ? LCB_LOG_SD_OTAG : "", (s)->get_host().host, (s)->get_host().port,                   \
        (s)->settings->log_redaction ? LCB_LOG_SD_CTAG : "", (void *)s

typedef struct lcb_GUESSVB_st {
    time_t last_update; /**< Last time this vBucket was heuristically set */
    char newix;         /**< New index, heuristically determined */
    char oldix;         /**< Original index, according to map */
    char used;          /**< Flag indicating whether or not this entry has been used */
} lcb_GUESSVB;

/* Ignore configuration updates for heuristically guessed vBuckets for a
 * maximum amount of [n] seconds */
#define MAX_KEEP_GUESS 20

static int should_keep_guess(lcb_GUESSVB *guess, lcbvb_VBUCKET *vb)
{
    if (guess->newix == guess->oldix) {
        /* Heuristic position is the same as starting position */
        return 0;
    }
    if (vb->servers[0] != guess->oldix) {
        /* Previous master changed */
        return 0;
    }

    if (time(nullptr) - guess->last_update > MAX_KEEP_GUESS) {
        /* Last usage too old */
        return 0;
    }

    return 1;
}

void lcb_vbguess_newconfig(lcb_INSTANCE *instance, lcbvb_CONFIG *cfg, lcb_GUESSVB *guesses)
{
    unsigned ii;

    if (!guesses) {
        return;
    }

    for (ii = 0; ii < cfg->nvb; ii++) {
        lcb_GUESSVB *guess = guesses + ii;
        lcbvb_VBUCKET *vb = cfg->vbuckets + ii;

        if (!guess->used) {
            continue;
        }

        /* IF: Heuristically learned a new index, _and_ the old index (which is
         * known to be bad) is the same index stated by the new config */
        if (should_keep_guess(guess, vb)) {
            lcb_log(LOGARGS(instance, TRACE), "Keeping heuristically guessed index. VBID=%d. Current=%d. Old=%d.", ii,
                    guess->newix, guess->oldix);
            vb->servers[0] = guess->newix;
        } else {
            /* We don't reassign to the guess structure here. The idea is that
             * we will simply use the new config. If this gives us problems, the
             * config will re-learn again. */
            lcb_log(LOGARGS(instance, TRACE),
                    "Ignoring heuristically guessed index. VBID=%d. Current=%d. Old=%d. New=%d", ii, guess->newix,
                    guess->oldix, vb->servers[0]);
            guess->used = 0;
        }
    }
}

int lcb_vbguess_remap(lcb_INSTANCE *instance, int vbid, int bad)
{
    if (LCBT_SETTING(instance, vb_noremap)) {
        return -1;
    }

    /* CCBC-1702: defensive bounds check.
     *
     * Server::handle_nmv pins instance->cur_configinfo for the duration of
     * the call, which is sufficient for the common case where cmdq.config
     * == cur_configinfo->vbc. But empirically (build-1524 FoRecoverDelta-
     * SUBDOC SIGSEGV at the deref of cfg->vbuckets[vbid]), there is still
     * at least one path where cmdq.config points at a lcbvb_CONFIG that
     * has been freed via lcbvb_destroy() while a SUBDOC response handler
     * is mid-call. The defensive zeroing in lcbvb_destroy() leaves a
     * stale cfg with vbuckets=NULL/nvb=0; without this guard, the
     * subsequent deref is a NULL+offset SIGSEGV.
     *
     * Returning -1 here funnels the op into the same path as a legitimate
     * "no remap currently available": lcb_kv_should_retry ->
     * mcreq_renew_packet -> retryq->nmvadd, where it waits for the next
     * config (which is in-flight at this exact moment, since the only
     * path that frees the old vbc is lcb_update_vbconfig()) and retries
     * against fresh pipelines. */
    lcbvb_CONFIG *cfg = LCBT_VBCONFIG(instance);
    if (cfg == nullptr || cfg->vbuckets == nullptr || vbid < 0 || (unsigned)vbid >= cfg->nvb) {
        lcb_log(LOGARGS(instance, WARN),
                "vbguess_remap: rejecting deref of stale or empty vbucket map "
                "(cfg=%p, vbuckets=%p, nvb=%u, vbid=%d). Op will be requeued.",
                (void *)cfg, cfg ? (void *)cfg->vbuckets : nullptr, cfg ? cfg->nvb : 0u, vbid);
        return -1;
    }

    if (LCBT_SETTING(instance, vb_noguess)) {
        int newix = lcbvb_nmv_remap_ex(cfg, vbid, bad, 0);
        if (newix > -1 && newix != bad) {
            lcb_log(LOGARGS(instance, TRACE), "Got new index from ffmap. VBID=%d. Old=%d. New=%d", vbid, bad, newix);
        }
        return newix;

    } else {
        lcb_GUESSVB *guesses = instance->vbguess;
        if (!guesses) {
            guesses = instance->vbguess = reinterpret_cast<lcb_GUESSVB *>(calloc(cfg->nvb, sizeof(lcb_GUESSVB)));
        }
        lcb_GUESSVB *guess = guesses + vbid;
        int newix = lcbvb_nmv_remap_ex(cfg, vbid, bad, 1);
        if (newix > -1 && newix != bad) {
            guess->newix = static_cast<char>(newix);
            guess->oldix = static_cast<char>(bad);
            guess->used = 1;
            guess->last_update = time(nullptr);
            lcb_log(LOGARGS(instance, TRACE), "Guessed new heuristic index VBID=%d. Old=%d. New=%d", vbid, bad, newix);
        }
        return newix;
    }
}

/**
 * Finds the index of an older server using the current config.
 *
 * This function is used to help reuse the server structures for memcached
 * packets.
 *
 * @param oldconfig The old configuration. This is the configuration the
 * old server is bound to
 * @param newconfig The new configuration. This will be inspected for new
 * nodes which may have been added, and ones which may have been removed.
 * @param server The server to match
 * @return The new index, or -1 if the current server is not present in the new
 * config.
 */
static int find_new_data_index(lcbvb_CONFIG *oldconfig, lcbvb_CONFIG *newconfig, lcb::Server *server)
{
    lcbvb_SVCMODE mode = LCBT_SETTING_SVCMODE(server->get_instance());
    const char *old_datahost = lcbvb_get_hostport(oldconfig, server->get_index(), LCBVB_SVCTYPE_DATA, mode);

    if (!old_datahost) {
        /* Old server had no data service */
        return -1;
    }

    for (size_t ii = 0; ii < LCBVB_NSERVERS(newconfig); ii++) {
        const char *new_datahost = lcbvb_get_hostport(newconfig, ii, LCBVB_SVCTYPE_DATA, mode);
        if (new_datahost && strcmp(new_datahost, old_datahost) == 0) {
            return ii;
        }
    }
    return -1;
}

static void log_vbdiff(lcb_INSTANCE *instance, lcbvb_CONFIGDIFF *diff)
{
    lcb_log(LOGARGS(instance, INFO), "Config Diff: [ vBuckets Modified=%d ], [Sequence Changed=%d]", diff->n_vb_changes,
            diff->sequence_changed);
    if (diff->servers_added) {
        for (char **curserver = diff->servers_added; *curserver; curserver++) {
            lcb_log(LOGARGS(instance, INFO), "Detected server %s added", *curserver);
        }
    }
    if (diff->servers_removed) {
        for (char **curserver = diff->servers_removed; *curserver; curserver++) {
            lcb_log(LOGARGS(instance, INFO), "Detected server %s removed", *curserver);
        }
    }
}

/**
 * This callback is invoked for packet relocation twice. It tries to relocate
 * commands to their destination server. Some commands may not be relocated
 * either because they have no explicit "Relocation Information" (i.e. no
 * specific vbucket) or because the command is tied to a specific server (i.e.
 * CMD_STAT).
 *
 * Note that `KEEP_PACKET` here doesn't mean to "Save" the packet, but rather
 * to keep the packet in the current queue (so that if the server ends up
 * being removed, the command will fail); rather than being relocated to
 * another server.
 */
static int iterwipe_cb(mc_CMDQUEUE *cq, mc_PIPELINE *oldpl, mc_PACKET *oldpkt, void *)
{
    protocol_binary_request_header hdr;
    auto *srv = static_cast<lcb::Server *>(oldpl);
    int newix;
    auto *instance = (lcb_INSTANCE *)cq->cqdata;

    mcreq_read_hdr(oldpkt, &hdr);
    /* we should not relocate GET_WITH_REPLICA packets */
    if (hdr.request.opcode == PROTOCOL_BINARY_CMD_GET_REPLICA) {
        return MCREQ_KEEP_PACKET;
    }

    lcb_RETRY_ACTION retry = lcb_kv_should_retry(srv->get_settings(), oldpkt, LCB_ERR_TOPOLOGY_CHANGE);
    if (!retry.should_retry) {
        return MCREQ_KEEP_PACKET;
    }

    if (LCBVB_DISTTYPE(cq->config) == LCBVB_DIST_VBUCKET) {
        newix = lcbvb_vbmaster(cq->config, ntohs(hdr.request.vbucket));

    } else {
        const char *key = nullptr;
        size_t nkey = 0;
        int tmpid;

        /* XXX: We ignore hashkey. This is going away soon, and is probably
         * better than simply failing the items. */
        mcreq_get_key(oldpkt, &key, &nkey);
        lcbvb_map_key(cq->config, key, nkey, &tmpid, &newix);
    }

    if (newix < 0 || newix > (int)cq->npipelines - 1) {
        return MCREQ_KEEP_PACKET;
    }

    mc_PIPELINE *newpl = cq->pipelines[newix];
    if (newpl == oldpl || newpl == nullptr) {
        return MCREQ_KEEP_PACKET;
    }

    lcb_log(LOGARGS(instance, DEBUG), "Remapped packet %p (SEQ=%u) from " SERVER_FMT " to " SERVER_FMT, (void *)oldpkt,
            oldpkt->opaque, SERVER_ARGS((lcb::Server *)oldpl), SERVER_ARGS((lcb::Server *)newpl));

    /** Otherwise, copy over the packet and find the new vBucket to map to */
    mc_PACKET *newpkt = mcreq_renew_packet(oldpkt);
    newpkt->flags &= ~MCREQ_STATE_FLAGS;
    mcreq_reenqueue_packet(newpl, newpkt);
    mcreq_packet_handled(oldpl, oldpkt);
    return MCREQ_REMOVE_PACKET;
}

/* CCBC-1702: structural cleanup of the replace path.
 *
 * The pre-fix flow used mcreq_queue_take_pipelines() to NULL out
 * cq->pipelines and zero cq->npipelines, then built the new pipeline
 * array, then mcreq_queue_add_pipelines() to install it. While LCB is
 * single-threaded and the event loop cannot dispatch a retryq tick
 * inside this call frame, leaving the cmdq in pipelines=NULL /
 * npipelines=0 across an arbitrary number of synchronous heap allocs
 * (the new lcb::Server constructors) is brittle: any future change
 * that introduces a synchronous reader of cq state in a Server ctor or
 * in find_new_data_index() would observe a transient inconsistent
 * cmdq.
 *
 * This rewrite performs the swap as a single tight sequence at the
 * end, after ppnew is fully built. Old slots that were not kept are
 * tracked via a parallel bitmap (`moved[]`) instead of by writing NULL
 * into cq->pipelines, so the live cq->pipelines buffer is not modified
 * before the swap. The retry-policy fix in settings.cc is the
 * load-bearing change for the visible behaviour; this is the
 * belt-and-suspenders. */
static void replace_config(lcb_INSTANCE *instance, lcbvb_CONFIG *oldconfig, lcbvb_CONFIG *newconfig)
{
    mc_CMDQUEUE *cq = &instance->cmdq;

    lcb_assert(LCBT_VBCONFIG(instance) == newconfig);

    unsigned nnew = LCBVB_NSERVERS(newconfig);
    mc_PIPELINE **ppnew = reinterpret_cast<mc_PIPELINE **>(calloc(nnew, sizeof(mc_PIPELINE *)));

    /* Snapshot the existing pipelines without disturbing cq. */
    mc_PIPELINE **old_pipelines_buf = cq->pipelines;
    unsigned nold = cq->npipelines;
    bool *moved = reinterpret_cast<bool *>(calloc(nold ? nold : 1, sizeof(bool)));

    /* Determine which existing servers are still part of the new cluster
     * config and place them in the new list. */
    for (unsigned ii = 0; ii < nold; ii++) {
        auto *cur = static_cast<lcb::Server *>(old_pipelines_buf[ii]);
        int newix = find_new_data_index(oldconfig, newconfig, cur);
        if (newix > -1) {
            cur->set_new_index(newix);
            ppnew[newix] = cur;
            moved[ii] = true;
            lcb_log(LOGARGS(instance, INFO), "Reusing server " SERVER_FMT ". OldIndex=%d. NewIndex=%d",
                    SERVER_ARGS(cur), ii, newix);
        }
    }

    /* Allocate new lcb::Server structures for slots that do not have one. */
    for (unsigned ii = 0; ii < nnew; ii++) {
        if (!ppnew[ii]) {
            ppnew[ii] = new lcb::Server(instance, static_cast<int>(ii));
        }
    }

    /* Atomic swap of cq state. From the next instruction onward, any
     * reader sees the fully-installed new pipelines, npipelines, scheds,
     * and config. */
    {
        size_t pl_bytes = sizeof(mc_PIPELINE *) * (nnew + 1);
        mc_PIPELINE **new_queue_pipelines = reinterpret_cast<mc_PIPELINE **>(malloc(pl_bytes));
        memcpy(new_queue_pipelines, ppnew, sizeof(mc_PIPELINE *) * nnew);

        unsigned new_ex = nnew;
        if (cq->fallback) {
            cq->fallback->index = nnew;
            new_queue_pipelines[nnew] = cq->fallback;
            new_ex++;
        }

        for (unsigned ii = 0; ii < nnew; ii++) {
            ppnew[ii]->parent = cq;
            ppnew[ii]->index = ii;
        }

        char *new_scheds = reinterpret_cast<char *>(calloc(nnew + 1, sizeof(char)));
        char *old_scheds = cq->scheds;

        /* Note: we do NOT free cq->pipelines here. old_pipelines_buf
         * aliases that buffer and the drain loop below still walks it
         * via old_pipelines_buf[ii]. The free is deferred to the bottom
         * of this function. */
        cq->pipelines = new_queue_pipelines;
        cq->npipelines = nnew;
        cq->_npipelines_ex = new_ex;
        cq->scheds = new_scheds;
        cq->config = newconfig;

        free(old_scheds);
    }

    /* Drain old pipelines that were not carried over: relocate their
     * pending packets onto the new pipelines (mcreq_iterwipe ->
     * iterwipe_cb), purge any that cannot be relocated, then close the
     * pipeline. */
    for (unsigned ii = 0; ii < nold; ii++) {
        if (moved[ii]) {
            continue;
        }
        mcreq_iterwipe(cq, old_pipelines_buf[ii], iterwipe_cb, nullptr);
        static_cast<lcb::Server *>(old_pipelines_buf[ii])->purge(LCB_ERR_MAP_CHANGED);
        static_cast<lcb::Server *>(old_pipelines_buf[ii])->close();
    }

    for (unsigned ii = 0; ii < nnew; ii++) {
        if (static_cast<lcb::Server *>(ppnew[ii])->has_pending()) {
            ppnew[ii]->flush_start(ppnew[ii]);
        }
    }

    free(moved);
    free(ppnew);
    free(old_pipelines_buf);
}

void lcb_update_vbconfig(lcb_INSTANCE *instance, lcb_pCONFIGINFO config)
{
    lcb::clconfig::ConfigInfo *old_config = instance->cur_configinfo;
    mc_CMDQUEUE *q = &instance->cmdq;

    instance->cur_configinfo = config;
    config->incref();
    q->config = instance->cur_configinfo->vbc;
    q->cqdata = instance;

    if (old_config) {
        lcbvb_CONFIGDIFF *diff = lcbvb_compare(old_config->vbc, config->vbc);

        if (diff) {
            log_vbdiff(instance, diff);
            lcbvb_free_diff(diff);
        }

        /* Apply the vb guesses */
        lcb_vbguess_newconfig(instance, config->vbc, instance->vbguess);

        replace_config(instance, old_config->vbc, config->vbc);
        old_config->decref();
    } else {
        size_t nservers = VB_NSERVERS(config->vbc);
        std::vector<mc_PIPELINE *> servers;

        for (size_t ii = 0; ii < nservers; ii++) {
            servers.push_back(new lcb::Server(instance, ii));
        }

        mcreq_queue_add_pipelines(q, &servers[0], nservers, config->vbc);
    }

    /* Update the list of nodes here for server list */
    instance->ht_nodes->clear();
    for (size_t ii = 0; ii < LCBVB_NSERVERS(config->vbc); ++ii) {
        const char *hp = lcbvb_get_hostport(config->vbc, ii, LCBVB_SVCTYPE_MGMT, LCBT_SETTING_SVCMODE(instance));
        if (hp) {
            instance->ht_nodes->add(hp, LCB_CONFIG_HTTP_PORT);
        }
    }

    lcb_maybe_breakout(instance);
}
