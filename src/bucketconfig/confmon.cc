/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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
#include "clconfig.h"
#define LOGARGS(mon, lvlbase) mon->settings, "confmon", LCB_LOG_##lvlbase, __FILE__, __LINE__
#define LOG(mon, lvlbase, msg) lcb_log(mon->settings, "confmon", LCB_LOG_##lvlbase, __FILE__, __LINE__, msg)

static void async_stop(void *);
static void async_start(void *);

typedef clconfig_provider Provider;
typedef clconfig_listener Listener;

namespace lcb {

struct Confmon : lcb_confmon_st {
    Confmon(lcb_settings*, lcbio_pTABLE iot);
    ~Confmon();

    Provider *next_active(Provider *cur);
    Provider *first_active();
    void prepare();
    void stop();
    void stop_real();
    void start();
    bool do_next_provider();
    int do_set_next(clconfig_info*, bool notify_miss);
    void invoke_listeners(clconfig_event_t, clconfig_info*);
    void provider_failed(Provider *which, lcb_error_t why);
    void provider_got_config(Provider *which, clconfig_info *config);
    bool is_refreshing() const {
        return (state & CONFMON_S_ACTIVE) != 0;
    }
    void dump(FILE *fp);


    /** This is the async handle for a reentrant start */
    lcbio_pTIMER as_start;

    /** Async handle for a reentrant stop */
    lcbio_pTIMER as_stop;

    /* CONFMON_S_* values. Used internally */
    int state;

    /** Last time the provider was stopped. As a microsecond timestamp */
    lcb_uint32_t last_stop_us;
};
}

using lcb::Confmon;

Provider* Confmon::next_active(clconfig_provider *cur)
{
    if (!LCB_LIST_HAS_NEXT((lcb_list_t *)&active_providers, &cur->ll)) {
        return NULL;
    }
    return LCB_LIST_ITEM(cur->ll.next, clconfig_provider, ll);
}

Provider* Confmon::first_active()
{
    if (LCB_LIST_IS_EMPTY((lcb_list_t *)&active_providers)) {
        return NULL;
    }
    return LCB_LIST_ITEM(active_providers.next, clconfig_provider, ll);
}

static const char *
provider_string(clconfig_method_t type) {
    if (type == LCB_CLCONFIG_HTTP) { return "HTTP"; }
    if (type == LCB_CLCONFIG_CCCP) { return "CCCP"; }
    if (type == LCB_CLCONFIG_FILE) { return "FILE"; }
    if (type == LCB_CLCONFIG_MCRAW) { return "MCRAW"; }
    if (type == LCB_CLCONFIG_USER) { return "USER"; }
    return "";
}

lcb_confmon* lcb_confmon_create(lcb_settings *settings, lcbio_pTABLE iot) {
    return new Confmon(settings, iot);
}

Confmon::Confmon(lcb_settings *settings_, lcbio_pTABLE iot_)
    : as_start(lcbio_timer_new(iot_, this, async_start)),
      as_stop(lcbio_timer_new(iot_, this, async_stop)),
      state(0),
      last_stop_us(0) {

    memset(static_cast<lcb_confmon*>(this), 0, sizeof(lcb_confmon));
    lcb_confmon::settings = settings_;
    lcb_confmon::iot = iot_;
    lcb_list_init(&listeners);
    lcb_clist_init(&active_providers);
    lcbio_table_ref(iot);
    lcb_settings_ref(settings);

    all_providers[LCB_CLCONFIG_FILE] = lcb_clconfig_create_file(this);
    all_providers[LCB_CLCONFIG_CCCP] = lcb_clconfig_create_cccp(this);
    all_providers[LCB_CLCONFIG_HTTP] = lcb_clconfig_create_http(this);
    all_providers[LCB_CLCONFIG_USER] = lcb_clconfig_create_user(this);
    all_providers[LCB_CLCONFIG_MCRAW] = lcb_clconfig_create_mcraw(this);

    for (size_t ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        all_providers[ii]->parent = this;
    }
}

void lcb_confmon_prepare(lcb_confmon *mon) {
    static_cast<Confmon*>(mon)->prepare();
}

void Confmon::prepare() {
    memset(&active_providers, 0, sizeof(active_providers));
    lcb_clist_init(&active_providers);

    lcb_log(LOGARGS(this, DEBUG), "Preparing providers (this may be called multiple times)");

    for (size_t ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        clconfig_provider *cur = all_providers[ii];
        if (cur) {
            if (cur->enabled) {
                lcb_clist_append(&active_providers, &cur->ll);
                lcb_log(LOGARGS(this, DEBUG), "Provider %s is ENABLED", provider_string(cur->type));
            } else if (cur->pause){
                cur->pause(cur);
                lcb_log(LOGARGS(this, DEBUG), "Provider %s is DISABLED", provider_string(cur->type));
            }
        }
    }

    lcb_assert(LCB_CLIST_SIZE(&active_providers));
    cur_provider = first_active();
}

void lcb_confmon_destroy(lcb_confmon *mon) {
    delete static_cast<Confmon*>(mon);
}

Confmon::~Confmon() {
    if (as_start) {
        lcbio_timer_destroy(as_start);
        as_start = NULL;
    }

    if (as_stop) {
        lcbio_timer_destroy(as_stop);
        as_stop = NULL;
    }

    if (config) {
        lcb_clconfig_decref(config);
        config = NULL;
    }

    for (size_t ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        clconfig_provider *provider = all_providers[ii];
        if (provider == NULL) {
            continue;
        }

        provider->shutdown(provider);
        all_providers[ii] = NULL;
    }

    lcbio_table_unref(iot);
    lcb_settings_unref(settings);
}

int Confmon::do_set_next(clconfig_info *new_config, bool notify_miss)
{
    unsigned ii;

    if (config) {
        lcbvb_CHANGETYPE chstatus = LCBVB_NO_CHANGES;
        lcbvb_CONFIGDIFF *diff = lcbvb_compare(config->vbc, new_config->vbc);

        if (!diff) {
            lcb_log(LOGARGS(this, DEBUG), "Couldn't create vbucket diff");
            return 0;
        }

        chstatus = lcbvb_get_changetype(diff);
        lcbvb_free_diff(diff);

        if (chstatus == 0 || lcb_clconfig_compare(config, new_config) >= 0) {
            const lcbvb_CONFIG *ca, *cb;

            ca = config->vbc;
            cb = new_config->vbc;

            lcb_log(LOGARGS(this, INFO), "Not applying configuration received via %s. No changes detected. A.rev=%d, B.rev=%d", provider_string(new_config->origin), ca->revid, cb->revid);
            if (notify_miss) {
                invoke_listeners(CLCONFIG_EVENT_GOT_ANY_CONFIG, new_config);
            }
            return 0;
        }
    }

    lcb_log(LOGARGS(this, INFO), "Setting new configuration. Received via %s", provider_string(new_config->origin));

    if (config) {
        /** DECREF the old one */
        lcb_clconfig_decref(config);
    }

    for (ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        clconfig_provider *cur = all_providers[ii];
        if (cur && cur->enabled && cur->config_updated) {
            cur->config_updated(cur, new_config->vbc);
        }
    }

    lcb_clconfig_incref(new_config);
    config = new_config;
    lcb_confmon_stop(this);

    invoke_listeners(CLCONFIG_EVENT_GOT_NEW_CONFIG, new_config);

    return 1;
}

void lcb_confmon_provider_failed(clconfig_provider *provider,
                                 lcb_error_t reason) {
    static_cast<Confmon*>(provider->parent)->provider_failed(provider, reason);
}

void Confmon::provider_failed(Provider *provider, lcb_error_t reason) {
    lcb_log(LOGARGS(this, INFO), "Provider '%s' failed", provider_string(provider->type));

    if (provider != cur_provider) {
        lcb_log(LOGARGS(this, TRACE), "Ignoring failure. Current=%p (%s)", (void*)cur_provider, provider_string(cur_provider->type));
        return;
    }
    if (!is_refreshing()) {
        lcb_log(LOGARGS(this, DEBUG), "Ignoring failure. Refresh not active");
    }

    if (reason != LCB_SUCCESS) {
        if (settings->detailed_neterr && last_error != LCB_SUCCESS) {
            /* Filter out any artificial 'connect error' or 'network error' codes */
            if (reason != LCB_CONNECT_ERROR && reason != LCB_NETWORK_ERROR) {
                last_error = reason;
            }
        } else {
            last_error = reason;
        }
    }

    cur_provider = next_active(cur_provider);

    if (!cur_provider) {
        LOG(this, TRACE, "Maximum provider reached. Resetting index");
        invoke_listeners(CLCONFIG_EVENT_PROVIDERS_CYCLED, NULL);
        cur_provider = first_active();
        stop();
    } else {
        uint32_t interval = 0;
        if (config) {
            /* Not first */
            interval = PROVIDER_SETTING(provider, grace_next_provider);
        }
        lcb_log(LOGARGS(this, DEBUG), "Will try next provider in %uus", interval);
        state |= CONFMON_S_ITERGRACE;
        lcbio_timer_rearm(as_start, interval);
    }
}

void lcb_confmon_provider_success(clconfig_provider *provider,
                                  clconfig_info *config) {
    static_cast<Confmon*>(provider->parent)->provider_got_config(provider, config);
}

void Confmon::provider_got_config(Provider *provider, clconfig_info *config) {
    do_set_next(config, true);
    stop();
}

bool Confmon::do_next_provider()
{
    lcb_list_t *ii;
    state &= ~CONFMON_S_ITERGRACE;

    LCB_LIST_FOR(ii, (lcb_list_t *)&active_providers) {
        clconfig_info *info;
        clconfig_provider *cached_provider;

        cached_provider = LCB_LIST_ITEM(ii, clconfig_provider, ll);
        info = cached_provider->get_cached(cached_provider);
        if (!info) {
            continue;
        }

        if (do_set_next(info, false)) {
            LOG(this, DEBUG, "Using cached configuration");
            return true;
        }
    }

    lcb_log(LOGARGS(this, TRACE), "Current provider is %s", provider_string(cur_provider->type));

    cur_provider->refresh(cur_provider);
    return false;
}

static void async_start(void *arg)
{
    reinterpret_cast<Confmon*>(arg)->do_next_provider();
}

lcb_error_t lcb_confmon_start(lcb_confmon *mon) {
    static_cast<Confmon*>(mon)->start();
    return LCB_SUCCESS;
}

void Confmon::start() {
    lcb_U32 tmonext = 0;
    lcbio_async_cancel(as_stop);
    if (is_refreshing()) {
        LOG(this, DEBUG, "Refresh already in progress...");
        return;
    }

    LOG(this, TRACE, "Start refresh requested");
    lcb_assert(cur_provider);
    state = CONFMON_S_ACTIVE|CONFMON_S_ITERGRACE;

    if (last_stop_us > 0) {
        lcb_U32 diff = LCB_NS2US(gethrtime()) - last_stop_us;
        if (diff <= settings->grace_next_cycle) {
            tmonext = settings->grace_next_cycle - diff;
        }
    }

    lcbio_timer_rearm(as_start, tmonext);
}

static void async_stop(void *arg) {
    reinterpret_cast<Confmon*>(arg)->stop_real();
}

void Confmon::stop_real() {
    lcb_list_t *ii;

    LCB_LIST_FOR(ii, (lcb_list_t *)&active_providers) {
        clconfig_provider *provider = LCB_LIST_ITEM(ii, clconfig_provider, ll);
        if (!provider->pause) {
            continue;
        }
        provider->pause(provider);
    }

    last_stop_us = LCB_NS2US(gethrtime());
    invoke_listeners(CLCONFIG_EVENT_MONITOR_STOPPED, NULL);
}

lcb_error_t lcb_confmon_stop(lcb_confmon *mon) {
    static_cast<Confmon*>(mon)->stop();
    return LCB_SUCCESS;
}

void Confmon::stop() {
    if (!is_refreshing()) {
        return;
    }
    lcbio_timer_disarm(as_start);
    lcbio_async_signal(as_stop);
    state = CONFMON_S_INACTIVE;
}

void lcb_clconfig_decref(clconfig_info *info)
{
    lcb_assert(info->refcount);

    if (--info->refcount) {
        return;
    }

    if (info->vbc) {
        lcbvb_destroy(info->vbc);
    }

    free(info);
}

int lcb_clconfig_compare(const clconfig_info *a, const clconfig_info *b)
{
    /** First check if both have revisions */
    int rev_a, rev_b;
    rev_a = lcbvb_get_revision(a->vbc);
    rev_b = lcbvb_get_revision(b->vbc);
    if (rev_a >= 0  && rev_b >= 0) {
        return rev_a - rev_b;
    }

    if (a->cmpclock == b->cmpclock) {
        return 0;

    } else if (a->cmpclock < b->cmpclock) {
        return -1;
    }

    return 1;
}

clconfig_info *
lcb_clconfig_create(lcbvb_CONFIG* config, clconfig_method_t origin)
{
    clconfig_info *info = reinterpret_cast<clconfig_info*>(calloc(1, sizeof(*info)));
    if (!info) {
        return NULL;
    }
    info->refcount = 1;
    info->vbc = config;
    info->origin = origin;
    return info;
}

void lcb_confmon_add_listener(lcb_confmon *mon, clconfig_listener *listener)
{
    listener->parent = mon;
    lcb_list_append(&mon->listeners, &listener->ll);
}

void lcb_confmon_remove_listener(lcb_confmon *mon, clconfig_listener *listener)
{
    lcb_list_delete(&listener->ll);
    (void)mon;
}

void Confmon::invoke_listeners(clconfig_event_t event, clconfig_info *info) {
    lcb_list_t *ll, *ll_next;
    LCB_LIST_SAFE_FOR(ll, ll_next, &listeners) {
        clconfig_listener *lsn = LCB_LIST_ITEM(ll, clconfig_listener, ll);
        lsn->callback(lsn, event, info);
    }
}

static void generic_shutdown(clconfig_provider *provider)
{
    free(provider);
}

clconfig_provider * lcb_clconfig_create_user(lcb_confmon *mon)
{
    clconfig_provider *provider = reinterpret_cast<clconfig_provider*>(calloc(1, sizeof(*provider)));
    provider->type = LCB_CLCONFIG_USER;
    provider->shutdown = generic_shutdown;

    (void)mon;
    return provider;
}

LCB_INTERNAL_API
int lcb_confmon_is_refreshing(lcb_confmon *mon)
{
    return static_cast<Confmon*>(mon)->is_refreshing();
}

LCB_INTERNAL_API
void
lcb_confmon_set_provider_active(lcb_confmon *mon,
    clconfig_method_t type, int enabled)
{
    clconfig_provider *provider = mon->all_providers[type];
    if (provider->enabled == enabled) {
        return;
    } else {
        provider->enabled = enabled;
    }
    lcb_confmon_prepare(mon);
}

void lcb_confmon_dump(lcb_confmon *mon, FILE *fp) {
    static_cast<Confmon*>(mon)->dump(fp);
}

void Confmon::dump(FILE *fp) {
    fprintf(fp, "CONFMON=%p\n", (void*)this);
    fprintf(fp, "STATE= (0x%x)", state);
    if (state & CONFMON_S_ACTIVE) {
        fprintf(fp, "ACTIVE|");
    }
    if (state == CONFMON_S_INACTIVE) {
        fprintf(fp, "INACTIVE/IDLE");
    }
    if (state & CONFMON_S_ITERGRACE) {
        fprintf(fp, "ITERGRACE");
    }
    fprintf(fp, "\n");
    fprintf(fp, "LAST ERROR: 0x%x\n", last_error);


    for (size_t ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        clconfig_provider *cur = all_providers[ii];
        if (!cur) {
            continue;
        }

        fprintf(fp, "** PROVIDER: 0x%x (%s) %p\n", cur->type, provider_string(cur->type), (void*)cur);
        fprintf(fp, "** ENABLED: %s\n", cur->enabled ? "YES" : "NO");
        fprintf(fp, "** CURRENT: %s\n", cur == cur_provider ? "YES" : "NO");
        if (cur->dump) {
            cur->dump(cur, fp);
        }
        fprintf(fp, "\n");
    }
}
