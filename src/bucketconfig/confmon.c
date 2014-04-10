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
#define LOGARGS(mon, lvlbase) \
    mon->settings, "confmon", LCB_LOG_##lvlbase, __FILE__, __LINE__

#define LOG(mon, lvlbase, msg) lcb_log(LOGARGS(mon, lvlbase), msg)
static int do_next_provider(lcb_confmon *mon);
static void invoke_listeners(lcb_confmon *mon,
                             clconfig_event_t event,
                             clconfig_info *info);

lcb_confmon* lcb_confmon_create(lcb_settings *settings, lcbio_pTABLE iot)
{
    int ii;
    lcb_confmon * mon = calloc(1, sizeof(*mon));
    mon->settings = settings;
    mon->iot = iot;
    lcb_list_init(&mon->listeners);
    lcb_list_init(&mon->active_providers);
    lcbio_table_ref(mon->iot);
    lcb_settings_ref(mon->settings);

    LOG(mon, TRACE, "Creating monitor...");
    mon->all_providers[LCB_CLCONFIG_FILE] = lcb_clconfig_create_file(mon);
    mon->all_providers[LCB_CLCONFIG_CCCP] = lcb_clconfig_create_cccp(mon);
    mon->all_providers[LCB_CLCONFIG_HTTP] = lcb_clconfig_create_http(mon);
    mon->all_providers[LCB_CLCONFIG_USER] = lcb_clconfig_create_user(mon);

    for (ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        mon->all_providers[ii]->parent = mon;
    }

    return mon;
}

void lcb_confmon_prepare(lcb_confmon *mon)
{
    int ii;
    int n_enabled = 0;

    for (ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        clconfig_provider *cur = mon->all_providers[ii];
        if (cur == NULL || cur->enabled == 0) {
            continue;
        }

        lcb_list_append(&mon->active_providers, &cur->ll);
        n_enabled++;
    }

    lcb_assert(n_enabled);
    lcb_log(LOGARGS(mon, DEBUG), "Have %d providers enabled", n_enabled);

    mon->cur_provider = LCB_LIST_ITEM(mon->active_providers.next,
                                      clconfig_provider, ll);
}

void lcb_confmon_destroy(lcb_confmon *mon)
{
    unsigned int ii;

    if (mon->tm_retry) {
        lcb_timer_destroy(NULL, mon->tm_retry);
    }

    if (mon->as_refresh) {
        lcb_async_destroy(NULL, mon->as_refresh);
    }

    if (mon->as_pause) {
        lcb_async_destroy(NULL, mon->as_pause);
    }

    mon->as_pause = NULL;
    mon->as_refresh = NULL;
    mon->tm_retry = NULL;

    if (mon->config) {
        lcb_clconfig_decref(mon->config);
        mon->config = NULL;
    }

    for (ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        clconfig_provider *provider = mon->all_providers[ii];
        if (provider == NULL) {
            continue;
        }

        provider->shutdown(provider);
        mon->all_providers[ii] = NULL;
    }

    lcbio_table_unref(mon->iot);
    lcb_settings_unref(mon->settings);

    free(mon);
}

int lcb_confmon_set_next(lcb_confmon *mon, clconfig_info *info, int force)
{

    invoke_listeners(mon, CLCONFIG_EVENT_GOT_ANY_CONFIG, info);

    if (mon->config && force == 0) {
        VBUCKET_CONFIG_DIFF *diff =
                vbucket_compare(mon->config->vbc, info->vbc);

        if (!diff) {
            return 0;
        }

        vbucket_free_diff(diff);
        if (lcb_clconfig_compare(mon->config, info) >= 0) {
            return 0;
        }
    }

    lcb_log(LOGARGS(mon, INFO),
            "Setting new configuration of type %d", info->origin);

    if (mon->config) {
        /** DECREF the old one */
        lcb_clconfig_decref(mon->config);
    }

    lcb_confmon_set_nodes(mon, NULL, info->vbc);

    lcb_clconfig_incref(info);
    mon->config = info;
    lcb_confmon_stop(mon);

    invoke_listeners(mon, CLCONFIG_EVENT_GOT_NEW_CONFIG, info);

    return 1;
}


static void retry_dispatch(lcb_timer_t timer, lcb_t instance, const void *cookie)
{
    lcb_confmon *mon = (lcb_confmon *)cookie;
    lcb_timer_destroy(instance, timer);
    mon->tm_retry = NULL;
    do_next_provider(mon);
}


void lcb_confmon_provider_failed(clconfig_provider *provider,
                                 lcb_error_t reason)
{
    lcb_confmon *mon = provider->parent;
    lcb_uint32_t tmo;
    lcb_list_t *next_ll;
    int is_end;
    lcb_log(LOGARGS(mon, INFO), "Provider [%d] failed", provider->type);

    if (provider != mon->cur_provider) {
        lcb_log(LOGARGS(mon, TRACE),
                "Ignoring failure. Current=%p", mon->cur_provider);

        return;
    }

    is_end = !LCB_LIST_HAS_NEXT(&mon->active_providers, &mon->cur_provider->ll);

    if (reason != LCB_SUCCESS) {
        mon->last_error = reason;
    }

    if (is_end) {
        LOG(mon, TRACE, "Maximum provider reached. Resetting index");
        next_ll = mon->active_providers.next;
        tmo = mon->settings->grace_next_cycle;
        invoke_listeners(mon, CLCONFIG_EVENT_PROVIDERS_CYCLED, NULL);

    } else {
        next_ll = mon->cur_provider->ll.next;
        tmo = mon->settings->grace_next_provider;
    }

    mon->cur_provider = LCB_LIST_ITEM(next_ll, clconfig_provider, ll);
    lcb_log(LOGARGS(mon, TRACE), "Next provider: %d/%p",
            mon->cur_provider->type, mon->cur_provider);

    if (mon->cur_provider == provider) {
        tmo = mon->settings->grace_next_cycle;
    }

    if (tmo == 0) {
        LOG(mon, TRACE, "Starting next provider");
        do_next_provider(mon);

    } else {
        if (mon->tm_retry) {
            return;
        }

        LOG(mon, TRACE, "Waiting for grace interval");
        mon->tm_retry = lcb_timer_create_simple(mon->iot,
                                                mon, tmo, retry_dispatch);
    }
}


static int do_next_provider(lcb_confmon *mon)
{
    lcb_list_t *ii;

    LCB_LIST_FOR(ii, &mon->active_providers) {
        clconfig_info *info;
        clconfig_provider *cached_provider;

        cached_provider = LCB_LIST_ITEM(ii, clconfig_provider, ll);
        info = cached_provider->get_cached(cached_provider);
        if (!info) {
            continue;
        }

        if (lcb_confmon_set_next(mon, info, 0)) {
            abort();
            LOG(mon, DEBUG, "Using cached configuration");
            return 1;
        }
    }

    lcb_log(LOGARGS(mon, TRACE), "Current provider is %d",
            mon->cur_provider->type);

    mon->cur_provider->refresh(mon->cur_provider);
    return 0;
}

static void async_dispatch(lcb_timer_t timer,
                           lcb_t instance, const void *cookie)
{
    lcb_confmon *mon = (lcb_confmon *)cookie;
    lcb_async_destroy(NULL, timer);
    mon->as_refresh = NULL;
    do_next_provider(mon);

    (void)instance;
}

lcb_error_t lcb_confmon_start(lcb_confmon *mon)
{
    lcb_error_t err;


    if (mon->as_pause) {
        lcb_async_destroy(NULL, mon->as_pause);
        mon->as_pause = NULL;
    }

    if (mon->as_refresh || mon->is_refreshing) {
        LOG(mon, DEBUG, "Refresh already in progress...");
        return LCB_SUCCESS;
    }

    LOG(mon, TRACE, "Start refresh requested");
    lcb_assert(mon->cur_provider);
    mon->is_refreshing = 1;
    mon->as_refresh = lcb_async_create(mon->iot,
                                       mon, async_dispatch, &err);

    return err;
}

static void async_stop(lcb_timer_t tm, lcb_t instance, const void *cookie)
{
    lcb_confmon *mon = (lcb_confmon *)cookie;
    lcb_list_t *ii;

    lcb_async_destroy(instance, tm);
    mon->as_pause = NULL;

    LCB_LIST_FOR(ii, &mon->active_providers) {
        clconfig_provider *provider = LCB_LIST_ITEM(ii, clconfig_provider, ll);
        if (!provider->pause) {
            continue;
        }
        provider->pause(provider);
    }
}

lcb_error_t lcb_confmon_stop(lcb_confmon *mon)
{
    lcb_error_t err = LCB_SUCCESS;

    if (mon->tm_retry) {
        lcb_timer_destroy(NULL, mon->tm_retry);
        mon->tm_retry = NULL;
    }

    if (mon->as_refresh) {
        lcb_async_destroy(NULL, mon->as_refresh);
        mon->as_refresh = NULL;
    }

    if (!mon->as_pause) {
        mon->as_pause = lcb_async_create(mon->iot,
                                         mon,
                                         async_stop,
                                         &err);
    }

    mon->is_refreshing = 0;
    return err;
}

void lcb_clconfig_decref(clconfig_info *info)
{
    lcb_assert(info->refcount);

    if (--info->refcount) {
        return;
    }

    if (info->vbc) {
        vbucket_config_destroy(info->vbc);
    }

    lcb_string_release(&info->raw);

    free(info);
}

int lcb_clconfig_compare(const clconfig_info *a, const clconfig_info *b)
{
    if (a->cmpclock == b->cmpclock) {
        return 0;

    } else if (a->cmpclock < b->cmpclock) {
        return -1;
    }

    return 1;
}

clconfig_info * lcb_clconfig_create(VBUCKET_CONFIG_HANDLE config,
                                    lcb_string *raw,
                                    clconfig_method_t origin)
{
    clconfig_info *info = calloc(1, sizeof(*info));
    if (!info) {
        return NULL;
    }
    info->refcount = 1;
    info->vbc = config;
    if (raw) {
        lcb_string_transfer(raw, &info->raw);
    }
    info->origin = origin;
    return info;
}

static hostlist_t hosts_from_config(VBUCKET_CONFIG_HANDLE config)
{
    hostlist_t ret;
    int n_nodes = 0;
    int ii;
    int srvmax = vbucket_config_get_num_servers(config);

    if (srvmax < 1) {
        return NULL;
    }

    ret = hostlist_create();
    for (ii = 0; ii < srvmax; ii++) {
        const char *rest;
        rest = vbucket_config_get_rest_api_server(config, ii);
        if (hostlist_add_stringz(ret, rest, 8091) == LCB_SUCCESS) {
            n_nodes++;
        }
    }

    if (!n_nodes) {
        hostlist_destroy(ret);
    }

    return ret;

}

void lcb_confmon_set_nodes(lcb_confmon *mon,
                           hostlist_t nodes,
                           VBUCKET_CONFIG_HANDLE config)
{
    lcb_size_t ii;
    int is_allocated = 0;

    if (nodes == NULL) {
        nodes = hosts_from_config(config);
        if (nodes) {
            is_allocated = 1;
        }
    }

    for (ii = 0; ii < LCB_CLCONFIG_MAX; ii++) {
        clconfig_provider *provider = mon->all_providers[ii];
        if (provider == NULL || provider->enabled == 0) {
            continue;
        }
        if (provider->nodes_updated == NULL) {
            continue;
        }
        provider->nodes_updated(provider, nodes, config);
    }

    if (is_allocated) {
        hostlist_destroy(nodes);
    }
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

static void invoke_listeners(lcb_confmon *mon,
                             clconfig_event_t event,
                             clconfig_info *info)
{
    lcb_list_t *ll, *ll_next;
    LCB_LIST_SAFE_FOR(ll, ll_next, &mon->listeners) {
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
    clconfig_provider *provider = calloc(1, sizeof(*provider));
    provider->type = LCB_CLCONFIG_USER;
    provider->shutdown = generic_shutdown;

    (void)mon;
    return provider;
}

LCB_INTERNAL_API
int lcb_confmon_get_state(lcb_confmon *mon)
{
    int ret = 0;
    if (mon->is_refreshing || mon->as_refresh) {
        ret |= CONFMON_S_ACTIVE;
    }
    if (mon->tm_retry && lcb_timer_armed(mon->tm_retry)) {
        ret |= CONFMON_S_ITERGRACE;
    }
    return ret;
}
