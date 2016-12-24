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

#define LCB_BOOTSTRAP_DEFINE_STRUCT 1
#include "internal.h"


#define LOGARGS(instance, lvl) instance->settings, "bootstrap", LCB_LOG_##lvl, __FILE__, __LINE__
static void initial_bootstrap_error(lcb_t, lcb_error_t,const char*);

using lcb::clconfig::EventType;
using lcb::clconfig::ConfigInfo;

/**
 * This function is where the configuration actually takes place. We ensure
 * in other functions that this is only ever called directly from an event
 * loop stack frame (or one of the small mini functions here) so that we
 * don't accidentally end up destroying resources underneath us.
 */
void lcb_BOOTSTRAP::config_callback(EventType event, ConfigInfo *info) {
    using namespace lcb::clconfig;
    lcb_t instance = parent;

    if (event != CLCONFIG_EVENT_GOT_NEW_CONFIG) {
        if (event == CLCONFIG_EVENT_PROVIDERS_CYCLED) {
            if (!LCBT_VBCONFIG(instance)) {
                initial_bootstrap_error(
                    instance, LCB_ERROR, "No more bootstrap providers remain");
            }
        }
        return;
    }

    instance->last_error = LCB_SUCCESS;

    /** Ensure we're not called directly twice again */
    configcb_indirect = true;
    lcbio_timer_disarm(tm);

    lcb_log(LOGARGS(instance, DEBUG), "Instance configured!");

    if (info->get_origin() != CLCONFIG_FILE) {
        /* Set the timestamp for the current config to control throttling,
         * but only if it's not an initial file-based config. See CCBC-482 */
        last_refresh = gethrtime();
        errcounter = 0;
    }

    if (info->get_origin() == CLCONFIG_CCCP) {
        /* Disable HTTP provider if we've received something via CCCP */

        if (instance->cur_configinfo == NULL ||
                instance->cur_configinfo->get_origin() != CLCONFIG_HTTP) {
            /* Never disable HTTP if it's still being used */
            instance->confmon->set_active(CLCONFIG_HTTP, false);
        }
    }

    if (instance->type != LCB_TYPE_CLUSTER) {
        lcb_update_vbconfig(instance, info);
    }

    if (!bootstrapped) {
        bootstrapped = true;
        lcb_aspend_del(&instance->pendops, LCB_PENDTYPE_COUNTER, NULL);

        if (instance->type == LCB_TYPE_BUCKET &&
                LCBVB_DISTTYPE(LCBT_VBCONFIG(instance)) == LCBVB_DIST_KETAMA &&
                instance->cur_configinfo->get_origin() != CLCONFIG_MCRAW) {

            lcb_log(LOGARGS(instance, INFO), "Reverting to HTTP Config for memcached buckets");
            instance->settings->bc_http_stream_time = -1;
            instance->confmon->set_active(CLCONFIG_HTTP, true);
            instance->confmon->set_active(CLCONFIG_CCCP, false);
        }
        instance->callbacks.bootstrap(instance, LCB_SUCCESS);
    }

    lcb_maybe_breakout(instance);
}


static void
initial_bootstrap_error(lcb_t instance, lcb_error_t err, const char *errinfo)
{
    struct lcb_BOOTSTRAP *bs = instance->bootstrap;

    instance->last_error = instance->confmon->get_last_error();
    if (instance->last_error == LCB_SUCCESS) {
        instance->last_error = err;
    }
    instance->callbacks.error(instance, instance->last_error, errinfo);
    lcb_log(LOGARGS(instance, ERR), "Failed to bootstrap client=%p. Code=0x%x, Message=%s", (void *)instance, err, errinfo);
    lcbio_timer_disarm(bs->tm);

    instance->callbacks.bootstrap(instance, instance->last_error);

    lcb_aspend_del(&instance->pendops, LCB_PENDTYPE_COUNTER, NULL);
    lcb_maybe_breakout(instance);
}

/**
 * This it the initial bootstrap timeout handler. This timeout pins down the
 * instance. It is only scheduled during the initial bootstrap and is only
 * triggered if the initial bootstrap fails to configure in time.
 */
static void initial_timeout(void *arg)
{
    struct lcb_BOOTSTRAP *bs = reinterpret_cast<lcb_BOOTSTRAP*>(arg);
    initial_bootstrap_error(bs->parent, LCB_ETIMEDOUT, "Failed to bootstrap in time");
}

/**
 * Proxy async call to config_callback
 */
static void async_refresh(void *arg)
{
    /** Get the best configuration and run stuff.. */
    lcb_BOOTSTRAP *bs = reinterpret_cast<lcb_BOOTSTRAP*>(arg);
    clconfig_info *info;

    info = bs->parent->confmon->get_config();
    bs->config_callback(lcb::clconfig::CLCONFIG_EVENT_GOT_NEW_CONFIG, info);
}

/**
 * set_next listener callback which schedules an async call to our config
 * callback.
 */
void
lcb_BOOTSTRAP::schedule_config_callback(lcb::clconfig::EventType event) {
    if (event != lcb::clconfig::CLCONFIG_EVENT_GOT_NEW_CONFIG) {
        return;
    }

    if (lcbio_timer_armed(tm) && lcbio_timer_get_target(tm) == async_refresh) {
        lcb_log(LOGARGS(parent, DEBUG), "Timer already present..");
        return;
    }

    lcb_log(LOGARGS(parent, INFO), "Got async step callback..");
    lcbio_timer_set_target(tm, async_refresh);
    lcbio_async_signal(tm);
}

lcb_BOOTSTRAP::lcb_BOOTSTRAP(lcb_t instance)
    : parent(instance),
      tm(lcbio_timer_new(parent->iotable, this, initial_timeout)),
      last_refresh(0),
      errcounter(0),
      bootstrapped(false),
      configcb_indirect(false) {
}

lcb_error_t
lcb_bootstrap_common(lcb_t instance, int options)
{
    struct lcb_BOOTSTRAP *bs = instance->bootstrap;
    hrtime_t now = gethrtime();

    if (!bs) {
        bs = new lcb_BOOTSTRAP(instance);
        instance->bootstrap = bs;
        instance->confmon->add_listener(bs);
    }

    if (instance->confmon->is_refreshing()) {
        return LCB_SUCCESS;
    }

    if (options & LCB_BS_REFRESH_THROTTLE) {
        /* Refresh throttle requested. This is not true if options == ALWAYS */
        hrtime_t next_ts;
        unsigned errthresh = LCBT_SETTING(instance, weird_things_threshold);

        if (options & LCB_BS_REFRESH_INCRERR) {
            bs->errcounter++;
        }
        next_ts = bs->last_refresh;
        next_ts += LCB_US2NS(LCBT_SETTING(instance, weird_things_delay));
        if (now < next_ts && bs->errcounter < errthresh) {
            lcb_log(LOGARGS(instance, INFO),
                "Not requesting a config refresh because of throttling parameters. Next refresh possible in %ums or %u errors. "
                "See LCB_CNTL_CONFDELAY_THRESH and LCB_CNTL_CONFERRTHRESH to modify the throttling settings",
                LCB_NS2US(next_ts-now)/1000, (unsigned)errthresh-bs->errcounter);
            return LCB_SUCCESS;
        }
    }

    if (options == LCB_BS_REFRESH_INITIAL) {
        bs->configcb_indirect = false;
        instance->confmon->prepare();
        lcbio_timer_set_target(bs->tm, initial_timeout);
        lcbio_timer_rearm(bs->tm, LCBT_SETTING(instance, config_timeout));
        lcb_aspend_add(&instance->pendops, LCB_PENDTYPE_COUNTER, NULL);
    }

    /* Reset the counters */
    bs->errcounter = 0;
    if (options != LCB_BS_REFRESH_INITIAL) {
        bs->last_refresh = now;
    }
    instance->confmon->start();
    return LCB_SUCCESS;
}

lcb_BOOTSTRAP::~lcb_BOOTSTRAP() {
    if (tm) {
        lcbio_timer_destroy(tm);
    }
}

void lcb_bootstrap_destroy(lcb_t instance)
{
    struct lcb_BOOTSTRAP *bs = instance->bootstrap;
    if (!bs) {
        return;
    }
    instance->confmon->remove_listener(bs);
    instance->bootstrap = NULL;
    delete bs;
}

LIBCOUCHBASE_API
lcb_error_t
lcb_get_bootstrap_status(lcb_t instance)
{
    if (instance->cur_configinfo) {
        return LCB_SUCCESS;
    }
    if (instance->last_error != LCB_SUCCESS) {
        return instance->last_error;
    }
    if (instance->type == LCB_TYPE_CLUSTER) {
        if (lcb::clconfig::http_get_conn(instance->confmon) != NULL) {
            return LCB_SUCCESS;
        }
    }
    return LCB_ERROR;
}

LIBCOUCHBASE_API
void
lcb_refresh_config(lcb_t instance)
{
    lcb_bootstrap_common(instance, LCB_BS_REFRESH_ALWAYS);
}
