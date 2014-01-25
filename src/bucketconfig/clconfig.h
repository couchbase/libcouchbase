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

#ifndef LCB_CLCONFIG_H
#define LCB_CLCONFIG_H

#include "hostlist.h"
#include "list.h"
#include "simplestring.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This module attempts to implement the 'Configuration Provider' interface
 * described at https://docs.google.com/document/d/1bSMt0Sj1uQtm0OYolQaJDJg4sASfoCEwU6_gjm1he8s/edit
 *
 * The model is fairly complex though significantly more maintainable and
 * testable than the previous model. The basic idea is as follows:
 *
 * (1) There is a 'Configuration Monitor' object (i.e. 'confmon') which acts
 * as the configuration supervisor. It is responsible for returning
 * configuration objects to those entities which request it.
 *
 * (2) There are multiple 'Configuration Provider' objects. These providers
 * aggregate configurations from multiple sources and implement a common
 * interface to:
 *  I. Return a 'quick' configuration - i.e. any cached configuration:
 *      get_cached()
 *
 *  II. Schedule a refresh to retrieve the latest configuration:
 *      refresh()
 *
 *  III. Notify the monitor that it has received a new configuration. The
 *  monitor itself will determine whether or not to accept the new
 *  configuration:
 *      confmon_set_next()
 *
 * (3) Configuration Info objects. These objects are refcounted wrappers
 * around vbucket configuration handles. They have a refcount and also an
 * integer which can be used to compare with other objects for 'freshness'.
 *
 * (4) Configuration Listeners. These are registered with the global supervisor
 * and are invoked whenever a new valid configuration is detected. This is
 * really only ever used during bootstrap or testing where we are explicitly
 * waiting for a configuration without having any actual commands to schedule.
 */

/**
 * The type of methods available. These are enumerated in order of preference
 */
typedef enum {
    LCB_CLCONFIG_USER,
    LCB_CLCONFIG_FILE,
    LCB_CLCONFIG_CCCP,
    LCB_CLCONFIG_HTTP,
    LCB_CLCONFIG_MAX,

    LCB_CLCONFIG_PHONY
} clconfig_method_t;


struct clconfig_info_st;
struct clconfig_provider_st;
struct clconfig_listener_st;
struct lcb_confmon_st;

/**
 * This object contains the information needed for libcouchbase to deal with
 * when retrieving new configs.
 */
typedef struct lcb_confmon_st {
    lcb_list_t active_providers;
    struct clconfig_provider_st *cur_provider;
    struct clconfig_provider_st * all_providers[LCB_CLCONFIG_MAX];
    struct clconfig_info_st * config;
    int is_refreshing;
    lcb_timer_t tm_retry;
    lcb_async_t as_refresh;
    lcb_async_t as_pause;
    lcb_list_t listeners;
    lcb_settings *settings;
    lcb_error_t last_error;
} lcb_confmon;

/**
 * The base structure of a provider. This structure is intended to be
 * 'subclassed' by implementors.
 */
typedef struct clconfig_provider_st {
    lcb_list_t ll;

    /** The type of provider */
    clconfig_method_t type;

    /** Whether this provider has been disabled explicitly by a user */
    int enabled;

    /** The parent manager object */
    struct lcb_confmon_st *parent;

    /**
     * Get the current map known to this provider. This should not perform
     * any blocking operations. Providers which use a push model may use
     * this method as an asynchronous return value for a previously-received
     * configuration.
     */
    struct clconfig_info_st* (*get_cached)(struct clconfig_provider_st *);


    /**
     * Request a new configuration. This will be called by the manager when
     * the cached configuration (i.e. 'get_cached') is deemed invalid. Thus
     * this function should unconditionally try to schedule getting the
     * newest configuration it can. When the configuration has been received,
     * the provider may call set_next_config.
     */
    lcb_error_t (*refresh)(struct clconfig_provider_st *);

    lcb_error_t (*pause)(struct clconfig_provider_st *);

    /**
     * Called to update the list of new nodes.
     * @param provider the provider instance
     * @param curr_config the current configuration.
     * Note that this should only update the server list and do nothing
     * else.
     */
    void (*nodes_updated)(struct clconfig_provider_st *,
                           hostlist_t,
                           VBUCKET_CONFIG_HANDLE);

    /** Destroy the resources created by this provider. */
    void (*shutdown)(struct clconfig_provider_st *);
} clconfig_provider;



typedef struct clconfig_info_st {
    /** Actual configuration */
    VBUCKET_CONFIG_HANDLE vbc;

    /** Comparative clock with which to compare */
    lcb_uint64_t cmpclock;

    /** Reference counter */
    unsigned int refcount;

    /** Origin provider type which produced this config */
    clconfig_method_t origin;

    /** Raw text of the config */
    lcb_string raw;
} clconfig_info;

typedef struct clconfig_listener_st {
    /** Linked list node */
    lcb_list_t ll;

    /** Monitor object */
    lcb_confmon *parent;

    /** Callback to be invoked */
    void (*callback)(struct clconfig_info_st *, struct clconfig_listener_st *);
} clconfig_listener;

/** Method-specific setup methods.. */
clconfig_provider * lcb_clconfig_create_http(lcb_confmon *mon);
clconfig_provider * lcb_clconfig_create_cccp(lcb_confmon *mon);
clconfig_provider * lcb_clconfig_create_file(lcb_confmon *mon);
clconfig_provider * lcb_clconfig_create_user(lcb_confmon *mon);

/** Get a provider by its type. */
#define lcb_confmon_get_provider(mon, ix) (mon)->all_providers[ix]

#define PROVIDER_SETTING(p, n) ((p)->parent->settings->n)

/**
 * Create a new configuration monitor server.
 */
LIBCOUCHBASE_API
lcb_confmon * lcb_confmon_create(lcb_settings *settings);

/**
 * Compares two info structures. This function returns an integer less than
 * zero, zero or greater than zero if the first argument is considered older
 * than, equal to, or later than the second argument.
 */
LIBCOUCHBASE_API
int lcb_clconfig_compare(const clconfig_info *a, const clconfig_info *b);


/**
 * Prepares the configuration monitor object. Currently this adds all the
 *
 */
LIBCOUCHBASE_API
void lcb_confmon_prepare(lcb_confmon *mon);

LIBCOUCHBASE_API
void lcb_confmon_destroy(lcb_confmon *mon);

/**
 * CB SAFE.
 *
 * Starts the monitor.
 */
LIBCOUCHBASE_API
lcb_error_t lcb_confmon_start(lcb_confmon *mon);

/**
 * CB SAFE.
 * Stops the monitor. This causes any pending network operations to be
 * cancelled. This should be called either before destruction or when a
 * desirable configuration has been found.
 */
LIBCOUCHBASE_API
lcb_error_t lcb_confmon_stop(lcb_confmon *mon);

/** Get the most recent configuration */
#define lcb_confmon_get_config(mon) (mon)->config

#define lcb_confmon_last_error(mon) (mon)->last_error

/**
 * NOT-CB-SAFE
 *
 * Sets the next configuration. If the next configuration is more recent than
 * the current configuration (or force is specified) then the current refresh
 * operation will stop. The next provider will be returned via
 * lcb_confmon_get_current().
 *
 * @param mon the monitor to use
 * @param info the new configuration info.
 * @param force whether to unconditionally set info as next config
 * @return true if the config was set, false otherwise.
 */
LIBCOUCHBASE_API
int lcb_confmon_set_next(lcb_confmon *mon, clconfig_info *info, int force);

/**
 * NOT-CB-SAFE
 *
 * Indicate that the current provider has failed to obtain a new configuration.
 * This is always called by a provider and may either be invoked after
 * set_next() returns false or if an explicit error was encountered.
 */
LIBCOUCHBASE_API
void lcb_confmon_provider_failed(clconfig_provider *provider,
                                 lcb_error_t err);

/**
 * Update a new set of nodes
 * @param mon the monitor object
 * @param nodes a list of updated nodes
 * @param config an optional configuration object from which the nodes were
 * derived. May be NULL.
 */
LIBCOUCHBASE_API
void lcb_confmon_set_nodes(lcb_confmon *mon,
                           hostlist_t nodes,
                           VBUCKET_CONFIG_HANDLE config);



/**
 * Adds a 'listener' object to be called at each configuration update. The
 * listener may co-exist with other listeners (though it should never be added
 * twice). When a new configuration is received and accept, the listener's
 * "callback" field will be invoked with it.
 *
 * The callback will continue to be invoked for each new configuration received
 * until remove_listener is called. Note that the listener is not allocated
 * by the confmon and its responsibility is the user's
 */
LIBCOUCHBASE_API
void lcb_confmon_add_listener(lcb_confmon *mon, clconfig_listener *listener);

/**
 * Remove a listener added via 'add_listener'.
 */
LIBCOUCHBASE_API
void lcb_confmon_remove_listener(lcb_confmon *mon, clconfig_listener *listener);

/**
 * Creates a new configuration wrapper object containing the vbucket config
 * pointed to by 'config'. Its initial refcount will be set to 1.
 *
 * @param config a newly parsed configuration
 * @param raw (optional) the raw buffer used for the config
 * @param origin the type of provider from which the config originated.
 */
clconfig_info * lcb_clconfig_create(VBUCKET_CONFIG_HANDLE config,
                                    lcb_string *raw,
                                    clconfig_method_t origin);

/**
 * Decrement the refcount. If the internal refcount reaches 0 then the internal
 * members (including the vbucket config handle itself) will be freed.
 */
void lcb_clconfig_decref(clconfig_info *info);
#define lcb_clconfig_incref(info) (info)->refcount++

/**
 * Sets the input/output filename for the file provider. This also enables
 * the file provider.
 */
int lcb_clconfig_file_set_filename(clconfig_provider *p, const char *f);

/**
 * Writes the configuration data within 'data' to the file in the provider.
 * If the file provider is not enabled, this does nothing.
 */
void lcb_clconfig_write_file(clconfig_provider *provider_base, lcb_string *data);

/**
 * Get the REST connection object.
 */
struct lcb_connection_st* lcb_confmon_get_rest_connection(lcb_confmon *mon);

lcb_host_t * lcb_confmon_get_rest_host(lcb_confmon *mon);

/** CCCP Routines */
LCB_INTERNAL_API
void lcb_clconfig_cccp_set_nodes(clconfig_provider *pb, hostlist_t mcnodes);
lcb_error_t lcb_cccp_update(clconfig_provider *provider, const char *host,
                            lcb_string *data);
void lcb_clconfig_cccp_disable(clconfig_provider *provider);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* LCB_CLCONFIG_H */
