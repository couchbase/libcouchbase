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

/**
 * This file contains the abstraction layer for a bucket configuration
 * provider.
 *
 * Included are routines for scheduling refreshes and the like.
 *
 * Previously this was tied to the instance; however we'll now make it
 * its own structure
 */

#include "internal.h"
#include "packetutils.h"
#include "bucketconfig/clconfig.h"

#define LOGARGS(instance, lvl) \
    &instance->settings, "bconf", LCB_LOG_##lvl, __FILE__, __LINE__

#define LOG(instance, lvl, msg) lcb_log(LOGARGS(instance, lvl), msg)

static int allocate_new_servers(lcb_t instance, clconfig_info *config);


/**
 * Callback functions called from libsasl to get the username to use for
 * authentication.
 *
 * @param context ponter to the lcb_t instance running the sasl bits
 * @param id the piece of information libsasl wants
 * @param result where to store the result (OUT)
 * @param len The length of the data returned (OUT)
 * @return SASL_OK if succes
 */
static int sasl_get_username(void *context, int id, const char **result,
                             unsigned int *len)
{
    lcb_t instance = context;
    if (!context || !result || (id != CBSASL_CB_USER && id != CBSASL_CB_AUTHNAME)) {
        return SASL_BADPARAM;
    }

    *result = instance->sasl.name;
    if (len) {
        *len = (unsigned int)strlen(*result);
    }

    return SASL_OK;
}

/**
 * Callback functions called from libsasl to get the password to use for
 * authentication.
 *
 * @param context ponter to the lcb_t instance running the sasl bits
 * @param id the piece of information libsasl wants
 * @param psecret where to store the result (OUT)
 * @return SASL_OK if succes
 */
static int sasl_get_password(cbsasl_conn_t *conn, void *context, int id,
                             cbsasl_secret_t **psecret)
{
    lcb_t instance = context;
    if (!conn || ! psecret || id != CBSASL_CB_PASS || instance == NULL) {
        return SASL_BADPARAM;
    }

    *psecret = &instance->sasl.password.secret;
    return SASL_OK;
}

static lcb_error_t setup_sasl_params(lcb_t instance)
{
    const char *passwd;
    cbsasl_callback_t sasl_callbacks[4];

    sasl_callbacks[0].id = CBSASL_CB_USER;
    sasl_callbacks[0].proc = (int( *)(void)) &sasl_get_username;
    sasl_callbacks[0].context = instance;
    sasl_callbacks[1].id = CBSASL_CB_AUTHNAME;
    sasl_callbacks[1].proc = (int( *)(void)) &sasl_get_username;
    sasl_callbacks[1].context = instance;
    sasl_callbacks[2].id = CBSASL_CB_PASS;
    sasl_callbacks[2].proc = (int( *)(void)) &sasl_get_password;
    sasl_callbacks[2].context = instance;
    sasl_callbacks[3].id = CBSASL_CB_LIST_END;
    sasl_callbacks[3].proc = NULL;
    sasl_callbacks[3].context = NULL;

    instance->sasl.name = instance->settings.username;
    memset(instance->sasl.password.buffer, 0,
           sizeof(instance->sasl.password.buffer));
    passwd = instance->settings.password;

    if (passwd) {
        unsigned long pwlen;
        lcb_size_t maxlen;

        pwlen = (unsigned long)strlen(passwd);
        maxlen = sizeof(instance->sasl.password.buffer) -
                 offsetof(cbsasl_secret_t, data);

        instance->sasl.password.secret.len = pwlen;

        if (pwlen < maxlen) {
            memcpy(instance->sasl.password.secret.data, passwd, pwlen);
        } else {
            return lcb_error_handler(instance, LCB_EINVAL, "Password too long");
        }
    }

    memcpy(instance->sasl.callbacks, sasl_callbacks, sizeof(sasl_callbacks));
    return LCB_SUCCESS;
}

static void relocate_packets(lcb_server_t *src, lcb_t dst_instance)
{
    packet_info pi;

    lcb_log(LOGARGS(dst_instance, DEBUG),
            "Relocating packets from %p [i=%d]",
            src, src->index);

    while (lcb_packet_read_ringbuffer(&pi, &src->cmd_log) > 0) {
        int idx;
        lcb_uint16_t vb = PACKET_REQ_VBID(&pi);
        lcb_server_t *dst;
        lcb_size_t nr;

        idx = vbucket_get_master(dst_instance->vbucket_config, vb);
        if (idx < 0) {
            idx = vbucket_found_incorrect_master(dst_instance->vbucket_config, vb, idx);
        }

        dst = dst_instance->servers + (lcb_size_t)idx;

        /* read from pending buffer first, because the only case so
         * far when we have cookies in both buffers is when we send
         * some commands to disconnected server (it will put them into
         * pending buffer/cookies and also copy into log), after that
         * SASL authenticator runs, and push its packets to output
         * buffer/cookies and also copy into log.
         *
         * Here we are traversing the log only. Therefore we will see
         * pending commands first.
         *
         * TODO it will be simplified when with the packet-oriented
         * commands patch, where cookies will live along with command
         * itself in the log
         */
        if (src->pending_cookies.nbytes) {
            nr = ringbuffer_read(&src->pending_cookies, &pi.ct, sizeof(pi.ct));
        } else {
            nr = ringbuffer_read(&src->output_cookies, &pi.ct, sizeof(pi.ct));
        }

        lcb_assert(nr == sizeof(pi.ct));

        lcb_server_start_packet_ex(dst, &pi.ct, &pi.res, sizeof(pi.res));
        if (PACKET_NBODY(&pi)) {
            lcb_server_write_packet(dst, pi.payload, PACKET_NBODY(&pi));
        }
        lcb_server_end_packet(dst);
        lcb_packet_release_ringbuffer(&pi, &src->cmd_log);
    }
}

/**
 * CONFIG REPLACEMENT AND PACKET RELOCATION.
 *
 * When we receive any sort of configuration update, all connections to all
 * servers are immediately reset, and a new server array is allocated with
 * new server structures.
 *
 * Before the old servers are destroyed, their buffers are relocated like so:
 * SRC->PENDING -> DST->PENDING
 * SRC->SENT    -> DST->PENDING
 * SRC->COOKIES -> DST->PENDING_COOKIES
 *
 * where 'src' is the old server struct, and 'dst' is the new server struct
 * which is the vBucket master for a given packet..
 *
 * When each server has connected, the code
 * (server.c, lcb_server_connected) will move the pending commands over to the
 * output commands.
 */

static int replace_config(lcb_t instance, clconfig_info *old_config,
                          clconfig_info *next_config)
{
    VBUCKET_CONFIG_DIFF *diff;
    VBUCKET_DISTRIBUTION_TYPE dist_t;

    lcb_size_t ii, old_nservers;
    lcb_server_t *old_servers;

    diff = vbucket_compare(old_config->vbc, next_config->vbc);
    if (diff == NULL ||
            (diff->sequence_changed == 0 && diff->n_vb_changes == 0)) {
        lcb_log(LOGARGS(instance, DEBUG),
            "Ignoring config update. No server changes; DIFF=%p", diff);
        vbucket_free_diff(diff);
        return LCB_CONFIGURATION_UNCHANGED;
    }

    old_nservers = instance->nservers;
    old_servers = instance->servers;
    dist_t = vbucket_config_get_distribution_type(next_config->vbc);
    vbucket_free_diff(diff);

    if (allocate_new_servers(instance, next_config) != 0) {
        return -1;
    }

    for (ii = 0; ii < old_nservers; ++ii) {
        lcb_server_t *ss = old_servers + ii;

        if (dist_t == VBUCKET_DISTRIBUTION_VBUCKET) {
            relocate_packets(ss, instance);

        } else {
            lcb_failout_server(ss, LCB_CLIENT_ETMPFAIL);
        }

        lcb_server_destroy(ss);
    }

    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t *ss = instance->servers + ii;
        if (ss->cmd_log.nbytes != 0) {
            lcb_server_send_packets(ss);
        }
    }

    free(old_servers);
    return LCB_CONFIGURATION_CHANGED;
}


static int allocate_new_servers(lcb_t instance, clconfig_info *config)
{
    lcb_size_t ii;

    instance->nservers = vbucket_config_get_num_servers(config->vbc);
    instance->servers = calloc(instance->nservers, sizeof(*instance->servers));
    if (!instance->servers) {
        return -1;
    }

    if (setup_sasl_params(instance) != LCB_SUCCESS) {
        return -1;
    }

    for (ii = 0; ii < instance->nservers; ii++) {
        lcb_server_t *cur = instance->servers + ii;
        cur->instance = instance;
        if (lcb_server_initialize(cur, ii) != LCB_SUCCESS) {
            return -1;
        }
    }

    return 0;
}

void lcb_update_vbconfig(lcb_t instance, clconfig_info *config)
{
    lcb_size_t ii;
    int change_status;
    clconfig_info *old_config;

    old_config = instance->cur_configinfo;
    instance->cur_configinfo = config;
    instance->dist_type = vbucket_config_get_distribution_type(config->vbc);
    instance->vbucket_config = config->vbc;
    lcb_clconfig_incref(config);

    instance->nreplicas =
            (lcb_uint16_t)vbucket_config_get_num_replicas(config->vbc);

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
    if (instance->vbucket_state_listener != NULL) {
        for (ii = 0; ii < instance->nservers; ++ii) {
            instance->vbucket_state_listener(instance->servers + ii);
        }
    }

    instance->callbacks.configuration(instance, change_status);
    lcb_maybe_breakout(instance);
}
