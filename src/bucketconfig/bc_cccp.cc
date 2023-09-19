/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014-2020 Couchbase, Inc.
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
 * This file contains the CCCP (Cluster Carrier Configuration Protocol)
 * implementation of the confmon provider. It utilizes a memcached connection
 * to retrieve configuration information.
 */

#include "internal.h"
#include "clconfig.h"
#include "packetutils.h"
#include <mcserver/negotiate.h>
#include <lcbio/lcbio.h>
#include <lcbio/timer-cxx.h>
#include <lcbio/ssl.h>
#include "ctx-log-inl.h"
#include "mc/compress.h"

#include <stdio.h>

#define LOGFMT CTX_LOGFMT
#define LOGID(p) CTX_LOGID(p->ioctx)
#define LOGARGS(cccp, lvl) cccp->parent->settings, "cccp", LCB_LOG_##lvl, __FILE__, __LINE__

struct CccpCookie;

using namespace lcb::clconfig;

struct CccpProvider : public Provider {
    explicit CccpProvider(Confmon *);
    ~CccpProvider() override;

    /**
     * Stops the current request.
     * @param is_clean Whether the state of the current request is 'clean',
     *        i.e. whether we are stopping because of an error condition, or
     *        because we have received a successful response.
     */
    void stop_current_request(bool is_clean);
    lcb_STATUS schedule_next_request(lcb_STATUS err, bool can_rollover, bool skip_if_push_supported);
    lcb_STATUS expect_config_with_version(const lcb_host_t *origin, config_version version);
    lcb_STATUS mcio_error(lcb_STATUS err);
    void on_timeout()
    {
        mcio_error(LCB_ERR_TIMEOUT);
    }
    lcb_STATUS update(const char *host, const std::string &config_json);
    void request_config();
    void on_io_read();

    bool pause() override;
    void configure_nodes(const lcb::Hostlist &) override;
    void config_updated(lcbvb_CONFIG *) override;
    void dump(FILE *) const override;
    lcb_STATUS refresh(unsigned options = 0) override;

    ConfigInfo *get_cached() override
    {
        return config;
    }

    const lcb::Hostlist *get_nodes() const override
    {
        return nodes;
    }

    void enable(void *arg) override
    {
        instance = reinterpret_cast<lcb_INSTANCE *>(arg);
        Provider::enable();
    }

    // Whether there is a pending CCCP config request.
    bool has_pending_request() const
    {
        return creq != nullptr || cmdcookie != nullptr || ioctx != nullptr;
    }

    lcb::Hostlist *nodes;
    ConfigInfo *config;
    lcb::io::Timer<CccpProvider, &CccpProvider::on_timeout> timer;
    lcb_INSTANCE *instance;
    lcb::io::ConnectionRequest *creq{};
    lcbio_CTX *ioctx;
    CccpCookie *cmdcookie;
    /*
     * The version, that the library has seen in the notifications, but hasn't fetched yet.
     *
     * For example, if KV engine sends clustermap notification while this config provider is waiting for response, the
     * version number from the notification will be recorded here, and once the current operation will be completed, the
     * provider will make new request if the expected version is newer than the current one.
     */
    config_version expected_config_version{-1, -1};
};

struct CccpCookie {
    CccpProvider *parent;
    bool active;
    lcb_STATUS select_rc;
    int refcnt{0};
    explicit CccpCookie(CccpProvider *parent_) : parent(parent_), active(true), select_rc(LCB_SUCCESS) {}

    void incref()
    {
        ++refcnt;
    }

    void decref()
    {
        --refcnt;
        if (refcnt <= 0) {
            delete this;
        }
    }
};

static void io_error_handler(lcbio_CTX *, lcb_STATUS);
static void io_read_handler(lcbio_CTX *, unsigned nr);
static void on_connected(lcbio_SOCKET *, void *, lcb_STATUS, lcbio_OSERR);

static void pooled_close_cb(lcbio_SOCKET *sock, int reusable, void *arg)
{
    bool *ru_ex = reinterpret_cast<bool *>(arg);
    lcbio_ref(sock);
    if (reusable && *ru_ex) {
        lcb::io::Pool::put(sock);
    } else {
        lcb::io::Pool::discard(sock);
    }
}

void CccpProvider::stop_current_request(bool is_clean)
{
    if (cmdcookie) {
        cmdcookie->active = false;
        cmdcookie = nullptr;
    }

    lcb::io::ConnectionRequest::cancel(&creq);

    if (ioctx) {
        lcbio_ctx_close(ioctx, pooled_close_cb, &is_clean);
        ioctx = nullptr;
    }
}

/**
 * Tell the provider that the newer configuration might be existing on the server side.
 *
 * If there is no request in-flight, the library will do PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG (0xb5) immediately,
 * otherwise update internal state with the version number and return;
 *
 * @param origin the hostname of the connection that was notification about configuration update
 * @param requested the version of the configuration from the KV notification
 * @return
 */
lcb_STATUS CccpProvider::expect_config_with_version(const lcb_host_t *origin, config_version requested)
{
    auto current = parent->get_current_version();
    auto previous_expected = expected_config_version;
    if (expected_config_version < requested) {
        expected_config_version = requested;
    }
    if (current < expected_config_version) {
        /*
         * The requested version is newer than we've seen so far (both current and previously requested)
         */
        if (has_pending_request()) {
            /*
             * Only one configuration request could be in-flight, but the version is stored in expected_config_version
             * already and will be checked once current request completes.
             */
            lcb_log(LOGARGS(this, DEBUG),
                    "Configuration request is in flight " LCB_HOST_FMT ": expected=%" PRId64 ":%" PRId64
                    ", current=%" PRId64 ":%" PRId64 ", requested=%" PRId64 ":%" PRId64,
                    LCB_HOST_ARG(parent->settings, origin), previous_expected.epoch, previous_expected.revision,
                    current.epoch, current.revision, requested.epoch, requested.revision);
            return LCB_SUCCESS;
        }
        /*
         * Request new configuration immediately
         */
        return schedule_next_request(LCB_SUCCESS, /* can_rollover */ true, /* skip_if_push_supported */ false);
    } else {
        /*
         * The config provider already seen this revision and probably already applied it and using as the current.
         */
        lcb_log(LOGARGS(this, TRACE),
                "Ignore configuration request " LCB_HOST_FMT ": expected=%" PRId64 ":%" PRId64 ", current=%" PRId64
                ":%" PRId64 ", requested=%" PRId64 ":%" PRId64 ", has_pending_request=%d",
                LCB_HOST_ARG(parent->settings, origin), previous_expected.epoch, previous_expected.revision,
                current.epoch, current.revision, requested.epoch, requested.revision, has_pending_request());
    }
    return LCB_SUCCESS;
}

lcb_STATUS CccpProvider::schedule_next_request(lcb_STATUS err, bool can_rollover, bool skip_if_push_supported)
{
    if (nodes->empty()) {
        timer.cancel();
        parent->provider_failed(this, err);
        return err;
    }

    if (skip_if_push_supported && nodes->all_hosts_support_config_push()) {
        /* all nodes support configuration push, and this function invoked from periodic poller, so nothing has to be
         * done here */
        parent->mode = CONFMON_M_PUSH;
        parent->stop();
        return LCB_SUCCESS;
    }

    lcb::Server *server{nullptr};
    lcb_host_t *next_host = nodes->next(can_rollover, skip_if_push_supported);
    if (!next_host) {
        timer.cancel();
        parent->provider_failed(this, err);
        return err;
    }

    do {
        /* try to find connected socket that corresponds the hostname */
        server = instance->find_server(*next_host);
        if (server != nullptr && server->supports_config_push()) {
            /* mark the address in the list, that it supports configuration push, so that it could be skipped later */
            next_host->supports_config_push = true;
            if (skip_if_push_supported) {
                next_host = nodes->next(can_rollover, skip_if_push_supported);
            } else {
                break;
            }
        } else {
            break;
        }
    } while (next_host != nullptr);

    /* there is no connected sockets */
    if (server != nullptr) {
        if (skip_if_push_supported && server->supports_config_push()) {
            /* we found the server, but at the same time all sockets support push, so we can stop polling and just
             * expect notifications from KV engine */
            lcb_log(LOGARGS(this, DEBUG), "Stop background polling, as all nodes support configuration push");
            parent->mode = CONFMON_M_PUSH;
            parent->stop();
            return LCB_SUCCESS;
        }

        cmdcookie = new CccpCookie(this);
        lcb_log(LOGARGS(this, TRACE), "Re-Issuing CCCP Command on server struct %p (" LCB_HOST_FMT ")", (void *)server,
                LCB_HOST_ARG(this->parent->settings, next_host));
        timer.rearm(settings().config_node_timeout);
        if (settings().bucket && settings().bucket[0] != '\0' && !server->selected_bucket) {
            cmdcookie->incref();
            instance->select_bucket(cmdcookie, server);
        }
        cmdcookie->incref();
        instance->request_config(cmdcookie, server, parent->get_current_version());

    } else {
        /* initiate new connection */
        lcb_log(LOGARGS(this, INFO), "Requesting connection to node " LCB_HOST_FMT " for CCCP configuration",
                LCB_HOST_ARG(this->parent->settings, next_host));
        creq = instance->memd_sockpool->get(*next_host, settings().config_node_timeout, on_connected, this);
    }

    return LCB_SUCCESS;
}

lcb_STATUS CccpProvider::mcio_error(lcb_STATUS err)
{
    if (err != LCB_ERR_UNSUPPORTED_OPERATION) {
        lcb_log(LOGARGS(this, ERR), LOGFMT "Could not get configuration: %s", LOGID(this), lcb_strerror_short(err));
    }

    stop_current_request(err == LCB_ERR_UNSUPPORTED_OPERATION);
    if (err == LCB_ERR_PROTOCOL_ERROR && LCBT_SETTING(instance, conntype) == LCB_TYPE_CLUSTER) {
        lcb_log(LOGARGS(this, WARN), LOGFMT "Failed to bootstrap using CCCP", LOGID(this));
        timer.cancel();
        parent->provider_failed(this, err);
        return err;
    } else {
        return schedule_next_request(err, /* can_rollover */ false, /* skip_if_push_supported */ false);
    }
}

/** Update the configuration from a server. */
lcb_STATUS lcb::clconfig::cccp_update(Provider *provider, const char *host, const std::string &config_json)
{
    return static_cast<CccpProvider *>(provider)->update(host, config_json);
}

lcb_STATUS lcb::clconfig::schedule_get_config(Provider *provider, const lcb_host_t *origin, config_version version)
{
    if (provider->type != CLCONFIG_CCCP) {
        return LCB_ERR_INVALID_ARGUMENT;
    }
    return static_cast<CccpProvider *>(provider)->expect_config_with_version(origin, version);
}

lcb_STATUS lcb::clconfig::schedule_get_config(Provider *provider)
{
    if (provider->type != CLCONFIG_CCCP) {
        return LCB_ERR_INVALID_ARGUMENT;
    }
    return static_cast<CccpProvider *>(provider)->schedule_next_request(LCB_SUCCESS, /* can_rollover */ true,
                                                                        /* skip_if_push_supported */ false);
}

lcb_STATUS CccpProvider::update(const char *host, const std::string &config_json)
{
    if (config_json.empty()) {
        // ignore empty payloads, in case of brief mode
        parent->stop();
        return LCB_SUCCESS;
    }
    lcbvb_CONFIG *vbc;
    int rv;
    ConfigInfo *new_config;
    vbc = lcbvb_create();

    if (!vbc) {
        return LCB_ERR_NO_MEMORY;
    }
    rv = lcbvb_load_json_ex(vbc, config_json.c_str(), host, &LCBT_SETTING(this->parent, network));

    if (rv) {
        lcb_log(LOGARGS(this, ERROR), LOGFMT "Failed to parse config", LOGID(this));
        lcb_log_badconfig(LOGARGS(this, ERROR), vbc, config_json.c_str());
        lcbvb_destroy(vbc);
        return LCB_ERR_PROTOCOL_ERROR;
    }

    lcbvb_replace_host(vbc, host);
    new_config = ConfigInfo::create(vbc, CLCONFIG_CCCP, host);

    if (!new_config) {
        lcbvb_destroy(vbc);
        return LCB_ERR_NO_MEMORY;
    }

    if (config) {
        config->decref();
    }

    /** TODO: Figure out the comparison vector */
    config = new_config;
    parent->provider_got_config(this, new_config);

    if (parent->get_current_version() < expected_config_version) {
        return schedule_next_request(LCB_SUCCESS, /* can_rollover */ true, /* skip_if_push_supported */ false);
    }
    return LCB_SUCCESS;
}

void lcb::clconfig::select_status(const void *cookie_, lcb_STATUS err)
{
    auto *cookie = reinterpret_cast<CccpCookie *>(const_cast<void *>(cookie_));
    cookie->select_rc = err;
    cookie->decref();
}

void lcb::clconfig::cccp_update(const void *cookie_, lcb_STATUS err, const lcb_host_t *origin,
                                const std::string &config_json)
{
    auto *cookie = reinterpret_cast<CccpCookie *>(const_cast<void *>(cookie_));
    CccpProvider *cccp = cookie->parent;

    lcb_STATUS select_rc = cookie->select_rc;
    bool was_active = cookie->active;
    if (cookie->active) {
        cookie->active = false;
        cccp->timer.cancel();
        cccp->cmdcookie = nullptr;
    }
    cookie->decref();

    if (select_rc != LCB_SUCCESS) {
        cccp->mcio_error(select_rc);
        return;
    }

    if (err == LCB_SUCCESS) {
        err = cccp->update(origin->host, config_json);
    }

    if (err != LCB_SUCCESS && was_active) {
        cccp->mcio_error(err);
    }
}

static void on_connected(lcbio_SOCKET *sock, void *data, lcb_STATUS err, lcbio_OSERR)
{
    lcbio_CTXPROCS ioprocs{};
    auto *cccp = reinterpret_cast<CccpProvider *>(data);
    lcb_settings *settings = cccp->parent->settings;
    cccp->creq = nullptr;

    if (err != LCB_SUCCESS) {
        if (sock) {
            lcb::io::Pool::discard(sock);
        }
        cccp->mcio_error(err);
        return;
    }

    if (lcbio_protoctx_get(sock, LCBIO_PROTOCTX_SESSINFO) == nullptr) {
        cccp->creq = lcb::SessionRequest::start(sock, settings, settings->config_node_timeout, on_connected, cccp);
        return;
    }

    ioprocs.cb_err = io_error_handler;
    ioprocs.cb_read = io_read_handler;
    cccp->ioctx = lcbio_ctx_new(sock, data, &ioprocs, "bc_cccp");
    sock->service = LCBIO_SERVICE_CFG;
    cccp->request_config();
}

lcb_STATUS CccpProvider::refresh(unsigned options)
{
    if (has_pending_request()) {
        return LCB_ERR_BUSY;
    }

    return schedule_next_request(LCB_SUCCESS, /* can_rollover */ true,
                                 /* skip_if_push_supported */ (options & lcb::BS_REFRESH_INCRERR) == 0);
}

bool CccpProvider::pause()
{
    if (!has_pending_request()) {
        return true;
    }

    stop_current_request(false);
    timer.cancel();
    return true;
}

CccpProvider::~CccpProvider()
{
    stop_current_request(false);

    if (config) {
        config->decref();
    }
    delete nodes;
    timer.release();
}

void CccpProvider::configure_nodes(const lcb::Hostlist &nodes_)
{
    /* note, that provider assumes that none of the nodes supports configuration push. It will be checked later, when
     * the address will be selected to fetch configuration. It allows to handle downgrade scenario, when newer server
     * version replaced with older, that do not support configuration push */
    nodes->assign(nodes_);
    if (parent->settings->randomize_bootstrap_nodes) {
        nodes->randomize();
    }
}

void CccpProvider::config_updated(lcbvb_CONFIG *vbc)
{
    lcbvb_SVCMODE mode = LCBT_SETTING_SVCMODE(parent);
    if (LCBVB_NSERVERS(vbc) < 1) {
        return;
    }

    nodes->clear();
    for (size_t ii = 0; ii < LCBVB_NSERVERS(vbc); ii++) {
        const char *mcaddr = lcbvb_get_hostport(vbc, ii, LCBVB_SVCTYPE_DATA, mode);
        if (!mcaddr) {
            lcb_log(LOGARGS(this, DEBUG), "Node %lu has no data service", (unsigned long int)ii);
            continue;
        }
        nodes->add(mcaddr, LCB_CONFIG_MCD_PORT);
    }

    if (settings().randomize_bootstrap_nodes) {
        nodes->randomize();
    }
}

static void io_error_handler(lcbio_CTX *ctx, lcb_STATUS err)
{
    auto *cccp = reinterpret_cast<CccpProvider *>(lcbio_ctx_data(ctx));
    cccp->mcio_error(err);
}

static void io_read_handler(lcbio_CTX *ioctx, unsigned)
{
    reinterpret_cast<CccpProvider *>(lcbio_ctx_data(ioctx))->on_io_read();
}

void CccpProvider::on_io_read()
{
    unsigned required;

#define return_error(e)                                                                                                \
    resp.release(ioctx);                                                                                               \
    mcio_error(e);                                                                                                     \
    return

    lcb::MemcachedResponse resp;
    if (!resp.load(ioctx, &required)) {
        lcbio_ctx_rwant(ioctx, required);
        lcbio_ctx_schedule(ioctx);
        return;
    }

    if (resp.status() != PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        std::string value{};
        if (resp.vallen()) {
            value.assign(resp.value(), resp.vallen());
        }
        lcb_log(LOGARGS(this, WARN), LOGFMT "CCCP Packet responded with 0x%02x; nkey=%d, cmd=0x%x, seq=0x%x, value=%s",
                LOGID(this), resp.status(), resp.keylen(), resp.opcode(), resp.opaque(), value.c_str());

        if (settings().bucket == nullptr) {
            switch (resp.status()) {
                case PROTOCOL_BINARY_RESPONSE_NO_BUCKET:
                    return_error(LCB_ERR_UNSUPPORTED_OPERATION);
            }
        }

        switch (resp.status()) {
            case PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED:
            case PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND:
                return_error(LCB_ERR_UNSUPPORTED_OPERATION);
            case PROTOCOL_BINARY_RATE_LIMITED_NETWORK_INGRESS:
            case PROTOCOL_BINARY_RATE_LIMITED_NETWORK_EGRESS:
            case PROTOCOL_BINARY_RATE_LIMITED_MAX_CONNECTIONS:
            case PROTOCOL_BINARY_RATE_LIMITED_MAX_COMMANDS:
                return_error(LCB_ERR_RATE_LIMITED);
            default:
                return_error(LCB_ERR_PROTOCOL_ERROR);
        }
    }

    if (!resp.bodylen()) {
        return_error(LCB_ERR_PROTOCOL_ERROR);
    }

    auto jsonstr = resp.inflated_value();
    std::string hoststr(lcbio_get_host(lcbio_ctx_sock(ioctx))->host);

    resp.release(ioctx);
    stop_current_request(true);

    lcb_STATUS err = update(hoststr.c_str(), jsonstr.c_str());

    if (err == LCB_SUCCESS) {
        timer.cancel();
    } else {
        schedule_next_request(LCB_ERR_PROTOCOL_ERROR, /* can_rollover */ false, /* skip_if_push_supported */ false);
    }

#undef return_error
}

void CccpProvider::request_config()
{
    lcb_log(LOGARGS(this, TRACE), "Attempting to retrieve cluster map via CCCP (timeout=%uus)",
            settings().config_node_timeout);

    lcb::MemcachedRequest req(PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG);
    req.opaque(0xF00D);
    lcbio_ctx_put(ioctx, req.data(), req.size());
    lcbio_ctx_rwant(ioctx, 24);
    lcbio_ctx_schedule(ioctx);
    timer.rearm(settings().config_node_timeout);
}

void CccpProvider::dump(FILE *fp) const
{
    if (!enabled) {
        return;
    }

    fprintf(fp, "## BEGIN CCCP PROVIDER DUMP ##\n");
    fprintf(fp, "TIMER ACTIVE: %s\n", timer.is_armed() ? "YES" : "NO");
    fprintf(fp, "PIPELINE RESPONSE COOKIE: %p\n", (void *)cmdcookie);
    if (ioctx) {
        fprintf(fp, "CCCP Owns connection:\n");
        lcbio_ctx_dump(ioctx, fp);
    } else if (creq) {
        fprintf(fp, "CCCP Is connecting\n");
    } else {
        fprintf(fp, "CCCP does not have a dedicated connection\n");
    }

    for (size_t ii = 0; ii < nodes->size(); ii++) {
        const lcb_host_t &curhost = (*nodes)[ii];
        lcb_settings *dummy = nullptr;
        fprintf(fp, "CCCP NODE: " LCB_HOST_FMT "\n", LCB_HOST_ARG(dummy, &curhost));
    }
    fprintf(fp, "## END CCCP PROVIDER DUMP ##\n");
}

CccpProvider::CccpProvider(Confmon *mon)
    : Provider(mon, CLCONFIG_CCCP), nodes(new lcb::Hostlist()), config(nullptr), timer(mon->iot, this),
      instance(nullptr), ioctx(nullptr), cmdcookie(nullptr)
{
}

Provider *lcb::clconfig::new_cccp_provider(Confmon *mon)
{
    return new CccpProvider(mon);
}
