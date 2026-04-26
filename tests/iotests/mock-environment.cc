/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012-2020 Couchbase, Inc.
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
#include "config.h"
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#include <mocksupport/server.h>
#include "mock-environment.h"
#include <sstream>
#include "internal.h" /* settings from lcb_INSTANCE *for logging */
#include "testutil.h"

#define LOGARGS(instance, lvl) instance->settings, "tests-ENV", LCB_LOG_##lvl, __FILE__, __LINE__

MockEnvironment *MockEnvironment::instance_;

MockEnvironment *MockEnvironment::getInstance()
{
    if (instance_ == nullptr) {
        instance_ = new MockEnvironment;
    }
    return instance_;
}

void MockEnvironment::Reset()
{
    if (instance_ != nullptr) {
        instance_->TearDown();
        instance_->SetUp();
    }
}

MockEnvironment::MockEnvironment(const char **args, const std::string &bucketname)
{
    argv_ = args;
    bucket_name_ = bucketname;
    SetUp();
}

void MockEnvironment::failoverNode(int index, const std::string &bucket, bool rebalance)
{
    MockBucketCommand bCmd(MockCommand::FAILOVER, index, bucket);
    bCmd.set("rebalance", rebalance);
    sendCommand(bCmd);
    getResponse();
}

void MockEnvironment::respawnNode(int index, const std::string &bucket)
{
    MockBucketCommand bCmd(MockCommand::RESPAWN, index, bucket);
    sendCommand(bCmd);
    getResponse();
}

void MockEnvironment::hiccupNodes(int msecs, int offset)
{
    MockCommand cmd(MockCommand::HICCUP);
    cmd.set("msecs", msecs);
    cmd.set("offset", offset);
    sendCommand(cmd);
    getResponse();
}

void MockEnvironment::regenVbCoords(const std::string &bucket)
{
    MockBucketCommand bCmd(MockCommand::REGEN_VBCOORDS, 0, bucket);
    MockResponse r;
    sendCommand(bCmd);
    getResponse(r);
    EXPECT_TRUE(r.isOk());
}

std::vector<int> MockEnvironment::getMcPorts(const std::string &bucket)
{
    MockCommand cmd(MockCommand::GET_MCPORTS);
    if (!bucket.empty()) {
        cmd.set("bucket", bucket);
    }

    sendCommand(cmd);
    MockResponse resp;
    getResponse(resp);
    EXPECT_TRUE(resp.isOk());
    const Json::Value &payload = resp.constResp()["payload"];

    std::vector<int> ret;

    for (const auto &ii : payload) {
        ret.push_back(ii.asInt());
    }
    return ret;
}

void MockEnvironment::setSaslMechs(std::vector<std::string> &mechanisms, const std::string &bucket,
                                   const std::vector<int> *nodes)
{
    MockCommand cmd(MockCommand::SET_SASL_MECHANISMS);
    Json::Value mechs(Json::arrayValue);
    for (const auto &mechanism : mechanisms) {
        mechs.append(mechanism);
    }
    cmd.set("mechs", mechs);

    if (!bucket.empty()) {
        cmd.set("bucket", bucket);
    }

    if (nodes != nullptr) {
        const std::vector<int> &v = *nodes;
        Json::Value array(Json::arrayValue);

        for (int ii : v) {
            array.append(ii);
        }

        cmd.set("servers", array);
    }

    sendCommand(cmd);
    getResponse();
}

void MockEnvironment::setCCCP(bool enabled, const std::string &bucket, const std::vector<int> *nodes)
{
    MockCommand cmd(MockCommand::SET_CCCP);
    cmd.set("enabled", enabled);

    if (!bucket.empty()) {
        cmd.set("bucket", bucket);
    }

    if (nodes != nullptr) {
        const std::vector<int> &v = *nodes;
        Json::Value array(Json::arrayValue);

        for (int ii : v) {
            array.append(ii);
        }

        cmd.set("servers", array);
    }

    sendCommand(cmd);
    getResponse();
}

void MockEnvironment::setEnhancedErrors(bool enabled, const std::string &bucket, const std::vector<int> *nodes)
{
    MockCommand cmd(MockCommand::SET_ENHANCED_ERRORS);
    cmd.set("enabled", enabled);

    if (!bucket.empty()) {
        cmd.set("bucket", bucket);
    }

    if (nodes != nullptr) {
        const std::vector<int> &v = *nodes;
        Json::Value array(Json::arrayValue);

        for (int ii : v) {
            array.append(ii);
        }

        cmd.set("servers", array);
    }

    sendCommand(cmd);
    getResponse();
}

void MockEnvironment::setCompression(const std::string &mode, const std::string &bucket, const std::vector<int> *nodes)
{
    MockCommand cmd(MockCommand::SET_COMPRESSION);
    cmd.set("mode", mode);

    if (!bucket.empty()) {
        cmd.set("bucket", bucket);
    }

    if (nodes != nullptr) {
        const std::vector<int> &v = *nodes;
        Json::Value array(Json::arrayValue);

        for (int ii : v) {
            array.append(ii);
        }

        cmd.set("servers", array);
    }

    sendCommand(cmd);
    getResponse();
}

Json::Value MockEnvironment::getKeyInfo(std::string key, const std::string &bucket)
{
    MockKeyCommand cmd(MockCommand::KEYINFO, key);
    cmd.bucket = bucket;
    sendCommand(cmd);
    MockResponse resp;
    getResponse(resp);
    return resp.constResp()["payload"];
}

int MockEnvironment::getKeyIndex(lcb_INSTANCE *instance, std::string &key, const std::string &bucket, int level)
{
    std::vector<int> indexes;
    indexes.resize(getNumNodes());
    const Json::Value info = getKeyInfo(key, bucket);
    int serverIndex = 0;
    for (Json::Value::const_iterator ii = info.begin(); ii != info.end(); ii++, serverIndex++) {
        const Json::Value &node = *ii;
        if (node.isNull()) {
            continue;
        }
        int index = node["Conf"]["Index"].asInt();
        std::string type = node["Conf"]["Type"].asString();
        lcb_log(LOGARGS(instance, DEBUG), "Key '%s' found at index %d with type '%s' (node %d)", key.c_str(), index,
                type.c_str(), serverIndex);
        indexes[index] = serverIndex;
    }

    // Level is 0 for master, 1 for first replica copy, ...
    return indexes[level];
}

void MockEnvironment::sendCommand(MockCommand &cmd)
{
    std::string s = cmd.encode();
    lcb_ssize_t nw = send(mock->client, s.c_str(), (unsigned long)s.size(), 0);
    assert(nw == s.size());
}

void MockEnvironment::getResponse(MockResponse &ret)
{
    std::string rbuf;
    do {
        char c;
        lcb_ssize_t rv = recv(mock->client, &c, 1, 0);
        assert(rv == 1);
        if (c == '\n') {
            break;
        }
        rbuf += c;
    } while (true);

    ret.assign(rbuf);
    if (!ret.isOk()) {
        std::cerr << "Mock command failed!" << std::endl;
        std::cerr << ret.constResp()["error"].asString() << std::endl;
        std::cerr << ret;
    }
}

void MockEnvironment::postCreate(lcb_INSTANCE *instance) const
{
    lcb_STATUS err;
    if (!isRealCluster()) {
        lcb_HTCONFIG_URLTYPE urltype = LCB_HTCONFIG_URLTYPE_COMPAT;
        err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_HTCONFIG_URLTYPE, &urltype);
        ASSERT_EQ(LCB_SUCCESS, err);
    } else {
        /*
         * Real Couchbase Server clusters periodically dip into TMPFAIL
         * during background work (notably the post-drop_scope collection
         * eviction on Server 8.0+). lcb's retry queue handles TMPFAIL with
         * non-idempotent retry but exits once LCB_CNTL_OP_TIMEOUT elapses
         * without progress. The default 2.5s budget is shorter than the
         * eviction-induced TMPFAIL window we observe on freshly-restarted
         * 8.x clusters across the contaminating-* test boundary, which
         * makes early ops in subsequent plugin runs abort before the
         * cluster recovers. Bump the default budget to 5s -- twice the
         * default, but still well under the 10s GET_AND_LOCK locktime
         * used by t_get.cc:testPessimisticLock so the retry storm in
         * that test still completes inside the locked window. Tests that
         * need a short timeout (e.g. the intentional-timeout regressions
         * in t_regression.cc and t_durability.cc) set their own
         * LCB_CNTL_OP_TIMEOUT after createConnection and are unaffected.
         */
        lcb_U32 op_timeout_us = 5 * 1000 * 1000;
        err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &op_timeout_us);
        ASSERT_EQ(LCB_SUCCESS, err);
    }
    err = lcb_cntl_string(instance, "enable_mutation_tokens", "true");
    ASSERT_EQ(LCB_SUCCESS, err);
}

void MockEnvironment::createConnection(HandleWrap &handle, lcb_INSTANCE **instance,
                                       const lcb_CREATEOPTS *user_options) const
{
    lcb_io_opt_t io;
    lcb_CREATEOPTS options = *user_options;

    if (lcb_create_io_ops(&io, nullptr) != LCB_SUCCESS) {
        fprintf(stderr, "Failed to create IO instance\n");
        exit(1);
    }

    lcb_createopts_io(&options, io);

    lcb_STATUS err = lcb_create(instance, &options);
    ASSERT_EQ(LCB_SUCCESS, err);
    postCreate(*instance);

    (void)lcb_set_cookie(*instance, io);

    handle.instance = *instance;
    handle.iops = io;
}

void MockEnvironment::createConnection(HandleWrap &handle, lcb_INSTANCE **instance)
{
    lcb_CREATEOPTS *options = nullptr;
    makeConnectParams(options, nullptr);

    if (test_tracer.enabled()) {
        lcb_createopts_tracer(options, test_tracer.lcb_tracer());
    }

    if (test_meter.enabled()) {
        lcb_createopts_meter(options, test_meter.lcb_meter());
    }

    createConnection(handle, instance, options);
    lcb_createopts_destroy(options);
}

void MockEnvironment::createConnection(HandleWrap &handle, lcb_INSTANCE **instance, const std::string &username,
                                       const std::string &password)
{
    lcb_CREATEOPTS *options = nullptr;
    makeConnectParams(options, nullptr);

    lcb_createopts_credentials(options, username.c_str(), username.size(), password.c_str(), password.size());
    createConnection(handle, instance, options);
    lcb_createopts_destroy(options);
}

void MockEnvironment::createConnection(lcb_INSTANCE **instance)
{
    HandleWrap handle;
    createConnection(handle, instance);

    handle.iops->v.base.need_cleanup = 1;
    handle.instance = nullptr;
    handle.iops = nullptr;
}

#define STAT_VERSION "version"

extern "C" {
static void statsCallback(lcb_INSTANCE *instance, lcb_CALLBACK_TYPE, const lcb_RESPSTATS *resp)
{
    MockEnvironment *me = nullptr;
    lcb_respstats_cookie(resp, (void **)&me);
    if (me->getServerVersion() != MockEnvironment::VERSION_UNKNOWN) {
        // ignore all subsequent responses
        return;
    }
    lcb_STATUS rc = lcb_respstats_status(resp);
    ASSERT_EQ(LCB_SUCCESS, rc) << lcb_strerror_short(rc);

    const char *server = nullptr;
    size_t server_len;
    lcb_respstats_server(resp, &server, &server_len);
    if (server == nullptr) {
        return;
    }

    const char *key = nullptr;
    size_t key_len = 0;
    lcb_respstats_key(resp, &key, &key_len);
    if (key == nullptr || key_len == 0) {
        return;
    }

    if (key_len != sizeof(STAT_VERSION) - 1 || memcmp(key, STAT_VERSION, sizeof(STAT_VERSION) - 1) != 0) {
        return;
    }
    MockEnvironment::ServerVersion version = MockEnvironment::VERSION_UNKNOWN;
    const char *value = nullptr;
    size_t value_len = 0;
    lcb_respstats_value(resp, &value, &value_len);
    if (value_len > 2) {
        int major = value[0] - '0';
        int minor = value[2] - '0';
        switch (major) {
            case 4:
                switch (minor) {
                    case 0:
                        version = MockEnvironment::VERSION_40;
                        break;
                    case 1:
                        version = MockEnvironment::VERSION_41;
                        break;
                    case 5:
                        version = MockEnvironment::VERSION_45;
                        break;
                    case 6:
                        version = MockEnvironment::VERSION_46;
                        break;
                    default:
                        break;
                }
                break;
            case 5:
                switch (minor) {
                    case 0:
                        version = MockEnvironment::VERSION_50;
                        break;
                    case 5:
                        version = MockEnvironment::VERSION_55;
                        break;
                    default:
                        break;
                }
                break;
            case 6:
                switch (minor) {
                    case 0:
                        version = MockEnvironment::VERSION_60;
                        break;
                    case 5:
                        version = MockEnvironment::VERSION_65;
                        break;
                    case 6:
                        version = MockEnvironment::VERSION_66;
                        break;
                    default:
                        break;
                }
                break;
            case 7:
                switch (minor) {
                    case 0:
                        version = MockEnvironment::VERSION_70;
                        break;
                    case 1:
                        version = MockEnvironment::VERSION_71;
                        break;
                    case 2:
                        version = MockEnvironment::VERSION_72;
                        break;
                    case 6:
                        version = MockEnvironment::VERSION_76;
                        break;
                    default:
                        break;
                }
                break;
            case 8:
                switch (minor) {
                    case 0:
                        version = MockEnvironment::VERSION_80;
                        break;
                    case 1:
                        version = MockEnvironment::VERSION_81;
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
    }
    if (version == MockEnvironment::VERSION_UNKNOWN) {
        lcb_log(LOGARGS(instance, ERROR), "Unable to determine version from string '%.*s', assuming 7.0",
                (int)value_len, value);
        version = MockEnvironment::VERSION_70;
    }
    me->setServerVersion(version);
    lcb_log(LOGARGS(instance, INFO), "Using real cluster version %.*s (id=%d)", (int)value_len, value, version);
}
}

void MockEnvironment::bootstrapRealCluster()
{
    serverParams = ServerParams(mock->http, mock->bucket, mock->username, mock->password);

    lcb_INSTANCE *tmphandle;
    lcb_STATUS err;
    lcb_CREATEOPTS *options = nullptr;
    serverParams.makeConnectParams(options, nullptr);

    err = lcb_create(&tmphandle, options);
    ASSERT_EQ(LCB_SUCCESS, err) << lcb_strerror_short(err);
    lcb_createopts_destroy(options);
    postCreate(tmphandle);
    err = lcb_connect(tmphandle);
    ASSERT_EQ(LCB_SUCCESS, err) << lcb_strerror_short(err);
    lcb_wait(tmphandle, LCB_WAIT_DEFAULT);

    lcb_install_callback(tmphandle, LCB_CALLBACK_STATS, (lcb_RESPCALLBACK)statsCallback);
    lcb_CMDSTATS *scmd;
    lcb_cmdstats_create(&scmd);
    err = lcb_stats(tmphandle, this, scmd);
    lcb_cmdstats_destroy(scmd);
    ASSERT_EQ(LCB_SUCCESS, err) << lcb_strerror_short(err);

    lcb_wait(tmphandle, LCB_WAIT_DEFAULT);

    const char *const *servers = lcb_get_server_list(tmphandle);
    int ii;
    for (ii = 0; servers[ii] != nullptr; ii++) {
        // no body
    }

    featureRegistry.insert("observe");
    featureRegistry.insert("views");
    featureRegistry.insert("http");
    featureRegistry.insert("replica_read");
    featureRegistry.insert("lock");

    numNodes = ii;

    waitForWriteReady(tmphandle);

    lcb_destroy(tmphandle);
}

extern "C" {
static void warmupStoreCallback(lcb_INSTANCE *, lcb_CALLBACK_TYPE, const lcb_RESPSTORE *resp)
{
    lcb_STATUS *out = nullptr;
    lcb_respstore_cookie(resp, reinterpret_cast<void **>(&out));
    *out = lcb_respstore_status(resp);
}
}

void MockEnvironment::waitForWriteReady(lcb_INSTANCE *instance)
{
    /*
     * After a contaminating test drops a scope holding many collections, the
     * Couchbase Server data engine continues to evict the collection contents
     * asynchronously even though the manifest UID has propagated. KV writes
     * during that window can come back as ETMPFAIL (errmap TEMPORARY) which
     * lcb retries up to LCB_CNTL_OP_TIMEOUT (default 2.5s) and then surfaces
     * as LCB_ERR_TEMPORARY_FAILURE. Each ctest plugin entry runs in its own
     * process and starts a fresh test binary roughly 1-2 seconds after the
     * previous contaminating test's drop_scope returns -- well inside that
     * window on Server 8.0+. Probe the bucket here, on the bootstrap handle,
     * until a small upsert succeeds (or an outright non-transient error
     * shows up). This runs once per process during global SetUp, so the
     * cost is paid at most once per ctest entry.
     */
    auto *old_callback = lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)warmupStoreCallback);

    const std::string key = "_lcb_test_warmup";
    const std::string value = "1";
    constexpr int max_attempts = 60;
    /*
     * 500ms in microseconds. Plain unsigned int rather than POSIX
     * useconds_t so the file builds on MSVC, which does not provide
     * the type. mocksupport/server.h defines usleep as
     * Sleep((us) / 1000) on Windows, accepting any integral input.
     */
    constexpr unsigned int backoff_us = 500000;

    lcb_STATUS rc = LCB_SUCCESS;
    for (int attempt = 0; attempt < max_attempts; ++attempt) {
        rc = LCB_ERR_TIMEOUT;

        lcb_CMDSTORE *cmd;
        lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
        lcb_cmdstore_key(cmd, key.data(), key.size());
        lcb_cmdstore_value(cmd, value.data(), value.size());
        lcb_STATUS sched_rc = lcb_store(instance, &rc, cmd);
        lcb_cmdstore_destroy(cmd);
        ASSERT_STATUS_EQ(LCB_SUCCESS, sched_rc);
        lcb_wait(instance, LCB_WAIT_DEFAULT);

        if (rc == LCB_SUCCESS) {
            break;
        }
        if (rc != LCB_ERR_TEMPORARY_FAILURE && rc != LCB_ERR_TIMEOUT) {
            FAIL() << "Bucket warmup probe failed: " << lcb_strerror_short(rc);
        }
        usleep(backoff_us);
    }
    ASSERT_STATUS_EQ(LCB_SUCCESS, rc) << "Bucket failed to accept writes after warmup probe";

    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)old_callback);
}

extern "C" {
static void mock_flush_callback(lcb_INSTANCE *, int, const lcb_RESPCBFLUSH *resp)
{
    ASSERT_EQ(LCB_SUCCESS, resp->rc);
}
}

void MockEnvironment::clearAndReset()
{
    if (is_using_real_cluster()) {
        return;
    }

    for (int ii = 0; ii < getNumNodes(); ii++) {
        respawnNode(ii, bucket_name_);
    }

    std::vector<int> mcPorts = getMcPorts(bucket_name_);
    serverParams.setMcPorts(mcPorts);
    setCCCP(true, bucket_name_);

    if (this != getInstance()) {
        return;
    }

    if (!innerClient) {
        lcb_CREATEOPTS *crParams = nullptr;
        // Use default I/O here..
        serverParams.makeConnectParams(crParams, nullptr);
        lcb_STATUS err = lcb_create(&innerClient, crParams);
        lcb_createopts_destroy(crParams);
        if (err != LCB_SUCCESS) {
            printf("Error on create: %s\n", lcb_strerror_short(err));
        }
        EXPECT_FALSE(nullptr == innerClient);
        postCreate(innerClient);
        err = lcb_connect(innerClient);
        EXPECT_EQ(LCB_SUCCESS, err);
        lcb_wait(innerClient, LCB_WAIT_DEFAULT);
        EXPECT_EQ(LCB_SUCCESS, lcb_get_bootstrap_status(innerClient));
        lcb_install_callback(innerClient, LCB_CALLBACK_CBFLUSH, (lcb_RESPCALLBACK)mock_flush_callback);
    } else {
        /* ensure that inner client is in a good shape (e.g. update internal timers, check dead sockets etc.) */
        lcb_tick_nowait(innerClient);
    }

    lcb_CMDCBFLUSH fcmd = {0};
    lcb_STATUS err;

    err = lcb_cbflush3(innerClient, nullptr, &fcmd);
    ASSERT_EQ(LCB_SUCCESS, err);
    lcb_wait(innerClient, LCB_WAIT_DEFAULT);
}

void MockEnvironment::SetUp()
{
    numNodes = 4;
    if (!mock) {
        mock = (struct test_server_info *)start_test_server((char **)argv_);
    }

    realCluster = is_using_real_cluster() != 0;
    ASSERT_NE((const void *)(nullptr), mock);
    http = get_mock_http_server(mock);
    ASSERT_NE((const char *)(nullptr), http);

    if (realCluster) {
        bootstrapRealCluster();
        return;
    }

    if (bucket_name_.empty()) {
        const char *name = getenv("LCB_TEST_BUCKET");
        if (name != nullptr) {
            bucket_name_ = name;
        } else {
            bucket_name_ = "default";
        }
    }
    serverParams = ServerParams(http, bucket_name_.c_str(), userName.c_str(), nullptr);

    // Mock 0.6
    featureRegistry.insert("observe");
    featureRegistry.insert("views");
    featureRegistry.insert("replica_read");
    featureRegistry.insert("lock");

    test_tracer = TestTracer();
    test_meter = TestMeter();

    clearAndReset();
}

void MockEnvironment::TearDown()
{
    if (mock != nullptr) {
        shutdown_mock_server(mock);
        mock = nullptr;
    }
    if (innerClient != nullptr) {
        lcb_destroy(innerClient);
        innerClient = nullptr;
    }
}

MockEnvironment::~MockEnvironment()
{
    TearDown();
}

void HandleWrap::destroy()
{
    if (instance) {
        lcb_destroy(instance);
    }
    if (iops) {
        lcb_destroy_io_ops(iops);
    }

    instance = nullptr;
    iops = nullptr;
}

HandleWrap::~HandleWrap()
{
    destroy();
}

MockCommand::MockCommand(Code code)
{
    this->code = code;
    name = GetName(code);
    command["command"] = name;
    payload = &(command["payload"] = Json::Value(Json::objectValue));
}

std::string MockCommand::encode()
{
    finalizePayload();
    return Json::FastWriter().write(command) + "\n";
}

void MockKeyCommand::finalizePayload()
{
    MockCommand::finalizePayload();
    if (vbucket != -1) {
        set("vBucket", vbucket);
    }

    if (!bucket.empty()) {
        set("Bucket", bucket);
    }
    set("Key", key);
}

void MockMutationCommand::finalizePayload()
{
    MockKeyCommand::finalizePayload();
    set("OnMaster", onMaster);

    if (!replicaList.empty()) {
        Json::Value arr(Json::arrayValue);
        Json::Value &arrval = (*payload)["OnReplicas"] = Json::Value(Json::arrayValue);
        for (int &ii : replicaList) {
            arrval.append(ii);
        }
    } else {
        set("OnReplicas", replicaCount);
    }

    if (cas != 0) {
        if (cas > (1LU << 30)) {
            fprintf(stderr, "Detected incompatible > 31 bit integer\n");
            abort();
        }
        set("CAS", static_cast<Json::UInt64>(cas));
    }

    if (!value.empty()) {
        set("Value", value);
    }
}

void MockBucketCommand::finalizePayload()
{
    MockCommand::finalizePayload();
    set("idx", ix);
    set("bucket", bucket);
}

void MockResponse::assign(const std::string &resp)
{
    bool rv = lcb::jsparse::parse_json(resp, jresp);
    assert(rv);
}

std::ostream &operator<<(std::ostream &os, const MockResponse &resp)
{
    os << Json::FastWriter().write(resp.jresp) << std::endl;
    return os;
}

bool MockResponse::isOk()
{
    const Json::Value &status = static_cast<const Json::Value &>(jresp)["status"];
    if (!status.isString()) {
        return false;
    }
    return tolower(status.asString()[0]) == 'o';
}
