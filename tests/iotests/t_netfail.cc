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
#include "iotests.h"
#include <map>

#include "internal.h" /* vbucket_* things from lcb_INSTANCE **/
#include <lcbio/iotable.h>
#include "bucketconfig/bc_http.h"

#define LOGARGS(instance, lvl) instance->settings, "tests-MUT", LCB_LOG_##lvl, __FILE__, __LINE__

#if defined(_WIN32) && !defined(usleep)
#define usleep(n) Sleep((n) / 1000)
#endif

namespace
{
class Retryer
{
  public:
    explicit Retryer(time_t maxDuration) : maxDuration(maxDuration) {}
    bool run()
    {
        time_t maxTime = time(nullptr) + maxDuration;
        while (!checkCondition()) {
            trigger();
            if (checkCondition()) {
                break;
            }
            if (time(nullptr) > maxTime) {
                printf("Time expired and condition still false!\n");
                break;
            } else {
                printf("Sleeping for a bit to allow failover/respawn propagation\n");
                usleep(100000); // Sleep for 100ms
            }
        }
        return checkCondition();
    }

  protected:
    virtual bool checkCondition() = 0;
    virtual void trigger() = 0;

  private:
    time_t maxDuration;
};

extern "C" {
static void nopStoreCb(lcb_INSTANCE *, int, const lcb_RESPBASE *) {}
}

class NumNodeRetryer : public Retryer
{
  public:
    NumNodeRetryer(time_t duration, lcb_INSTANCE *instance, size_t expCount)
        : Retryer(duration), instance(instance), expCount(expCount)
    {
        genDistKeys(LCBT_VBCONFIG(instance), distKeys);
    }
    virtual ~NumNodeRetryer() = default;

  protected:
    bool checkCondition() override
    {
        return lcb_get_num_nodes(instance) == expCount;
    }
    void trigger() override
    {
        lcb_RESPCALLBACK oldCb = lcb_install_callback(instance, LCB_CALLBACK_STORE, nopStoreCb);
        lcb_CMDSTORE *scmd;
        lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
        lcb_sched_enter(instance);

        size_t nSubmit = 0;
        for (auto &distKey : distKeys) {
            lcb_cmdstore_key(scmd, distKey.c_str(), distKey.size());
            lcb_cmdstore_value(scmd, distKey.c_str(), distKey.size());
            lcb_STATUS rc = lcb_store(instance, nullptr, scmd);
            if (rc != LCB_SUCCESS) {
                continue;
            }
            nSubmit++;
        }
        lcb_cmdstore_destroy(scmd);
        if (nSubmit) {
            lcb_sched_leave(instance);
            lcb_wait(instance, LCB_WAIT_DEFAULT);
        }

        lcb_install_callback(instance, LCB_CALLBACK_STORE, oldCb);
    }

  private:
    lcb_INSTANCE *instance;
    size_t expCount;
    std::vector<std::string> distKeys;
};
} // namespace

static bool syncWithNodeCount_(lcb_INSTANCE *instance, size_t expCount)
{
    NumNodeRetryer rr(60, instance, expCount);
    return rr.run();
}

#define SYNC_WITH_NODECOUNT(instance, expCount)                                                                        \
    if (!syncWithNodeCount_(instance, expCount)) {                                                                     \
        lcb_log(LOGARGS(instance, WARN), "Timed out waiting for new configuration. Slow system?");                     \
        fprintf(stderr, "*** FIXME: TEST NOT RUN! (not an SDK error)\n");                                              \
        return;                                                                                                        \
    }

extern "C" {
static void opFromCallback_storeCB(lcb_INSTANCE *, lcb_CALLBACK_TYPE, const lcb_RESPSTORE *resp)
{
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_respstore_status(resp));
}

static void opFromCallback_statsCB(lcb_INSTANCE *instance, lcb_CALLBACK_TYPE, const lcb_RESPSTATS *resp)
{
    char *statkey;
    lcb_size_t nstatkey;

    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_respstats_status(resp));

    const char *server;
    size_t server_len;
    lcb_respstats_server(resp, &server, &server_len);
    if (server != nullptr) {
        const char *key;
        size_t nkey;
        lcb_respstats_key(resp, &key, &nkey);

        const char *bytes;
        size_t nbytes;
        lcb_respstats_value(resp, &bytes, &nbytes);

        nstatkey = server_len + nkey + 2;
        statkey = new char[nstatkey];
        snprintf(statkey, nstatkey, "%.*s-%.*s", (int)server_len, server, (int)nkey, key);

        lcb_CMDSTORE *cmd;
        lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
        lcb_cmdstore_key(cmd, statkey, nstatkey);
        lcb_cmdstore_value(cmd, bytes, nbytes);
        ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, nullptr, cmd));
        lcb_cmdstore_destroy(cmd);
        delete[] statkey;
    }
}
}

TEST_F(MockUnitTest, testOpFromCallback)
{
    // @todo we need to have a test that actually tests the timeout callback..
    lcb_INSTANCE *instance;
    HandleWrap hw;
    createConnection(hw, &instance);

    lcb_install_callback(instance, LCB_CALLBACK_STATS, (lcb_RESPCALLBACK)opFromCallback_statsCB);
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)opFromCallback_storeCB);

    lcb_CMDSTATS *stat;
    lcb_cmdstats_create(&stat);
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl_string(instance, "operation_timeout", "5.0"));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_stats(instance, nullptr, stat));
    lcb_cmdstats_destroy(stat);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
}

struct timeout_test_cookie {
    int *counter;
    lcb_STATUS expected;
};
extern "C" {
static void set_callback(lcb_INSTANCE * /* instance */, lcb_CALLBACK_TYPE, const lcb_RESPSTORE *resp)
{
    timeout_test_cookie *tc;

    lcb_respstore_cookie(resp, (void **)&tc);
    EXPECT_EQ(tc->expected, lcb_respstore_status(resp));
    if (lcb_respstore_status(resp) == LCB_ERR_TIMEOUT) {
        // Remove the hiccup at the first timeout failure
        MockEnvironment::getInstance()->hiccupNodes(0, 0);
    }
    *tc->counter -= 1;
}

struct next_store_st {
    lcb_INSTANCE *instance;
    struct timeout_test_cookie *tc;
    lcb_CMDSTORE *cmdp;
};

static void reschedule_callback(void *cookie)
{
    lcb_STATUS err;
    auto *ns = (struct next_store_st *)cookie;
    lcb_log(LOGARGS(ns->instance, INFO), "Rescheduling operation..");
    err = lcb_store(ns->instance, ns->tc, ns->cmdp);
    lcb_loop_unref(ns->instance);
    EXPECT_EQ(LCB_SUCCESS, err);
}
}

TEST_F(MockUnitTest, testTimeoutOnlyStale)
{
    SKIP_UNLESS_MOCK()

    HandleWrap hw;
    createConnection(hw);
    lcb_INSTANCE *instance = hw.getLcb();
    lcb_uint32_t tmoval = 1000000;
    int nremaining = 2;
    struct timeout_test_cookie cookies[2];
    MockEnvironment *mock = MockEnvironment::getInstance();

    // Set the timeout
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmoval);

    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)set_callback);

    const char *key = "i'm a key";
    const char *value = "a value";

    removeKey(instance, key);

    // Make the mock timeout the first cookie. The extras length is:
    mock->hiccupNodes(1500, 1);

    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(cmd, key, strlen(key));
    lcb_cmdstore_value(cmd, value, strlen(value));

    cookies[0].counter = &nremaining;
    cookies[0].expected = LCB_ERR_TIMEOUT;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, cookies, cmd));

    cookies[1].counter = &nremaining;
    cookies[1].expected = LCB_SUCCESS;
    struct next_store_st ns {
    };
    ns.cmdp = cmd;
    ns.tc = cookies + 1;
    ns.instance = instance;
    lcbio_pTIMER timer = lcbio_timer_new(instance->iotable, &ns, reschedule_callback);
    lcb_loop_ref(instance);
    lcbio_timer_rearm(timer, 900000);

    lcb_log(LOGARGS(instance, INFO), "Waiting..");
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    lcbio_timer_destroy(timer);

    ASSERT_EQ(0, nremaining);
    lcb_cmdstore_destroy(cmd);
}

TEST_F(MockUnitTest, testTimeoutOnlyStaleWithPerOperationProperty)
{
    SKIP_UNLESS_MOCK()

    HandleWrap hw;
    createConnection(hw);
    lcb_INSTANCE *instance = hw.getLcb();
    lcb_uint32_t tmoval = 1000000;
    int nremaining = 2;
    struct timeout_test_cookie cookies[2];
    MockEnvironment *mock = MockEnvironment::getInstance();

    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)set_callback);

    const char *key = "testTimeoutOnlyStaleWithPerOperationProperty";
    const char *value = "a value";

    removeKey(instance, key); // also needed to warm up the connection before hiccup

    // Make the mock timeout the first cookie. The extras length is:
    mock->hiccupNodes(1500, 1);

    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(cmd, key, strlen(key));
    lcb_cmdstore_value(cmd, value, strlen(value));
    lcb_cmdstore_timeout(cmd, tmoval);

    cookies[0].counter = &nremaining;
    cookies[0].expected = LCB_ERR_TIMEOUT;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, cookies, cmd));

    cookies[1].counter = &nremaining;
    cookies[1].expected = LCB_SUCCESS;
    struct next_store_st ns {
    };
    lcb_cmdstore_key(cmd, key, strlen(key));
    ns.cmdp = cmd;
    ns.tc = cookies + 1;
    ns.instance = instance;
    lcbio_pTIMER timer = lcbio_timer_new(instance->iotable, &ns, reschedule_callback);
    lcb_loop_ref(instance);
    lcbio_timer_rearm(timer, 900000);

    lcb_log(LOGARGS(instance, INFO), "Waiting..");
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    lcbio_timer_destroy(timer);

    ASSERT_EQ(0, nremaining);
    lcb_cmdstore_destroy(cmd);
}

extern "C" {
struct rvbuf {
    lcb_STATUS error;
    uint64_t cas1;
    uint64_t cas2;
    char *bytes;
    lcb_size_t nbytes;
    lcb_int32_t counter;
};
int store_cnt;

/* Needed for "testPurgedBody", to ensure preservation of connection */
static void io_close_wrap(lcb_io_opt_t, lcb_socket_t)
{
    fprintf(stderr, "We requested to close, but we were't expecting it\n");
    abort();
}

static void store_callback(lcb_INSTANCE *instance, lcb_CALLBACK_TYPE, const lcb_RESPSTORE *resp)
{
    struct rvbuf *rv = nullptr;
    lcb_respstore_cookie(resp, (void **)(&rv));
    rv->error = lcb_respstore_status(resp);
    lcb_log(LOGARGS(instance, INFO), "Got storage callback for cookie %p with err=0x%x", (void *)rv, (int)rv->error);

    store_cnt++;
    if (!instance->wait) { /* do not touch IO if we are using lcb_wait() */
        lcb_stop_loop(instance);
    }
}

static void get_callback(lcb_INSTANCE *instance, lcb_CALLBACK_TYPE, const lcb_RESPGET *resp)
{
    struct rvbuf *rv;
    lcb_respget_cookie(resp, (void **)&rv);
    rv->error = lcb_respget_status(resp);
    const char *p;
    size_t n;
    lcb_respget_value(resp, &p, &n);
    rv->bytes = (char *)malloc(n);
    memcpy((void *)rv->bytes, p, n);
    rv->nbytes = n;
    if (!instance->wait) { /* do not touch IO if we are using lcb_wait() */
        lcb_stop_loop(instance);
    }
}
}

struct StoreContext {
    std::map<std::string, lcb_STATUS> mm;

    void check(int expected) const
    {
        EXPECT_EQ(expected, mm.size());

        for (const auto &entry : mm) {
            EXPECT_EQ(LCB_SUCCESS, entry.second);
        }
    }

    void clear()
    {
        mm.clear();
    }
};

extern "C" {
static void ctx_store_callback(lcb_INSTANCE *, lcb_CALLBACK_TYPE, const lcb_RESPSTORE *resp)
{
    StoreContext *ctx;
    lcb_respstore_cookie(resp, (void **)&ctx);
    const char *key;
    size_t nkey;
    lcb_respstore_key(resp, &key, &nkey);
    std::string s(key, nkey);
    ctx->mm[s] = lcb_respstore_status(resp);
}
}

TEST_F(MockUnitTest, testReconfigurationOnNodeFailover)
{
    SKIP_UNLESS_MOCK()
    lcb_INSTANCE *instance;
    HandleWrap hw;
    const char *argv[] = {"--replicas", "0", "--nodes", "4", nullptr};

    MockEnvironment mock_o(argv), *mock = &mock_o;

    std::vector<std::string> keys;
    std::vector<lcb_CMDSTORE *> cmds;

    mock->createConnection(hw, &instance);
    instance->settings->vb_noguess = 1;
    lcb_connect(instance);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(0, lcb_get_num_replicas(instance));

    size_t numNodes = mock->getNumNodes();

    genDistKeys(LCBT_VBCONFIG(instance), keys);
    genStoreCommands(keys, cmds);
    StoreContext ctx;

    mock->failoverNode(0);
    SYNC_WITH_NODECOUNT(instance, numNodes - 1)

    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)ctx_store_callback);
    for (auto &cmd : cmds) {
        ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, &ctx, cmd));
    }
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ctx.check((int)cmds.size());

    mock->respawnNode(0);
    SYNC_WITH_NODECOUNT(instance, numNodes)

    ctx.clear();
    for (auto &cmd : cmds) {
        ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, &ctx, cmd));
    }
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ctx.check((int)cmds.size());
    for (auto &cmd : cmds) {
        lcb_cmdstore_destroy(cmd);
    }
}

struct fo_context_st {
    MockEnvironment *env;
    int index;
    lcb_INSTANCE *instance;
};
// Hiccup the server, then fail it over.
extern "C" {
static void fo_callback(void *cookie)
{
    auto *ctx = (fo_context_st *)cookie;
    ctx->env->failoverNode(ctx->index);
    ctx->env->hiccupNodes(0, 0);
    lcb_loop_unref(ctx->instance);
}
}

TEST_F(MockUnitTest, testBufferRelocationOnNodeFailover)
{
    SKIP_UNLESS_MOCK()
    struct rvbuf rv {
    };
    lcb_INSTANCE *instance;
    HandleWrap hw;
    std::string key = "testBufferRelocationOnNodeFailover";
    std::string val = "foo";

    const char *argv[] = {"--replicas", "0", "--nodes", "4", nullptr};
    MockEnvironment mock_o(argv), *mock = &mock_o;

    // We need to disable CCCP for this test to receive "Push" style
    // configuration.
    mock->setCCCP(false);

    mock->createConnection(hw, &instance);
    lcb_connect(instance);
    lcb_wait(instance, LCB_WAIT_DEFAULT);

    // Set the timeout for 15 seconds
    lcb_uint32_t tmoval = 15000000;
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmoval);

    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)store_callback);
    lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);

    // Initialize the nodes first..
    removeKey(instance, key);

    /* Schedule SET operation */
    lcb_CMDSTORE *storecmd;
    lcb_cmdstore_create(&storecmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(storecmd, key.c_str(), key.size());
    lcb_cmdstore_value(storecmd, val.c_str(), val.size());

    /* Determine what server should receive that operation */
    int vb, idx;
    lcbvb_map_key(LCBT_VBCONFIG(instance), key.c_str(), key.size(), &vb, &idx);
    mock->hiccupNodes(5000, 1);

    struct fo_context_st ctx = {mock, idx, instance};
    lcbio_pTIMER timer;
    timer = lcbio_timer_new(instance->iotable, &ctx, fo_callback);
    lcb_loop_ref(instance);
    lcbio_timer_rearm(timer, 500000);

    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, &rv, storecmd));

    store_cnt = 0;
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(1, store_cnt);
    ASSERT_STATUS_EQ(LCB_SUCCESS, rv.error);

    memset(&rv, 0, sizeof(rv));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, &rv, storecmd));
    store_cnt = 0;
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(1, store_cnt);

    lcb_cmdstore_destroy(storecmd);

    /* Check that value was actually set */
    lcb_CMDGET *getcmd;
    lcb_cmdget_create(&getcmd);
    lcb_cmdget_key(getcmd, key.c_str(), key.size());
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_get(instance, &rv, getcmd));
    lcb_cmdget_destroy(getcmd);

    lcb_wait(instance, LCB_WAIT_DEFAULT);
    lcbio_timer_destroy(timer);
    ASSERT_STATUS_EQ(LCB_SUCCESS, rv.error);
    ASSERT_EQ(rv.nbytes, val.size());
    std::string bytes = std::string(rv.bytes, rv.nbytes);
    ASSERT_STREQ(bytes.c_str(), val.c_str());
    free(rv.bytes);
}

TEST_F(MockUnitTest, testSaslMechs)
{
    // Ensure our SASL mech listing works.
    SKIP_UNLESS_MOCK()

    const char *argv[] = {"--buckets", "protected:secret:couchbase", nullptr};

    lcb_INSTANCE *instance;
    lcb_STATUS err;
    lcb_CREATEOPTS *crParams = nullptr;
    MockEnvironment mock_o(argv, "protected"), *protectedEnv = &mock_o;
    protectedEnv->makeConnectParams(crParams, nullptr);
    protectedEnv->setCCCP(false);

    std::string username("protected");
    std::string password("secret");
    std::string bucket("protected");
    lcb_createopts_credentials(crParams, username.c_str(), username.size(), password.c_str(), password.size());
    lcb_createopts_bucket(crParams, bucket.c_str(), bucket.size());
    doLcbCreate(&instance, crParams, protectedEnv);
    lcb_createopts_destroy(crParams);

    // Make the socket pool disallow idle connections
    instance->memd_sockpool->get_options().maxidle = 0;

    err = lcb_connect(instance);
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    lcb_wait(instance, LCB_WAIT_DEFAULT);

    // Force our SASL mech
    err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_FORCE_SASL_MECH, (void *)"blah");
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    Item itm("key", "value");
    KVOperation kvo(&itm);
    kvo.allowableErrors.insert(LCB_ERR_SASLMECH_UNAVAILABLE);
    kvo.allowableErrors.insert(LCB_ERR_TIMEOUT);
    kvo.store(instance);
    ASSERT_FALSE(kvo.globalErrors.find(LCB_ERR_SASLMECH_UNAVAILABLE) == kvo.globalErrors.end());

    err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_FORCE_SASL_MECH, (void *)"    ");
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    kvo.clear();
    kvo.allowableErrors.insert(LCB_ERR_SASLMECH_UNAVAILABLE);
    kvo.allowableErrors.insert(LCB_ERR_TIMEOUT);
    kvo.store(instance);
    ASSERT_FALSE(kvo.globalErrors.find(LCB_ERR_SASLMECH_UNAVAILABLE) == kvo.globalErrors.end());

    err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_FORCE_SASL_MECH, (void *)"PLAIN");
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    kvo.clear();
    kvo.store(instance);
    ASSERT_TRUE(kvo.globalErrors.find(LCB_ERR_TIMEOUT) == kvo.globalErrors.end());

    err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_FORCE_SASL_MECH, (void *)"blah PLAIN");
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    kvo.clear();
    kvo.store(instance);
    ASSERT_TRUE(kvo.globalErrors.find(LCB_ERR_TIMEOUT) == kvo.globalErrors.end());

    err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_FORCE_SASL_MECH, (void *)"  PLAIN    ");
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    kvo.clear();
    kvo.store(instance);
    ASSERT_TRUE(kvo.globalErrors.find(LCB_ERR_TIMEOUT) == kvo.globalErrors.end());

    err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_FORCE_SASL_MECH, (void *)"blah,PLAIN");
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    kvo.clear();
    kvo.store(instance);
    ASSERT_TRUE(kvo.globalErrors.find(LCB_ERR_TIMEOUT) == kvo.globalErrors.end());

    lcb_destroy(instance);
}

#ifndef LCB_NO_SSL
TEST_F(MockUnitTest, testSaslSHA)
{
    // Ensure our SASL mech listing works.
    SKIP_UNLESS_MOCK()

    const char *argv[] = {"--buckets", "protected:secret:couchbase", nullptr};

    lcb_INSTANCE *instance = nullptr;
    lcb_CREATEOPTS *crParams = nullptr;
    MockEnvironment mock_o(argv, "protected"), *protectedEnv = &mock_o;
    protectedEnv->makeConnectParams(crParams, nullptr, LCB_TYPE_CLUSTER);
    crParams->type = LCB_TYPE_BUCKET;
    protectedEnv->setCCCP(false);

    std::string username("protected");
    std::string password("secret");
    std::string bucket("protected");
    lcb_createopts_credentials(crParams, username.c_str(), username.size(), password.c_str(), password.size());
    lcb_createopts_bucket(crParams, bucket.c_str(), bucket.size());

    std::vector<std::string> mechs;

    mechs.emplace_back("SCRAM-SHA512");
    protectedEnv->setSaslMechs(mechs);

    {
        doLcbCreate(&instance, crParams, protectedEnv);

        // Make the socket pool disallow idle connections
        instance->memd_sockpool->get_options().maxidle = 0;

        ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_connect(instance));
        ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_wait(instance, LCB_WAIT_DEFAULT));

        Item itm("key", "value");
        KVOperation kvo(&itm);

        kvo.store(instance);

        lcb_destroy(instance);
    }

    lcb_createopts_destroy(crParams);
}
#endif

extern "C" {
static void get_credentials(lcbauth_CREDENTIALS *credentials)
{
    std::map<std::string, std::string> *store = nullptr;
    lcbauth_credentials_cookie(credentials, reinterpret_cast<void **>(&store));
    const char *bucket = nullptr;
    size_t bucket_len = 0;
    lcbauth_credentials_bucket(credentials, &bucket, &bucket_len);
    std::string bucket_name(bucket, bucket_len);
    auto password = (*store)[bucket_name];
    lcbauth_credentials_username(credentials, bucket_name.c_str(), bucket_name.size());
    lcbauth_credentials_password(credentials, password.c_str(), password.size());
    lcbauth_credentials_result(credentials, LCBAUTH_RESULT_OK);
}
}

TEST_F(MockUnitTest, testDynamicAuth)
{
    SKIP_UNLESS_MOCK()

    const char *argv[] = {"--buckets", "protected:secret:couchbase", nullptr};

    lcb_INSTANCE *instance;
    lcb_STATUS err;
    lcb_CREATEOPTS *crParams = nullptr;
    MockEnvironment mock_o(argv, "protected"), *mock = &mock_o;
    mock->makeConnectParams(crParams, nullptr);
    mock->setCCCP(false);

    std::string bucket("protected");
    lcb_createopts_bucket(crParams, bucket.c_str(), bucket.size());
    doLcbCreate(&instance, crParams, mock);

    std::map<std::string, std::string> credentials;
    credentials["protected"] = "secret";
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcbauth_set_callback(auth, &credentials, get_credentials);
    lcbauth_set_mode(auth, LCBAUTH_MODE_DYNAMIC);
    lcb_set_auth(instance, auth);

    err = lcb_connect(instance);
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_wait(instance, LCB_WAIT_DEFAULT));

    Item itm("key", "value");
    KVOperation kvo(&itm);
    kvo.store(instance);
    lcb_destroy(instance);
    lcbauth_unref(auth);
    lcb_createopts_destroy(crParams);
}

static void doManyItems(lcb_INSTANCE *instance, const std::vector<std::string> &keys)
{
    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
    lcb_sched_enter(instance);
    for (auto &key : keys) {
        lcb_cmdstore_key(cmd, key.c_str(), key.size());
        lcb_cmdstore_value(cmd, key.c_str(), key.size());
        EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, nullptr, cmd));
    }
    lcb_cmdstore_destroy(cmd);
    lcb_sched_leave(instance);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
}

extern "C" {
static void mcdFoVerifyCb(lcb_INSTANCE *, int, const lcb_RESPSTORE *resp)
{
    EXPECT_EQ(LCB_SUCCESS, lcb_respstore_status(resp));
}
}

TEST_F(MockUnitTest, DISABLED_testMemcachedFailover)
{
    SKIP_UNLESS_MOCK()
    const char *argv[] = {"--buckets", "cache::memcache", nullptr};
    lcb_INSTANCE *instance;
    lcb_CREATEOPTS *crParams = nullptr;
    lcb_RESPCALLBACK oldCb;

    MockEnvironment mock_o(argv, "cache"), *mock = &mock_o;
    mock->makeConnectParams(crParams, nullptr);
    doLcbCreate(&instance, crParams, mock);
    lcb_createopts_destroy(crParams);

    // Check internal setting here
    lcb_connect(instance);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    size_t numNodes = mock->getNumNodes();

    oldCb = lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)mcdFoVerifyCb);

    // Get the command list:
    std::vector<std::string> distKeys;
    genDistKeys(LCBT_VBCONFIG(instance), distKeys);
    doManyItems(instance, distKeys);
    // Should succeed implicitly with callback above

    // Fail over the first node..
    mock->failoverNode(1, "cache");
    SYNC_WITH_NODECOUNT(instance, numNodes - 1)

    // Set the callback to the previous one. We expect failures here
    lcb_install_callback(instance, LCB_CALLBACK_STORE, oldCb);
    doManyItems(instance, distKeys);

    mock->respawnNode(1, "cache");
    SYNC_WITH_NODECOUNT(instance, numNodes)
    ASSERT_EQ(numNodes, lcb_get_num_nodes(instance));

    // Restore the verify callback
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)mcdFoVerifyCb);
    doManyItems(instance, distKeys);

    lcb_destroy(instance);
}

struct NegativeIx {
    lcb_STATUS err;
    int callCount;
};

extern "C" {
static void get_callback3(lcb_INSTANCE *, int, const lcb_RESPGET *resp)
{
    NegativeIx *ni;
    lcb_respget_cookie(resp, (void **)&ni);
    ni->err = lcb_respget_status(resp);
    ni->callCount++;
}

static void store_callback3(lcb_INSTANCE *, int, const lcb_RESPSTORE *resp)
{
    NegativeIx *ni;
    lcb_respstore_cookie(resp, (void **)&ni);
    ni->err = lcb_respstore_status(resp);
    ni->callCount++;
}
}
/**
 * This tests the case where a negative index appears for a vbucket ID for the
 * mapped key. In this case we'd expect that the command would be retried
 * at least once, and not receive an LCB_ERR_NO_MATCHING_SERVER.
 *
 * Unfortunately this test is a bit hacky since we need to modify the vbucket
 * information, and hopefully get a new config afterwards. Additionally we'd
 * want to mod
 */
TEST_F(MockUnitTest, testNegativeIndex)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createConnection(hw, &instance);
    lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback3);
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)store_callback3);
    std::string key("ni_key");
    // Get the config
    lcbvb_CONFIG *vbc = instance->cur_configinfo->vbc;
    /* make sure monitor will not overwrite out "fix" */
    instance->confmon->stop();
    instance->confmon->stop_real();
    int vb = lcbvb_k2vb(vbc, key.c_str(), key.size());

    // Set the timeout to something a bit shorter
    lcb_cntl_setu32(instance, LCB_CNTL_OP_TIMEOUT, 500000);

    NegativeIx ni{};
    lcb_STATUS err;

    /* warm up the collection cache */
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, key.c_str(), key.size());
    std::string value("{}");
    lcb_cmdstore_value(scmd, value.c_str(), value.size());
    ni.err = LCB_SUCCESS;
    ni.callCount = 0;
    err = lcb_store(instance, &ni, scmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(1, ni.callCount);
    ASSERT_STATUS_EQ(LCB_SUCCESS, ni.err);
    lcb_cmdstore_destroy(scmd);

    lcb_CMDGET *gcmd;
    lcb_cmdget_create(&gcmd);
    lcb_cmdget_key(gcmd, key.c_str(), key.size());
    ni.err = LCB_SUCCESS;
    ni.callCount = 0;
    // Set the index to -1
    vbc->vbuckets[vb].servers[0] = -1;
    err = lcb_get(instance, &ni, gcmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(1, ni.callCount);
    ASSERT_STATUS_EQ(LCB_ERR_NO_MATCHING_SERVER, ni.err);
    lcb_cmdget_destroy(gcmd);
    // That's it
}

namespace
{
struct RestoreCtx {
    lcbvb_CONFIG *vbc;
    int vb;
    int saved_master;
    bool fired;
    lcb_INSTANCE *instance;
};

extern "C" {
static void restore_master_callback(void *cookie)
{
    auto *ctx = static_cast<RestoreCtx *>(cookie);
    ctx->vbc->vbuckets[ctx->vb].servers[0] = ctx->saved_master;
    ctx->fired = true;
    lcb_loop_unref(ctx->instance);
}
}
} // namespace

/**
 * Reproduces the rebound failure mode seen in SDKD situational tests
 * (CCBC-1702): a brief window where the vbucket map's master index is
 * unresolvable for the requested key. In production this happens during
 * replace_config(), where mcreq_queue_take_pipelines() sets
 * cq->npipelines = 0 before mcreq_queue_add_pipelines() reinstalls the
 * new array. Any retryq tick that fires inside that window sees
 * srvix >= cq->npipelines (or srvix < 0 when a vbucket has no master
 * yet) and -- with the historical default of LCB_RETRY_ON_MISSINGNODE = 0
 * -- fails the op with LCB_ERR_NO_MATCHING_SERVER.
 *
 * We exercise the same code path without iptables by:
 *   1. Storing a key normally (warm up).
 *   2. Stopping the config monitor so retryq cannot get a fresh map
 *      from the cluster.
 *   3. Setting vbuckets[vb].servers[0] = -1 to force lcbvb_vbmaster()
 *      to return -1 -- the precise condition retryq.cc:264 trips on.
 *   4. Scheduling a timer 200 ms into the future that restores the
 *      original master index (simulating the new config arriving).
 *   5. Issuing a GET with a 2 s deadline and waiting.
 *
 * On gerrit/master (RETRY_ON_MISSINGNODE = 0), retryq fails the op at
 * the first tick with LCB_ERR_NO_MATCHING_SERVER, well before the
 * timer fires. With RETRY_ON_MISSINGNODE = 1 the op stays in retryq
 * across ticks; once the timer restores the map, the next tick
 * dispatches the op to the correct pipeline and the GET succeeds.
 */
TEST_F(MockUnitTest, testRetryOnMissingNodeAfterMapRepair)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createConnection(hw, &instance);
    lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback3);
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)store_callback3);

    std::string key("ni_repair_key");
    lcbvb_CONFIG *vbc = instance->cur_configinfo->vbc;
    instance->confmon->stop();
    instance->confmon->stop_real();
    int vb = lcbvb_k2vb(vbc, key.c_str(), key.size());
    int saved_master = vbc->vbuckets[vb].servers[0];

    lcb_cntl_setu32(instance, LCB_CNTL_OP_TIMEOUT, 2000000); // 2 s

    NegativeIx ni{};
    lcb_STATUS err;

    /* warm up: store the key with a healthy map */
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, key.c_str(), key.size());
    std::string value("{}");
    lcb_cmdstore_value(scmd, value.c_str(), value.size());
    ni.err = LCB_SUCCESS;
    ni.callCount = 0;
    err = lcb_store(instance, &ni, scmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(1, ni.callCount);
    ASSERT_STATUS_EQ(LCB_SUCCESS, ni.err);
    lcb_cmdstore_destroy(scmd);

    /* corrupt the map so vbmaster() returns -1 for this key */
    vbc->vbuckets[vb].servers[0] = -1;

    /* schedule the repair 200 ms out -- comfortably inside the 2 s op
     * deadline and well past retryq's first tick (default 10 ms) */
    RestoreCtx ctx{vbc, vb, saved_master, false, instance};
    lcbio_pTIMER timer = lcbio_timer_new(instance->iotable, &ctx, restore_master_callback);
    lcb_loop_ref(instance);
    lcbio_timer_rearm(timer, 200000);

    /* dispatch GET; with the fix it sits in retryq until the timer fires */
    lcb_CMDGET *gcmd;
    lcb_cmdget_create(&gcmd);
    lcb_cmdget_key(gcmd, key.c_str(), key.size());
    ni.err = LCB_ERR_GENERIC;
    ni.callCount = 0;
    err = lcb_get(instance, &ni, gcmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    lcbio_timer_destroy(timer);
    lcb_cmdget_destroy(gcmd);

    ASSERT_TRUE(ctx.fired) << "Restore timer should have fired before lcb_wait returned";
    ASSERT_EQ(1, ni.callCount);
    EXPECT_STATUS_EQ(LCB_SUCCESS, ni.err);
}

namespace
{
struct ReplaceConfigCtx {
    lcb_INSTANCE *instance;
    lcbvb_CONFIG *new_vbc; /* ownership transferred to ConfigInfo when fired */
    bool fired;
};

extern "C" {
static void replace_config_callback(void *cookie)
{
    auto *ctx = static_cast<ReplaceConfigCtx *>(cookie);
    /* Wrap the prebuilt new vbc into a ConfigInfo and install via the
     * full replace path. lcb_update_vbconfig will:
     *   1. Set instance->cur_configinfo to the new ConfigInfo and incref
     *      it (refcount goes 1 -> 2).
     *   2. Update cmdq.config to the new vbc.
     *   3. Call replace_config(), which atomically swaps cmdq.pipelines
     *      and friends.
     *   4. Decref the old ConfigInfo (refcount 1 -> 0), which destroys
     *      its lcbvb_CONFIG via lcbvb_destroy().
     * After return, the old vbc is freed; any captured raw lcbvb_CONFIG*
     * pointers that hadn't taken a ConfigInfo ref are now dangling. The
     * subsequent retryq tick in the main flow exercises post-replace
     * dispatch on the new map. */
    auto *new_info =
        lcb::clconfig::ConfigInfo::create(ctx->new_vbc, lcb::clconfig::CLCONFIG_CCCP, "synthetic-replace");
    lcb_update_vbconfig(ctx->instance, new_info);
    /* lcb_update_vbconfig() incref'd new_info to 2; create() left it at 1.
     * So after lcb_update_vbconfig returns, refcount is 2. We decref to
     * release our local ref; cur_configinfo still owns the remaining
     * one. */
    new_info->decref();
    ctx->fired = true;
    lcb_loop_unref(ctx->instance);
}
}
} // namespace

/**
 * Drives a real config-replace mid-retry, exercising the full
 * lcb_update_vbconfig -> replace_config code path that the simpler
 * testRetryOnMissingNodeAfterMapRepair does not reach (that test mutates
 * the live vbc in place rather than installing a new ConfigInfo).
 *
 * The bug surface this guards against -- and which on gerrit/master
 * required FoRecoverDelta in the SDKD situational suite to expose --
 * is the lifetime of the old lcbvb_CONFIG once lcb_update_vbconfig
 * decrefs it: any code path that captured a raw lcbvb_CONFIG* (e.g.,
 * Server::handle_nmv via LCBT_VBCONFIG, or anyone holding cmdq.config
 * across an event-loop callback) without a ConfigInfo ref now points
 * at freed memory. CCBC-1702 plugs the two known holders (handle_nmv
 * via incref/decref guard) and adds defensive zeroing in
 * lcbvb_destroy() so that a missed holder NULL-derefs deterministically
 * rather than reading garbage.
 *
 * The test corrupts the live vbmap so the GET goes into retryq, then
 * 100 ms later swaps in a brand-new ConfigInfo (built from a JSON
 * round-trip of the live config with the master restored). With all
 * the fixes in place, the retryq tick following the swap dispatches
 * the GET on the freshly-installed pipelines and the op succeeds.
 */
TEST_F(MockUnitTest, testConfigReplaceMidRetry)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createConnection(hw, &instance);
    lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback3);
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)store_callback3);

    std::string key("repl_replace_key");
    lcbvb_CONFIG *vbc = instance->cur_configinfo->vbc;
    instance->confmon->stop();
    instance->confmon->stop_real();
    int vb = lcbvb_k2vb(vbc, key.c_str(), key.size());

    lcb_cntl_setu32(instance, LCB_CNTL_OP_TIMEOUT, 2000000); // 2 s

    NegativeIx ni{};
    lcb_STATUS err;

    /* warm up under the healthy map */
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, key.c_str(), key.size());
    std::string value("{}");
    lcb_cmdstore_value(scmd, value.c_str(), value.size());
    ni.err = LCB_SUCCESS;
    ni.callCount = 0;
    err = lcb_store(instance, &ni, scmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(1, ni.callCount);
    ASSERT_STATUS_EQ(LCB_SUCCESS, ni.err);
    lcb_cmdstore_destroy(scmd);

    /* Snapshot the (still-healthy) live vbc as JSON. We will load this
     * into a fresh lcbvb_CONFIG and feed it back through
     * lcb_update_vbconfig() to drive a full replace cycle. */
    char *cfg_json = lcbvb_save_json(vbc);
    ASSERT_TRUE(cfg_json != nullptr) << "lcbvb_save_json returned NULL";

    auto *new_vbc = lcbvb_create();
    ASSERT_TRUE(new_vbc != nullptr);
    int rv = lcbvb_load_json(new_vbc, cfg_json);
    free(cfg_json);
    ASSERT_EQ(0, rv) << "lcbvb_load_json failed";

    /* Now corrupt the live map so the GET enters retryq */
    vbc->vbuckets[vb].servers[0] = -1;

    /* Schedule the swap 100 ms out -- comfortably past retryq's first
     * tick (default 10 ms) so the op is sitting in retryq when the
     * config flips. */
    ReplaceConfigCtx ctx{instance, new_vbc, false};
    lcbio_pTIMER timer = lcbio_timer_new(instance->iotable, &ctx, replace_config_callback);
    lcb_loop_ref(instance);
    lcbio_timer_rearm(timer, 100000);

    /* dispatch GET; it lands in retryq, waits for the swap, then
     * dispatches on the new pipelines */
    lcb_CMDGET *gcmd;
    lcb_cmdget_create(&gcmd);
    lcb_cmdget_key(gcmd, key.c_str(), key.size());
    ni.err = LCB_ERR_GENERIC;
    ni.callCount = 0;
    err = lcb_get(instance, &ni, gcmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, err);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    lcbio_timer_destroy(timer);
    lcb_cmdget_destroy(gcmd);

    ASSERT_TRUE(ctx.fired) << "Replace timer should have fired before lcb_wait returned";
    ASSERT_EQ(1, ni.callCount);
    EXPECT_STATUS_EQ(LCB_SUCCESS, ni.err);
}
