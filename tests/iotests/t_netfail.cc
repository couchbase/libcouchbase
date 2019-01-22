/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012 Couchbase, Inc.
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

#include "internal.h" /* vbucket_* things from lcb_t */
#include <lcbio/iotable.h>
#include "bucketconfig/bc_http.h"

#define LOGARGS(instance, lvl) \
    instance->settings, "tests-MUT", LCB_LOG_##lvl, __FILE__, __LINE__

#if defined(_WIN32) && !defined(usleep)
#define usleep(n) Sleep((n) / 1000)
#endif

namespace {
class Retryer {
public:
    Retryer(time_t maxDuration) : maxDuration(maxDuration) {}
    bool run() {
        time_t maxTime = time(NULL) + maxDuration;
        while (!checkCondition()) {
            trigger();
            if (checkCondition()) {
                break;
            }
            if (time(NULL) > maxTime) {
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
static void nopStoreCb(lcb_t, int, const lcb_RESPBASE *) {}
}

class NumNodeRetryer : public Retryer {
public:
    NumNodeRetryer(time_t duration, lcb_t instance, size_t expCount) :
        Retryer(duration), instance(instance), expCount(expCount) {
        genDistKeys(LCBT_VBCONFIG(instance), distKeys);
    }
    virtual ~NumNodeRetryer() {}

protected:
    virtual bool checkCondition() {
        return lcb_get_num_nodes(instance) == expCount;
    }
    virtual void trigger() {
        lcb_RESPCALLBACK oldCb = lcb_install_callback3(instance, LCB_CALLBACK_STORE, nopStoreCb);
        lcb_CMDSTORE scmd = { 0 };
        scmd.operation = LCB_SET;
        lcb_sched_enter(instance);

        size_t nSubmit = 0;
        for (size_t ii = 0; ii < distKeys.size(); ii++) {
            LCB_CMD_SET_KEY(&scmd, distKeys[ii].c_str(), distKeys[ii].size());
            LCB_CMD_SET_VALUE(&scmd, distKeys[ii].c_str(), distKeys[ii].size());
            lcb_error_t rc = lcb_store3(instance, NULL, &scmd);
            if (rc != LCB_SUCCESS) {
                continue;
            }
            nSubmit++;
        }
        if (nSubmit) {
            lcb_sched_leave(instance);
            lcb_wait(instance);
        }

        lcb_install_callback3(instance, LCB_CALLBACK_STORE, oldCb);
    }

private:
    lcb_t instance;
    size_t expCount;
    std::vector<std::string> distKeys;
};
}

static bool
syncWithNodeCount_(lcb_t instance, size_t expCount)
{
    NumNodeRetryer rr(60, instance, expCount);
    return rr.run();
}

#define SYNC_WITH_NODECOUNT(instance, expCount) \
    if (!syncWithNodeCount_(instance, expCount)) { \
        lcb_log(LOGARGS(instance, WARN), "Timed out waiting for new configuration. Slow system?"); \
        fprintf(stderr, "*** FIXME: TEST NOT RUN! (not an SDK error)\n"); \
        return; \
    }



extern "C" {
static void opFromCallback_storeCB(lcb_t, lcb_CALLBACKTYPE, lcb_RESPSTORE *resp)
{
    ASSERT_EQ(LCB_SUCCESS, resp->rc);
}

static void opFromCallback_statsCB(lcb_t instance, lcb_CALLBACKTYPE, lcb_RESPSTATS *resp)
{
    char *statkey;
    lcb_size_t nstatkey;

    const char *server_endpoint = resp->server;
    const void *key = resp->key;
    lcb_size_t nkey = resp->nkey;
    const void *bytes = resp->value;
    lcb_size_t nbytes = resp->nvalue;

    ASSERT_EQ(LCB_SUCCESS, resp->rc);
    if (server_endpoint != NULL) {
        nstatkey = strlen(server_endpoint) + nkey + 2;
        statkey = new char[nstatkey];
        snprintf(statkey, nstatkey, "%s-%.*s", server_endpoint,
                 (int)nkey, (const char *)key);

        lcb_CMDSTORE cmd = {0};
        LCB_CMD_SET_KEY(&cmd, statkey, nstatkey);
        LCB_CMD_SET_VALUE(&cmd, bytes, nbytes);
        ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, NULL, &cmd));
        delete []statkey;
    }
}
}

TEST_F(MockUnitTest, testOpFromCallback)
{
    // @todo we need to have a test that actually tests the timeout callback..
    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);

    lcb_install_callback3(instance, LCB_CALLBACK_STATS, (lcb_RESPCALLBACK)opFromCallback_statsCB);
    lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)opFromCallback_storeCB);

    lcb_CMDSTATS stat = {0};
    ASSERT_EQ(LCB_SUCCESS, lcb_cntl_string(instance, "operation_timeout", "5.0"));
    ASSERT_EQ(LCB_SUCCESS, lcb_stats3(instance, NULL, &stat));
    lcb_wait(instance);
}

struct timeout_test_cookie {
    int *counter;
    lcb_error_t expected;
};
extern "C" {
static void set_callback(lcb_t instance, lcb_CALLBACKTYPE, lcb_RESPSTORE *resp)
{
    timeout_test_cookie *tc = (timeout_test_cookie*)resp->cookie;
    EXPECT_EQ(tc->expected, resp->rc);
    if (resp->rc == LCB_ETIMEDOUT) {
        // Remove the hiccup at the first timeout failure
        MockEnvironment::getInstance()->hiccupNodes(0, 0);
    }
    *tc->counter -= 1;
}

struct next_store_st {
    lcb_t instance;
    struct timeout_test_cookie *tc;
    lcb_CMDSTORE *cmdp;
};

static void reschedule_callback(void *cookie)
{
    lcb_error_t err;
    struct next_store_st *ns = (struct next_store_st *)cookie;
    lcb_log(LOGARGS(ns->instance, INFO), "Rescheduling operation..");
    err = lcb_store3(ns->instance, ns->tc, ns->cmdp);
    lcb_loop_unref(ns->instance);
    EXPECT_EQ(LCB_SUCCESS, err);
}

}

TEST_F(MockUnitTest, testTimeoutOnlyStale)
{
    SKIP_UNLESS_MOCK();

    HandleWrap hw;
    createConnection(hw);
    lcb_t instance = hw.getLcb();
    lcb_uint32_t tmoval = 1000000;
    int nremaining = 2;
    struct timeout_test_cookie cookies[2];
    MockEnvironment *mock = MockEnvironment::getInstance();

    // Set the timeout
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmoval);

    lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)set_callback);

    const char *key = "i'm a key";
    const char *value = "a value";

    removeKey(instance, key);

    // Make the mock timeout the first cookie. The extras length is:
    mock->hiccupNodes(1500, 1);


    lcb_CMDSTORE cmd = {0};
    LCB_CMD_SET_KEY(&cmd, key, strlen(key));
    LCB_CMD_SET_VALUE(&cmd, value, strlen(value));
    cmd.operation = LCB_SET;

    cookies[0].counter = &nremaining;
    cookies[0].expected = LCB_ETIMEDOUT;
    ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, cookies, &cmd));

    cookies[1].counter = &nremaining;
    cookies[1].expected = LCB_SUCCESS;
    struct next_store_st ns;
    ns.cmdp = &cmd;
    ns.tc = cookies + 1;
    ns.instance = instance;
    lcbio_pTIMER timer = lcbio_timer_new(instance->iotable, &ns, reschedule_callback);
    lcb_loop_ref(instance);
    lcbio_timer_rearm(timer, 900000);

    lcb_log(LOGARGS(instance, INFO), "Waiting..");
    lcb_wait(instance);
    lcbio_timer_destroy(timer);

    ASSERT_EQ(0, nremaining);
}


extern "C" {
    struct rvbuf {
        lcb_error_t error;
        lcb_cas_t cas1;
        lcb_cas_t cas2;
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

    static void store_callback(lcb_t instance, lcb_CALLBACKTYPE, lcb_RESPSTORE *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)resp->cookie;
        lcb_log(LOGARGS(instance, INFO),
                "Got storage callback for cookie %p with err=0x%x",
                (void *)resp->cookie,
                (int)resp->rc);

        rv->error = resp->rc;
        store_cnt++;
        if (!instance->wait) { /* do not touch IO if we are using lcb_wait() */
            lcb_stop_loop(instance);
        }
    }

    static void get_callback(lcb_t instance, lcb_CALLBACKTYPE, lcb_RESPGET *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)resp->cookie;
        rv->error = resp->rc;
        rv->bytes = (char *)malloc(resp->nvalue);
        memcpy((void *)rv->bytes, resp->value, resp->nvalue);
        rv->nbytes = resp->nvalue;
        if (!instance->wait) { /* do not touch IO if we are using lcb_wait() */
            lcb_stop_loop(instance);
        }
    }
}

struct StoreContext {
    std::map<std::string, lcb_error_t> mm;
    typedef std::map<std::string, lcb_error_t>::iterator MyIter;

    void check(int expected) {
        EXPECT_EQ(expected, mm.size());

        for (MyIter iter = mm.begin(); iter != mm.end(); iter++) {
            EXPECT_EQ(LCB_SUCCESS, iter->second);
        }
    }

    void clear() {
        mm.clear();
    }
};

extern "C" {
static void ctx_store_callback(lcb_t, lcb_CALLBACKTYPE, const lcb_RESPSTORE *resp)
{
    StoreContext *ctx = reinterpret_cast<StoreContext *>(
            const_cast<void *>(resp->cookie));

    std::string s((const char *)resp->key, resp->nkey);
    ctx->mm[s] = resp->rc;
}
}

TEST_F(MockUnitTest, testReconfigurationOnNodeFailover)
{
    SKIP_UNLESS_MOCK();
    lcb_t instance;
    HandleWrap hw;
    lcb_error_t err;
    const char *argv[] = { "--replicas", "0", "--nodes", "4", NULL };

    MockEnvironment mock_o(argv), *mock = &mock_o;

    std::vector<std::string> keys;
    std::vector<lcb_CMDSTORE> cmds;

    mock->createConnection(hw, instance);
    instance->settings->vb_noguess = 1;
    lcb_connect(instance);
    lcb_wait(instance);
    ASSERT_EQ(0, lcb_get_num_replicas(instance));

    size_t numNodes = mock->getNumNodes();

    genDistKeys(LCBT_VBCONFIG(instance), keys);
    genStoreCommands(keys, cmds);
    StoreContext ctx;

    mock->failoverNode(0);
    SYNC_WITH_NODECOUNT(instance, numNodes-1);

    lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)ctx_store_callback);
    for (int i = 0; i < cmds.size(); i++) {
        ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, &ctx, &cmds[i]));
    }
    lcb_wait(instance);
    ctx.check((int)cmds.size());

    mock->respawnNode(0);
    SYNC_WITH_NODECOUNT(instance, numNodes);

    ctx.clear();
    for (int i = 0; i < cmds.size(); i++) {
        ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, &ctx, &cmds[i]));
    }
    lcb_wait(instance);
    ctx.check((int)cmds.size());
}



struct fo_context_st {
    MockEnvironment *env;
    int index;
    lcb_t instance;
};
// Hiccup the server, then fail it over.
extern "C" {
static void fo_callback(void *cookie)
{
    fo_context_st *ctx = (fo_context_st *)cookie;
    ctx->env->failoverNode(ctx->index);
    ctx->env->hiccupNodes(0, 0);
    lcb_loop_unref(ctx->instance);
}
}

TEST_F(MockUnitTest, testBufferRelocationOnNodeFailover)
{
    SKIP_UNLESS_MOCK();
    lcb_error_t err;
    struct rvbuf rv;
    lcb_t instance;
    HandleWrap hw;
    std::string key = "testBufferRelocationOnNodeFailover";
    std::string val = "foo";

    const char *argv[] = { "--replicas", "0", "--nodes", "4", NULL };
    MockEnvironment mock_o(argv), *mock = &mock_o;

    // We need to disable CCCP for this test to receive "Push" style
    // configuration.
    mock->setCCCP(false);

    mock->createConnection(hw, instance);
    lcb_connect(instance);
    lcb_wait(instance);

    // Set the timeout for 15 seconds
    lcb_uint32_t tmoval = 15000000;
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmoval);

    lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)store_callback);
    lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);

    // Initialize the nodes first..
    removeKey(instance, key);

    /* Schedule SET operation */
    lcb_CMDSTORE storecmd = {0};
    LCB_CMD_SET_KEY(&storecmd, key.c_str(), key.size());
    LCB_CMD_SET_VALUE(&storecmd, val.c_str(), val.size());
    storecmd.operation = LCB_SET;

    /* Determine what server should receive that operation */
    int vb, idx;
    lcbvb_map_key(LCBT_VBCONFIG(instance), key.c_str(), key.size(), &vb, &idx);
    mock->hiccupNodes(5000, 1);

    struct fo_context_st ctx = { mock, idx, instance };
    lcbio_pTIMER timer;
    timer = lcbio_timer_new(instance->iotable, &ctx, fo_callback);
    lcb_loop_ref(instance);
    lcbio_timer_rearm(timer, 500000);

    ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, &rv, &storecmd));

    store_cnt = 0;
    lcb_wait(instance);
    ASSERT_EQ(1, store_cnt);
    ASSERT_EQ(LCB_SUCCESS, rv.error);

    memset(&rv, 0, sizeof(rv));
    ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, &rv, &storecmd));
    store_cnt = 0;
    lcb_wait(instance);
    ASSERT_EQ(1, store_cnt);

    /* Check that value was actually set */
    lcb_CMDGET getcmd = {0};
    LCB_CMD_SET_KEY(&getcmd, key.c_str(), key.size());
    ASSERT_EQ(LCB_SUCCESS, lcb_get3(instance, &rv, &getcmd));

    lcb_wait(instance);
    lcbio_timer_destroy(timer);
    ASSERT_EQ(LCB_SUCCESS, rv.error);
    ASSERT_EQ(rv.nbytes, val.size());
    std::string bytes = std::string(rv.bytes, rv.nbytes);
    ASSERT_STREQ(bytes.c_str(), val.c_str());
    free(rv.bytes);
}

TEST_F(MockUnitTest, testSaslMechs)
{
    // Ensure our SASL mech listing works.
    SKIP_UNLESS_MOCK();

    const char *argv[] = { "--buckets", "protected:secret:couchbase", NULL };

    lcb_t instance;
    lcb_error_t err;
    struct lcb_create_st crParams;
    MockEnvironment mock_o(argv, "protected"), *protectedEnv = &mock_o;
    protectedEnv->makeConnectParams(crParams, NULL);
    protectedEnv->setCCCP(false);

    crParams.v.v0.user = "protected";
    crParams.v.v0.passwd = "secret";
    crParams.v.v0.bucket = "protected";
    doLcbCreate(&instance, &crParams, protectedEnv);

    // Make the socket pool disallow idle connections
    instance->memd_sockpool->get_options().maxidle = 0;

    err = lcb_connect(instance);
    ASSERT_EQ(LCB_SUCCESS, err);
    lcb_wait(instance);

    // Force our SASL mech
    err = lcb_cntl(instance, LCB_CNTL_SET,
                   LCB_CNTL_FORCE_SASL_MECH, (void *)"blah");
    ASSERT_EQ(LCB_SUCCESS, err);

    Item itm("key", "value");
    KVOperation kvo(&itm);

    kvo.allowableErrors.insert(LCB_SASLMECH_UNAVAILABLE);
    kvo.allowableErrors.insert(LCB_ETIMEDOUT);
    kvo.store(instance);

    ASSERT_FALSE(kvo.globalErrors.find(LCB_SASLMECH_UNAVAILABLE) ==
              kvo.globalErrors.end());

    err = lcb_cntl(instance, LCB_CNTL_SET,
                   LCB_CNTL_FORCE_SASL_MECH, (void *)"PLAIN");
    ASSERT_EQ(LCB_SUCCESS, err);

    kvo.clear();
    kvo.store(instance);

    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testSaslSHA)
{
    // Ensure our SASL mech listing works.
    SKIP_UNLESS_MOCK();

    const char *argv[] = { "--buckets", "protected:secret:couchbase", NULL };

    lcb_t instance = NULL;
    lcb_error_t err;
    struct lcb_create_st crParams;
    MockEnvironment mock_o(argv, "protected"), *protectedEnv = &mock_o;
    protectedEnv->makeConnectParams(crParams, NULL);
    protectedEnv->setCCCP(false);

    crParams.v.v2.user = "protected";
    crParams.v.v2.passwd = "secret";
    crParams.v.v2.bucket = "protected";
    crParams.v.v2.mchosts = NULL;

    {
        doLcbCreate(&instance, &crParams, protectedEnv);

        // Make the socket pool disallow idle connections
        instance->memd_sockpool->get_options().maxidle = 0;

        ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
        ASSERT_EQ(LCB_SUCCESS, lcb_wait(instance));

        err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_FORCE_SASL_MECH, (void *)"SCRAM-SHA512");
        ASSERT_EQ(LCB_SUCCESS, err);

        Item itm("key", "value");
        KVOperation kvo(&itm);

        kvo.allowableErrors.insert(LCB_SASLMECH_UNAVAILABLE);
        kvo.allowableErrors.insert(LCB_ETIMEDOUT);
        kvo.store(instance);

        ASSERT_FALSE(kvo.globalErrors.find(LCB_SASLMECH_UNAVAILABLE) == kvo.globalErrors.end());

        lcb_destroy(instance);
    }

    std::vector<std::string> mechs;
    mechs.push_back("SCRAM-SHA512");
    protectedEnv->setSaslMechs(mechs);

    {
        instance = NULL;
        doLcbCreate(&instance, &crParams, protectedEnv);

        // Make the socket pool disallow idle connections
        instance->memd_sockpool->get_options().maxidle = 0;

        ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
        ASSERT_EQ(LCB_SUCCESS, lcb_wait(instance));

        Item itm("key", "value");
        KVOperation kvo(&itm);

        kvo.allowableErrors.insert(LCB_SASLMECH_UNAVAILABLE);
        kvo.allowableErrors.insert(LCB_ETIMEDOUT);
        kvo.store(instance);

#ifndef LCB_NO_SSL
        err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_FORCE_SASL_MECH, (void *)"SCRAM-SHA512");
        ASSERT_EQ(LCB_SUCCESS, err);

        kvo.clear();
        kvo.store(instance);
#endif

        lcb_destroy(instance);
    }
}


extern "C" {
static const char *get_username(void *cookie, const char *host, const char *port, const char *bucket)
{
    return bucket;
}

static const char *get_password(void *cookie, const char *host, const char *port, const char *bucket)
{
    std::map< std::string, std::string > *credentials = static_cast< std::map< std::string, std::string > * >(cookie);
    return (*credentials)[bucket].c_str();
}
}

TEST_F(MockUnitTest, testDynamicAuth)
{
    SKIP_UNLESS_MOCK();

    const char *argv[] = {"--buckets", "protected:secret:couchbase", NULL};

    lcb_t instance;
    lcb_error_t err;
    struct lcb_create_st crParams;
    MockEnvironment mock_o(argv, "protected"), *mock = &mock_o;
    mock->makeConnectParams(crParams, NULL);
    mock->setCCCP(false);

    crParams.v.v0.bucket = "protected";
    doLcbCreate(&instance, &crParams, mock);

    std::map< std::string, std::string > credentials;
    credentials["protected"] = "secret";
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcbauth_set_callbacks(auth, &credentials, get_username, get_password);
    lcbauth_set_mode(auth, LCBAUTH_MODE_DYNAMIC);
    lcb_set_auth(instance, auth);

    err = lcb_connect(instance);
    ASSERT_EQ(LCB_SUCCESS, err);
    ASSERT_EQ(LCB_SUCCESS, lcb_wait(instance));

    Item itm("key", "value");
    KVOperation kvo(&itm);
    kvo.store(instance);
    lcb_destroy(instance);
    lcbauth_unref(auth);
}

static void
doManyItems(lcb_t instance, std::vector<std::string> keys)
{
    lcb_CMDSTORE cmd = { 0 };
    cmd.operation = LCB_SET;
    lcb_sched_enter(instance);
    for (size_t ii = 0; ii < keys.size(); ii++) {
        LCB_CMD_SET_KEY(&cmd, keys[ii].c_str(), keys[ii].size());
        LCB_CMD_SET_VALUE(&cmd, keys[ii].c_str(), keys[ii].size());
        EXPECT_EQ(LCB_SUCCESS, lcb_store3(instance, NULL, &cmd));
    }
    lcb_sched_leave(instance);
    lcb_wait(instance);
}

extern "C" {
static void mcdFoVerifyCb(lcb_t, int, const lcb_RESPBASE *rb)
{
    EXPECT_EQ(LCB_SUCCESS, rb->rc);
}
}

TEST_F(MockUnitTest, DISABLED_testMemcachedFailover)
{
    SKIP_UNLESS_MOCK();
    const char *argv[] = { "--buckets", "cache::memcache", NULL };
    lcb_t instance;
    struct lcb_create_st crParams;
    lcb_RESPCALLBACK oldCb;

    MockEnvironment mock_o(argv, "cache"), *mock = &mock_o;
    mock->makeConnectParams(crParams, NULL);
    doLcbCreate(&instance, &crParams, mock);

    // Check internal setting here
    lcb_connect(instance);
    lcb_wait(instance);
    size_t numNodes = mock->getNumNodes();

    oldCb = lcb_install_callback3(instance, LCB_CALLBACK_STORE, mcdFoVerifyCb);

    // Get the command list:
    std::vector<std::string> distKeys;
    genDistKeys(LCBT_VBCONFIG(instance), distKeys);
    doManyItems(instance, distKeys);
    // Should succeed implicitly with callback above

    // Fail over the first node..
    mock->failoverNode(1, "cache");
    SYNC_WITH_NODECOUNT(instance, numNodes-1);

    // Set the callback to the previous one. We expect failures here
    lcb_install_callback3(instance, LCB_CALLBACK_STORE, oldCb);
    doManyItems(instance, distKeys);

    mock->respawnNode(1, "cache");
    SYNC_WITH_NODECOUNT(instance, numNodes);
    ASSERT_EQ(numNodes, lcb_get_num_nodes(instance));

    // Restore the verify callback
    lcb_install_callback3(instance, LCB_CALLBACK_STORE, mcdFoVerifyCb);
    doManyItems(instance, distKeys);

    lcb_destroy(instance);
}

struct NegativeIx {
    lcb_error_t err;
    int callCount;
};

extern "C" {
static void get_callback3(lcb_t, int, const lcb_RESPBASE *resp)
{
    NegativeIx *ni = (NegativeIx *)resp->cookie;
    ni->err = resp->rc;
    ni->callCount++;
}
}
/**
 * This tests the case where a negative index appears for a vbucket ID for the
 * mapped key. In this case we'd expect that the command would be retried
 * at least once, and not receive an LCB_NO_MATCHING_SERVER.
 *
 * Unfortunately this test is a bit hacky since we need to modify the vbucket
 * information, and hopefully get a new config afterwards. Additionally we'd
 * want to mod
 */
TEST_F(MockUnitTest, testNegativeIndex)
{
    HandleWrap hw;
    lcb_t instance;
    createConnection(hw, instance);
    lcb_install_callback3(instance, LCB_CALLBACK_GET, get_callback3);
    std::string key("ni_key");
    // Get the config
    lcbvb_CONFIG *vbc = instance->cur_configinfo->vbc;
    int vb = lcbvb_k2vb(vbc, key.c_str(), key.size());

    // Set the index to -1
    vbc->vbuckets[vb].servers[0] = -1;
    NegativeIx ni = { LCB_SUCCESS };
    lcb_CMDGET gcmd = { 0 };
    LCB_CMD_SET_KEY(&gcmd, key.c_str(), key.size());
    // Set the timeout to something a bit shorter
    lcb_cntl_setu32(instance, LCB_CNTL_OP_TIMEOUT, 500000);

    lcb_sched_enter(instance);
    lcb_error_t err = lcb_get3(instance, &ni, &gcmd);
    ASSERT_EQ(LCB_SUCCESS, err);
    lcb_sched_leave(instance);
    lcb_wait(instance);
    ASSERT_EQ(1, ni.callCount);
    // That's it
}
