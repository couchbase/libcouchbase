/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012-2018 Couchbase, Inc.
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
#include <gtest/gtest.h>
#include "iotests.h"
using std::vector;
using std::string;

// This file contains the 'migrated' tests from smoke-test.c

static lcb_config_transport_t transports[] = {
        LCB_CONFIG_TRANSPORT_HTTP, LCB_CONFIG_TRANSPORT_LIST_END };
struct rvbuf {
    lcb_error_t error;
    lcb_storage_t operation;
    vector<char> bytes;
    vector<char> key;
    lcb_cas_t cas;
    lcb_uint32_t flags;
    lcb_int32_t counter;
    lcb_uint32_t errorCount;

    template <typename T> void setKey(const T* resp) {
        const char *ktmp, *kend;
        ktmp = (const char*)resp->key;
        kend = ktmp + resp->nkey;
        key.assign(ktmp, kend);
    }

    void setValue(const lcb_RESPGET *resp) {
        const char *btmp = (const char*)resp->value;
        const char *bend = btmp + resp->nvalue;
        bytes.assign(btmp, bend);
    }

    string getKeyString() {
        return string(key.begin(), key.end());
    }

    string getValueString() {
        return string(bytes.begin(), bytes.end());
    }

    rvbuf() {
        reset();
    }

    void reset() {
        error = LCB_SUCCESS;
        operation = LCB_SET;
        cas = 0;
        flags = 0;
        counter = 0;
        errorCount = 0;
        key.clear();
        bytes.clear();
    }

    void setError(lcb_error_t err) {
        EXPECT_GT(counter, 0);
        counter--;
        if (err != LCB_SUCCESS) {
            error = err;
            errorCount++;
        }
    }
    void incRemaining() { counter++; }
};

extern "C"
{
static void store_callback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPSTORE *resp)
{
    rvbuf *rv = (rvbuf *)resp->cookie;
    rv->setError(resp->rc);
    rv->setKey(resp);
    rv->operation = resp->op;
}

static void get_callback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPGET *resp)
{
    rvbuf *rv = (rvbuf*)resp->cookie;
    rv->setError(resp->rc);
    rv->setKey(resp);
    if (resp->rc == LCB_SUCCESS) {
        rv->setValue(resp);
    }
}

static void touch_callback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPTOUCH *resp)
{
    rvbuf *rv = (rvbuf *)resp->cookie;
    rv->setError(resp->rc);
    rv->setKey(resp);
    EXPECT_EQ(LCB_SUCCESS, resp->rc);
}

static void version_callback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPMCVERSION *resp)
{
    const char *server_endpoint = (const char *)resp->server;
    const char *vstring = (const char *)resp->mcversion;
    lcb_size_t nvstring = resp->nversion;
    rvbuf *rv = (rvbuf *)resp->cookie;
    char *str;
    EXPECT_EQ(LCB_SUCCESS, resp->rc);

    if (server_endpoint == NULL) {
        assert(rv->counter == 0);
        return;
    }

    rv->setError(resp->rc);
    /*copy the key to an allocated buffer and ensure the key read from vstring
     * will not segfault
     */
    str = (char *)malloc(nvstring);
    memcpy(str, vstring, nvstring);
    free(str);
}
} //extern "C"
static void
setupCallbacks(lcb_t instance)
{
    lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)store_callback);
    lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);
    lcb_install_callback3(instance, LCB_CALLBACK_TOUCH, (lcb_RESPCALLBACK)touch_callback);
    lcb_install_callback3(instance, LCB_CALLBACK_VERSIONS, (lcb_RESPCALLBACK)version_callback);
}

class SmokeTest : public ::testing::Test
{
protected:
    MockEnvironment *mock;
    lcb_t session;
    void SetUp() {
        assert(session == NULL);
        session = NULL;
        mock = NULL;
    }

    void TearDown() {
        if (session != NULL) {
            lcb_destroy(session);
        }
        if (mock != NULL) {
            delete mock;
        }

        session = NULL;
        mock = NULL;
    }
    void destroySession() {
        if (session != NULL) {
            lcb_destroy(session);
            session = NULL;
        }
    }

    SmokeTest() : mock(NULL), session(NULL) {}
public:
    void testSet1();
    void testSet2();
    void testGet1();
    void testGet2();
    void testTouch1();
    void testVersion1();
    void testSpuriousSaslError();
    lcb_error_t testMissingBucket();

    // Call to connect instance
    void connectCommon(const char *password = NULL, lcb_error_t expected = LCB_SUCCESS);
};

void
SmokeTest::testSet1()
{
    rvbuf rv;
    lcb_CMDSTORE cmd = {0};

    string key("foo");
    string value("bar");

    LCB_CMD_SET_KEY(&cmd, key.c_str(), key.size());
    LCB_CMD_SET_VALUE(&cmd, value.c_str(), value.size());
    cmd.operation = LCB_SET;
    EXPECT_EQ(LCB_SUCCESS, lcb_store3(session, &rv, &cmd));
    rv.incRemaining();
    lcb_wait(session);
    EXPECT_EQ(LCB_SUCCESS, rv.error);
    EXPECT_EQ(LCB_SET, rv.operation);
    EXPECT_EQ(key, rv.getKeyString());
}

void
SmokeTest::testSet2()
{
    struct rvbuf rv;
    lcb_size_t ii;
    lcb_CMDSTORE cmd = {0};
    string key("foo"), value("bar");

    LCB_CMD_SET_KEY(&cmd, key.c_str(), key.size());
    LCB_CMD_SET_VALUE(&cmd, value.c_str(), value.size());
    cmd.operation = LCB_SET;

    rv.errorCount = 0;
    rv.counter = 0;
    for (ii = 0; ii < 10; ++ii, rv.incRemaining()) {
        EXPECT_EQ(LCB_SUCCESS, lcb_store3(session, &rv, &cmd));
    }
    lcb_wait(session);
    EXPECT_EQ(0, rv.errorCount);
}

void
SmokeTest::testGet1()
{
    lcb_error_t err;
    struct rvbuf rv;
    string key("foo"), value("bar");

    lcb_CMDSTORE storecmd = {0};
    LCB_CMD_SET_KEY(&storecmd, key.c_str(), key.size());
    LCB_CMD_SET_VALUE(&storecmd, value.c_str(), value.size());
    storecmd.operation = LCB_SET;
    EXPECT_EQ(LCB_SUCCESS, lcb_store3(session, &rv, &storecmd));
    rv.incRemaining();

    lcb_wait(session);
    EXPECT_EQ(LCB_SUCCESS, rv.error);

    rv.reset();

    lcb_CMDGET getcmd = {0};
    LCB_CMD_SET_KEY(&getcmd, key.c_str(), key.size());
    EXPECT_EQ(LCB_SUCCESS, lcb_get3(session, &rv, &getcmd));
    rv.incRemaining();
    lcb_wait(session);

    EXPECT_EQ(rv.error, LCB_SUCCESS);
    EXPECT_EQ(key, rv.getKeyString());
    EXPECT_EQ(value, rv.getValueString());
}

static void
genAZString(vector<string>& coll)
{
    string base("foo");
    for (size_t ii = 0; ii < 26; ++ii) {
        coll.push_back(base);
        coll.back() += ('a' + ii);
    }
}

void
SmokeTest::testGet2()
{
    struct rvbuf rv;
    string value("bar");
    vector<string> coll;
    genAZString(coll);

    for (size_t ii = 0; ii < coll.size(); ii++) {
        const string& curKey = coll[ii];

        lcb_CMDSTORE cmd = {0};
        LCB_CMD_SET_KEY(&cmd, curKey.c_str(), curKey.size());
        LCB_CMD_SET_VALUE(&cmd, value.c_str(), value.size());
        cmd.operation = LCB_SET;
        EXPECT_EQ(LCB_SUCCESS, lcb_store3(session, &rv, &cmd));
        rv.incRemaining();
        lcb_wait(session);
        EXPECT_EQ(LCB_SUCCESS, rv.error);

        rv.reset();
    }

    rv.counter = coll.size();

    for (size_t ii = 0; ii < coll.size(); ii++) {
        const string& curKey = coll[ii];

        lcb_CMDGET cmd = {0};
        LCB_CMD_SET_KEY(&cmd, curKey.c_str(), curKey.size());
        EXPECT_EQ(LCB_SUCCESS, lcb_get3(session, &rv, &cmd));
        rv.incRemaining();
    }
    lcb_wait(session);
    EXPECT_EQ(LCB_SUCCESS, rv.error);
    EXPECT_EQ(value, rv.getValueString());
}

void
SmokeTest::testTouch1()
{
    struct rvbuf rv;
    vector<string> coll;
    string value("bar");
    genAZString(coll);

    for (size_t ii = 0; ii < coll.size(); ii++) {
        const string& curKey = coll[ii];
        lcb_CMDSTORE cmd = {0};
        LCB_CMD_SET_KEY(&cmd, curKey.c_str(), curKey.size());
        LCB_CMD_SET_VALUE(&cmd, value.c_str(), value.size());
        cmd.operation = LCB_SET;
        EXPECT_EQ(LCB_SUCCESS, lcb_store3(session, &rv, &cmd));

        rv.incRemaining();
        lcb_wait(session);
        EXPECT_EQ(LCB_SUCCESS, rv.error);

        rv.reset();
    }

    rv.counter = coll.size();
    for (size_t ii = 0; ii < coll.size(); ii++) {
        const string& curKey = coll[ii];

        lcb_CMDTOUCH cmd = {0};
        LCB_CMD_SET_KEY(&cmd, curKey.c_str(), curKey.size());
        EXPECT_EQ(LCB_SUCCESS, lcb_touch3(session, &rv, &cmd));
        rv.incRemaining();
    }

    lcb_wait(session);
    EXPECT_EQ(LCB_SUCCESS, rv.error);
}

void
SmokeTest::testVersion1()
{
    struct rvbuf rv;
    lcb_CMDBASE cmd = {0};

    EXPECT_EQ(LCB_SUCCESS, lcb_server_versions3(session, &rv, &cmd));
    rv.counter = mock->getNumNodes();
    lcb_wait(session);
    EXPECT_EQ(LCB_SUCCESS, rv.error);
    EXPECT_EQ(0, rv.counter);
}

lcb_error_t
SmokeTest::testMissingBucket()
{
    destroySession();
    // create a new session
    lcb_create_st cropts;
    mock->makeConnectParams(cropts);
    cropts.v.v2.transports = transports;
    cropts.v.v2.bucket = "nonexist";
    cropts.v.v2.user = "nonexist";
    lcb_error_t err;
    err = lcb_create(&session, &cropts);
    EXPECT_EQ(LCB_SUCCESS, err);
    mock->postCreate(session);

    err = lcb_connect(session);
    EXPECT_EQ(LCB_SUCCESS, err);
    lcb_wait(session);
    err = lcb_get_bootstrap_status(session);
    EXPECT_NE(LCB_SUCCESS, err);
    EXPECT_TRUE(err == LCB_BUCKET_ENOENT||err == LCB_AUTH_ERROR);
    destroySession();
    return err;
}

void
SmokeTest::testSpuriousSaslError()
{
    int iterations = 50;
    rvbuf rvs[50];
    int i;
    string key("KEY");

    for (i = 0; i < iterations; i++) {
        rvs[i].counter = 999;

        lcb_CMDSTORE cmd = {0};
        LCB_CMD_SET_KEY(&cmd, key.c_str(), key.size());
        LCB_CMD_SET_VALUE(&cmd, key.c_str(), key.size());
        cmd.operation = LCB_SET;
        EXPECT_EQ(LCB_SUCCESS, lcb_store3(session, rvs + i, &cmd));
    }
    lcb_wait(session);

    for (i = 0; i < iterations; i++) {
        const char *errinfo = NULL;
        if (rvs[i].errorCount != LCB_SUCCESS) {
            errinfo = "Did not get success response";
        } else if (rvs[i].key.size() != 3) {
            errinfo = "Did not get expected key length";
        } else if (rvs[i].getKeyString() != key) {
            errinfo = "Weird key size";
        }
        if (errinfo) {
            EXPECT_FALSE(true) << errinfo;
        }
    }
}

void
SmokeTest::connectCommon(const char *password, lcb_error_t expected)
{
    lcb_create_st cropts;
    mock->makeConnectParams(cropts, NULL);

    if (password != NULL) {
        cropts.v.v2.passwd = password;
    }
    cropts.v.v2.transports = transports;
    lcb_error_t err = lcb_create(&session, &cropts);
    EXPECT_EQ(LCB_SUCCESS, err);

    mock->postCreate(session);
    err = lcb_connect(session);
    EXPECT_EQ(LCB_SUCCESS, err);
    lcb_wait(session);
    EXPECT_EQ(expected, lcb_get_bootstrap_status(session));
    setupCallbacks(session);
}

TEST_F(SmokeTest, testMemcachedBucket)
{
    SKIP_UNLESS_MOCK();
    const char *args[] = { "--buckets", "default::memcache", NULL };
    mock = new MockEnvironment(args);
    mock->setCCCP(false);
    connectCommon();
    testSet1();
    testSet2();
    testGet1();
    testGet2();
    testVersion1();

    // A bit out of place, but check that replica commands fail at schedule-time
    lcb_sched_enter(session);
    lcb_CMDGETREPLICA cmd = { 0 };
    LCB_CMD_SET_KEY(&cmd, "key", 3);
    lcb_error_t rc;

    cmd.strategy = LCB_REPLICA_FIRST;
    rc = lcb_rget3(session, NULL, &cmd);
    ASSERT_EQ(LCB_NO_MATCHING_SERVER, rc);

    cmd.strategy = LCB_REPLICA_ALL;
    rc = lcb_rget3(session, NULL, &cmd);
    ASSERT_EQ(LCB_NO_MATCHING_SERVER, rc);

    cmd.strategy = LCB_REPLICA_SELECT;
    cmd.index = 0;
    rc = lcb_rget3(session, NULL, &cmd);
    ASSERT_EQ(LCB_NO_MATCHING_SERVER, rc);


    testMissingBucket();
}

TEST_F(SmokeTest, testCouchbaseBucket)
{
    SKIP_UNLESS_MOCK();
    const char *args[] = { "--buckets", "default::couchbase", "--debug", NULL };
    mock = new MockEnvironment(args);
    mock->setCCCP(false);
    connectCommon();
    testSet1();
    testSet2();
    testGet1();
    testGet2();
    testVersion1();
    testMissingBucket();
}

TEST_F(SmokeTest, testSaslBucket)
{
    SKIP_UNLESS_MOCK();
    const char *args[] = { "--buckets", "protected:secret:couchbase", NULL };
    mock = new MockEnvironment(args, "protected");
    mock->setCCCP(false);


    testMissingBucket();

    connectCommon("secret");
    testSpuriousSaslError();

    destroySession();
    connectCommon("incorrect", LCB_AUTH_ERROR);
    destroySession();
}
