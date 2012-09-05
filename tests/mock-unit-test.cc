/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>

#include "server.h"
#include "mock-unit-test.h"


const void *MockUnitTest::mock;
const char *MockUnitTest::http;
int MockUnitTest::numNodes;

void MockUnitTest::SetUpTestCase()
{
    numNodes = 10;
    mock = start_mock_server(NULL);
    ASSERT_NE((const void *)(NULL), mock);
    http = get_mock_http_server(mock);
    ASSERT_NE((const char *)(NULL), http);
}

void MockUnitTest::TearDownTestCase()
{
    shutdown_mock_server(mock);
}

/*
 * Test cases
 */
extern "C" {
    static void error_callback(lcb_t instance,
                               lcb_error_t err,
                               const char *errinfo)
    {
        std::cerr << "Error " << lcb_strerror(instance, err);
        if (errinfo) {
            std::cerr << errinfo;
        }

        ASSERT_TRUE(false);
    }
}

void MockUnitTest::createConnection(lcb_t &instance)
{
    struct lcb_io_opt_st *io;

    io = get_test_io_opts();
    if (io == NULL) {
        fprintf(stderr, "Failed to create IO instance\n");
        exit(1);
    }

    lcb_create_st options(http, "Administrator", "password",
                          getenv("LCB_TEST_BUCKET"), io);

    ASSERT_EQ(LCB_SUCCESS, lcb_create(&instance, &options));
    (void)lcb_set_cookie(instance, io);
    (void)lcb_set_error_callback(instance, error_callback);
    ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
    lcb_wait(instance);
}

extern "C" {
    static void testGetMissGetCallback(lcb_t, const void *cookie,
                                       lcb_error_t error,
                                       const lcb_get_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_EQ(LCB_KEY_ENOENT, error);
        ASSERT_NE((const lcb_get_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        std::string val((const char*)resp->v.v0.key, resp->v.v0.nkey);
        EXPECT_TRUE(val == "testGetMiss1" || val == "testGetMiss2");
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testGetMiss)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_get_callback(instance, testGetMissGetCallback);
    int numcallbacks = 0;

    lcb_get_cmd_t cmd1("testGetMiss1");
    lcb_get_cmd_t cmd2("testGetMiss2");
    lcb_get_cmd_t *cmds[] = { &cmd1, &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_get(instance, &numcallbacks, 2, cmds));

    lcb_wait(instance);
    EXPECT_EQ(2, numcallbacks);
}

extern "C" {
    static void testSimpleSetStoreCallback(lcb_t, const void *cookie,
                                           lcb_storage_t operation,
                                           lcb_error_t error,
                                           const lcb_store_resp_t *resp)
    {
        using namespace std;
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_SET, operation);
        EXPECT_EQ(LCB_SUCCESS, error);
        ASSERT_NE((const lcb_store_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        std::string val((const char*)resp->v.v0.key, resp->v.v0.nkey);
        EXPECT_TRUE(val == "testSimpleStoreKey1" || val == "testSimpleStoreKey2");
        ++(*counter);
        EXPECT_NE(0, resp->v.v0.cas);
    }
}

TEST_F(MockUnitTest, testSimpleSet)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, testSimpleSetStoreCallback);
    int numcallbacks = 0;
    lcb_store_cmd_t cmd1(LCB_SET, "testSimpleStoreKey1", 19, "key1", 4);
    lcb_store_cmd_t cmd2(LCB_SET, "testSimpleStoreKey2", 19, "key2", 4);
    lcb_store_cmd_t* cmds[] = { &cmd1, &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &numcallbacks, 2, cmds));
    lcb_wait(instance);
    EXPECT_EQ(2, numcallbacks);
}

extern "C" {
    static void testGetHitGetCallback(lcb_t, const void *cookie,
                                      lcb_error_t error,
                                      const lcb_get_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_EQ(LCB_SUCCESS, error);
        ASSERT_NE((const lcb_get_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testGetHit)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_get_callback(instance, testGetHitGetCallback);
    int numcallbacks = 0;

    utilStoreKey(instance, "testGetKey1", "foo");
    utilStoreKey(instance, "testGetKey2", "foo");
    lcb_get_cmd_t cmd1("testGetKey1");
    lcb_get_cmd_t cmd2("testGetKey2");
    lcb_get_cmd_t *cmds[] = { &cmd1, &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_get(instance, &numcallbacks, 2, cmds));

    lcb_wait(instance);
    EXPECT_EQ(2, numcallbacks);
}

extern "C" {
    static void testRemoveCallback(lcb_t, const void *cookie,
                                   lcb_error_t error,
                                   const lcb_remove_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_EQ(LCB_SUCCESS, error);
        ASSERT_NE((const lcb_remove_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testRemove)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_remove_callback(instance, testRemoveCallback);
    int numcallbacks = 0;
    utilStoreKey(instance, "testRemoveKey1", "foo");
    utilStoreKey(instance, "testRemoveKey2", "foo");
    lcb_remove_cmd_t cmd1("testRemoveKey1");
    lcb_remove_cmd_t cmd2("testRemoveKey2");
    lcb_remove_cmd_t *cmds[] = { &cmd1, &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_remove(instance, &numcallbacks, 2, cmds));

    lcb_wait(instance);
    EXPECT_EQ(2, numcallbacks);
}

extern "C" {
    static void testRemoveMissCallback(lcb_t, const void *cookie,
                                   lcb_error_t error,
                                   const lcb_remove_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_EQ(LCB_KEY_ENOENT, error);
        ASSERT_NE((const lcb_remove_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testRemoveMiss)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_remove_callback(instance, testRemoveMissCallback);
    int numcallbacks = 0;
    utilRemoveKey(instance, "testRemoveMissKey1");
    utilRemoveKey(instance, "testRemoveMissKey2");
    lcb_remove_cmd_t cmd1("testRemoveMissKey1");
    lcb_remove_cmd_t cmd2("testRemoveMissKey2");
    lcb_remove_cmd_t *cmds[] = { &cmd1, &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_remove(instance, &numcallbacks, 2, cmds));

    lcb_wait(instance);
    EXPECT_EQ(2, numcallbacks);
}

extern "C" {
    static void testSimpleAddStoreCallback(lcb_t, const void *cookie,
                                           lcb_storage_t operation,
                                           lcb_error_t error,
                                           const lcb_store_resp_t *resp)
    {
        using namespace std;
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_ADD, operation);
        ASSERT_NE((const lcb_store_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        std::string val((const char*)resp->v.v0.key, resp->v.v0.nkey);
        EXPECT_STREQ("testSimpleAddKey", val.c_str());
        if (*counter == 0) {
            EXPECT_EQ(LCB_SUCCESS, error);
            EXPECT_NE(0, resp->v.v0.cas);
        } else {
            EXPECT_EQ(LCB_KEY_EEXISTS, error);
        }
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testSimpleAdd)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, testSimpleAddStoreCallback);
    utilRemoveKey(instance, "testSimpleAddKey");
    int numcallbacks = 0;
    lcb_store_cmd_t cmd1(LCB_ADD, "testSimpleAddKey", 16, "key1", 4);
    lcb_store_cmd_t cmd2(LCB_ADD, "testSimpleAddKey", 16, "key2", 4);
    lcb_store_cmd_t* cmds[] = { &cmd1, &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &numcallbacks, 2, cmds));
    lcb_wait(instance);
    EXPECT_EQ(2, numcallbacks);
}

extern "C" {
    static void testSimpleAppendStoreCallback(lcb_t, const void *cookie,
                                              lcb_storage_t operation,
                                              lcb_error_t error,
                                              const lcb_store_resp_t *resp)
    {
        using namespace std;
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_APPEND, operation);
        ASSERT_NE((const lcb_store_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        EXPECT_EQ(LCB_SUCCESS, error);
        EXPECT_NE(0, resp->v.v0.cas);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testSimpleAppend)
{
    std::string key("testSimpleAppendKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, testSimpleAppendStoreCallback);
    utilStoreKey(instance, key, "foo");
    int numcallbacks = 0;
    lcb_store_cmd_t cmd(LCB_APPEND, key.data(), key.length(), "bar", 3);
    lcb_store_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);

    Item itm;
    utilGetKey(instance, key, itm);
    EXPECT_STREQ("foobar", itm.val.c_str());

}

extern "C" {
    static void testSimplePrependStoreCallback(lcb_t, const void *cookie,
                                              lcb_storage_t operation,
                                              lcb_error_t error,
                                              const lcb_store_resp_t *resp)
    {
        using namespace std;
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_PREPEND, operation);
        ASSERT_NE((const lcb_store_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        EXPECT_EQ(LCB_SUCCESS, error);
        EXPECT_NE(0, resp->v.v0.cas);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testSimplePrepend)
{
    std::string key("testSimplePrependKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, testSimplePrependStoreCallback);
    utilStoreKey(instance, key, "foo");
    int numcallbacks = 0;
    lcb_store_cmd_t cmd(LCB_PREPEND, key.data(), key.length(), "bar", 3);
    lcb_store_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);

    Item itm;
    utilGetKey(instance, key, itm);
    EXPECT_STREQ("barfoo", itm.val.c_str());
}

extern "C" {
    static void testSimpleReplaceNonexistingStoreCallback(lcb_t, const void *cookie,
                                                          lcb_storage_t operation,
                                                          lcb_error_t error,
                                                          const lcb_store_resp_t *resp)
    {
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_REPLACE, operation);
        ASSERT_NE((const lcb_store_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        EXPECT_EQ(LCB_KEY_ENOENT, error);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testSimpleReplaceNonexisting)
{
    std::string key("testSimpleReplaceNonexistingKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, testSimpleReplaceNonexistingStoreCallback);
    utilRemoveKey(instance, key);
    int numcallbacks = 0;
    lcb_store_cmd_t cmd(LCB_REPLACE, key.data(), key.length(), "bar", 3);
    lcb_store_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);
}

extern "C" {
    static void testSimpleReplaceStoreCallback(lcb_t, const void *cookie,
                                               lcb_storage_t operation,
                                               lcb_error_t error,
                                               const lcb_store_resp_t *resp)
    {
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_REPLACE, operation);
        ASSERT_NE((const lcb_store_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        EXPECT_EQ(LCB_SUCCESS, error);
        EXPECT_NE(0, resp->v.v0.cas);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testSimpleReplace)
{
    std::string key("testSimpleReplaceKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, testSimpleReplaceStoreCallback);
    utilStoreKey(instance, key, "foo");
    int numcallbacks = 0;
    lcb_store_cmd_t cmd(LCB_REPLACE, key.data(), key.length(), "bar", 3);
    lcb_store_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);
    Item itm;
    utilGetKey(instance, key, itm);
    EXPECT_STREQ("bar", itm.val.c_str());
}

extern "C" {
    static void testIncorrectCasReplaceStoreCallback(lcb_t, const void *cookie,
                                                     lcb_storage_t operation,
                                                     lcb_error_t error,
                                                     const lcb_store_resp_t *resp)
    {
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_REPLACE, operation);
        EXPECT_EQ(LCB_KEY_EEXISTS, error);
        ASSERT_NE((const lcb_store_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testIncorrectCasReplace)
{
    std::string key("testIncorrectCasReplaceKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, testIncorrectCasReplaceStoreCallback);
    utilStoreKey(instance, key, "foo");
    Item itm;
    utilGetKey(instance, key, itm);

    int numcallbacks = 0;
    lcb_store_cmd_t cmd(LCB_REPLACE, key.data(), key.length(), "bar", 3);
    lcb_store_cmd_t* cmds[] = { &cmd };

    cmd.v.v0.cas = itm.cas + 1;
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);
}
extern "C" {
    static void testCasReplaceStoreCallback(lcb_t, const void *cookie,
                                            lcb_storage_t operation,
                                            lcb_error_t error,
                                            const lcb_store_resp_t *resp)
    {
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_REPLACE, operation);
        EXPECT_EQ(LCB_SUCCESS, error);
        ASSERT_NE((const lcb_store_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testCasReplace)
{
    std::string key("testCasReplaceKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, testCasReplaceStoreCallback);
    utilStoreKey(instance, key, "foo");
    Item itm;
    utilGetKey(instance, key, itm);

    int numcallbacks = 0;
    lcb_store_cmd_t cmd(LCB_REPLACE, key.data(), key.length(), "bar", 3);
    lcb_store_cmd_t* cmds[] = { &cmd };

    cmd.v.v0.cas = itm.cas;
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);
    utilGetKey(instance, key, itm);
    EXPECT_STREQ("bar", itm.val.c_str());
}

extern "C" {
    static void testTouchMissCallback(lcb_t, const void *cookie,
                                      lcb_error_t error,
                                      const lcb_touch_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_EQ(LCB_KEY_ENOENT, error);
        ASSERT_NE((const lcb_touch_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testTouchMiss)
{
    std::string key("testTouchMissKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_touch_callback(instance, testTouchMissCallback);
    utilRemoveKey(instance, key);

    int numcallbacks = 0;
    lcb_touch_cmd_t cmd(key.data(), key.length(), 666);
    lcb_touch_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_touch(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);
}

extern "C" {
    static void testTouchHitCallback(lcb_t, const void *cookie,
                                     lcb_error_t error,
                                     const lcb_touch_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_EQ(LCB_SUCCESS, error);
        ASSERT_NE((const lcb_touch_resp_t*)NULL, resp);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testTouchHit)
{
    std::string key("testTouchHitKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_touch_callback(instance, testTouchHitCallback);
    utilStoreKey(instance, key, "foo");

    int numcallbacks = 0;
    lcb_touch_cmd_t cmd(key.data(), key.length(), 666);
    lcb_touch_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_touch(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);
}

extern "C" {
    static void testServerStatsCallback(lcb_t, const void *cookie,
                                        lcb_error_t error,
                                        const lcb_server_stat_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_EQ(LCB_SUCCESS, error);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testServerStats)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_stat_callback(instance, testServerStatsCallback);
    int numcallbacks = 0;
    lcb_server_stats_cmd_t cmd;
    lcb_server_stats_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_server_stats(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_LT(1, numcallbacks);
}

extern "C" {
    static void testServerVersionsCallback(lcb_t, const void *cookie,
                                           lcb_error_t error,
                                           const lcb_server_version_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_EQ(LCB_SUCCESS, error);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testServerVersion)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_version_callback(instance, testServerVersionsCallback);
    int numcallbacks = 0;
    lcb_server_version_cmd_t cmd;
    lcb_server_version_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_server_versions(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_LT(1, numcallbacks);
}


extern "C" {
    static void testFlushCallback(lcb_t, const void *cookie,
                                  lcb_error_t error,
                                  const lcb_flush_resp_t *resp)
    {
        int *counter = (int*)cookie;
        EXPECT_TRUE(error == LCB_SUCCESS || error == LCB_NOT_SUPPORTED);
        EXPECT_EQ(0, resp->version);
        ++(*counter);
    }
}

TEST_F(MockUnitTest, testFlush)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_flush_callback(instance, testFlushCallback);
    int numcallbacks = 0;
    lcb_flush_cmd_t cmd;
    lcb_flush_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_flush(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_LT(1, numcallbacks);
}

extern "C" {
    static void flags_store_callback(lcb_t,
                                     const void *,
                                     lcb_storage_t operation,
                                     lcb_error_t error,
                                     const lcb_store_resp_t *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, error);
        ASSERT_EQ(5, resp->v.v0.nkey);
        ASSERT_EQ(0, memcmp(resp->v.v0.key, "flags", 5));
        ASSERT_EQ(LCB_SET, operation);
    }

    static void flags_get_callback(lcb_t, const void *,
                                   lcb_error_t error,
                                   const lcb_get_resp_t *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, error);
        ASSERT_EQ(5, resp->v.v0.nkey);
        ASSERT_EQ(0, memcmp(resp->v.v0.key, "flags", 5));
        ASSERT_EQ(1, resp->v.v0.nbytes);
        ASSERT_EQ(0, memcmp(resp->v.v0.bytes, "x", 1));
        ASSERT_EQ(0xdeadbeef, resp->v.v0.flags);
    }
}

TEST_F(MockUnitTest, testFlags)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_get_callback(instance, flags_get_callback);
    (void)lcb_set_store_callback(instance, flags_store_callback);

    lcb_store_cmd_t storeCommand(LCB_SET, "flags", 5, "x", 1, 0xdeadbeef);
    lcb_store_cmd_t* storeCommands[] = { &storeCommand };

    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, NULL, 1, storeCommands));
    // Wait for it to be persisted
    lcb_wait(instance);

    lcb_get_cmd_t cmd("flags", 5);
    lcb_get_cmd_t *cmds[] = { &cmd };
    ASSERT_EQ(LCB_SUCCESS, lcb_get(instance, NULL, 1, cmds));

    /* Wait for it to be received */
    lcb_wait(instance);
}

static lcb_uint64_t arithm_val;

extern "C" {
    static void arithmetic_store_callback(lcb_t, const void *,
                                          lcb_storage_t operation,
                                          lcb_error_t error,
                                          const lcb_store_resp_t *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, error);
        ASSERT_EQ(LCB_SET, operation);
        ASSERT_EQ(7, resp->v.v0.nkey);
        ASSERT_EQ(0, memcmp(resp->v.v0.key, "counter", 7));
    }

    static void arithmetic_incr_callback(lcb_t, const void *,
                                         lcb_error_t error,
                                         const lcb_arithmetic_resp_t *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, error);
        ASSERT_EQ(7, resp->v.v0.nkey);
        ASSERT_EQ(0, memcmp(resp->v.v0.key, "counter", 7));
        ASSERT_EQ(arithm_val + 1, resp->v.v0.value);
        arithm_val = resp->v.v0.value;
    }

    static void arithmetic_decr_callback(lcb_t, const void *,
                                         lcb_error_t error,
                                         const lcb_arithmetic_resp_t *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, error);
        ASSERT_EQ(7, resp->v.v0.nkey);
        ASSERT_EQ(0, memcmp(resp->v.v0.key, "counter", 7));
        ASSERT_EQ(arithm_val - 1, resp->v.v0.value);
        arithm_val = resp->v.v0.value;
    }

    static void arithmetic_create_callback(lcb_t, const void *,
                                           lcb_error_t error,
                                           const lcb_arithmetic_resp_t *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, error);
        ASSERT_EQ(9, resp->v.v0.nkey);
        ASSERT_EQ(0, memcmp(resp->v.v0.key, "mycounter", 9));
        ASSERT_EQ(0xdeadbeef, resp->v.v0.value);
    }
}

TEST_F(MockUnitTest, populateArithmetic)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_store_callback(instance, arithmetic_store_callback);

    lcb_store_cmd_t cmd(LCB_SET, "counter", 7, "0", 1);
    lcb_store_cmd_t *cmds[] = { &cmd };

    lcb_store(instance, this, 1, cmds);
    lcb_wait(instance);
    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testIncr)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_arithmetic_callback(instance, arithmetic_incr_callback);

    for (int ii = 0; ii < 10; ++ii) {
        lcb_arithmetic_cmd_t cmd("counter", 7, 1);
        lcb_arithmetic_cmd_t *cmds[] = { &cmd };
        lcb_arithmetic(instance, NULL, 1, cmds);
        lcb_wait(instance);
    }

    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testDecr)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_arithmetic_callback(instance, arithmetic_decr_callback);

    for (int ii = 0; ii < 10; ++ii) {
        lcb_arithmetic_cmd_t cmd("counter", 7, -1);
        lcb_arithmetic_cmd_t *cmds[] = { &cmd };
        lcb_arithmetic(instance, NULL, 1, cmds);
        lcb_wait(instance);
    }

    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testArithmeticCreate)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_arithmetic_callback(instance, arithmetic_create_callback);
    lcb_arithmetic_cmd_t cmd("mycounter", 9, 0x77, 1, 0xdeadbeef);
    lcb_arithmetic_cmd_t *cmds[] = { &cmd };
    lcb_arithmetic(instance, NULL, 1, cmds);
    lcb_wait(instance);
    lcb_destroy(instance);
}

extern "C" {
    static void syncmode_store_callback(lcb_t,
                                        const void *cookie,
                                        lcb_storage_t,
                                        lcb_error_t error,
                                        const lcb_store_resp_t *)
    {
        int *status = (int *)cookie;
        *status = error;
    }
}

TEST_F(MockUnitTest, testSyncmodeDefault)
{

    lcb_t instance;
    createConnection(instance);
    ASSERT_EQ(LCB_ASYNCHRONOUS, lcb_behavior_get_syncmode(instance));
    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testSyncmodeBehaviorToggle)
{
    lcb_t instance;
    createConnection(instance);
    lcb_behavior_set_syncmode(instance, LCB_SYNCHRONOUS);
    ASSERT_EQ(LCB_SYNCHRONOUS, lcb_behavior_get_syncmode(instance));
    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testSyncStore)
{
    lcb_t instance;
    createConnection(instance);
    lcb_behavior_set_syncmode(instance, LCB_SYNCHRONOUS);
    ASSERT_EQ(LCB_SYNCHRONOUS, lcb_behavior_get_syncmode(instance));

    lcb_set_store_callback(instance, syncmode_store_callback);

    int cookie = 0xffff;
    lcb_store_cmd_t cmd(LCB_SET, "key", 3);
    lcb_store_cmd_t *cmds[] = { &cmd };
    lcb_error_t ret = lcb_store(instance, &cookie, 1, cmds);
    ASSERT_EQ(LCB_SUCCESS, ret);
    ASSERT_EQ((int)LCB_SUCCESS, cookie);
    cookie = 0xffff;

    cmd.v.v0.operation = LCB_ADD;
    ret = lcb_store(instance, &cookie, 1, cmds);
    ASSERT_TRUE(ret == LCB_KEY_EEXISTS &&
                cookie == LCB_KEY_EEXISTS);
    lcb_destroy(instance);
}

extern "C" {
    static void timings_callback(lcb_t,
                                 const void *cookie,
                                 lcb_timeunit_t timeunit,
                                 lcb_uint32_t min,
                                 lcb_uint32_t max,
                                 lcb_uint32_t total,
                                 lcb_uint32_t maxtotal)
    {
        FILE *fp = (FILE *)cookie;
        if (fp != NULL) {
            fprintf(fp, "[%3u - %3u]", min, max);

            switch (timeunit) {
            case LCB_TIMEUNIT_NSEC:
                fprintf(fp, "ns");
                break;
            case LCB_TIMEUNIT_USEC:
                fprintf(fp, "us");
                break;
            case LCB_TIMEUNIT_MSEC:
                fprintf(fp, "ms");
                break;
            case LCB_TIMEUNIT_SEC:
                fprintf(fp, "s");
                break;
            default:
                ;
            }

            int num = (int)((float)20.0 * (float)total / (float)maxtotal);

            fprintf(fp, " |");
            for (int ii = 0; ii < num; ++ii) {
                fprintf(fp, "#");
            }

            fprintf(fp, " - %u\n", total);
        }
    }
}

TEST_F(MockUnitTest, testTimings)
{
    FILE *fp = stdout;
    if (getenv("LCB_VERBOSE_TESTS") == NULL) {
        fp = NULL;
    }

    lcb_t instance;
    createConnection(instance);
    lcb_enable_timings(instance);

    lcb_store_cmd_t storecmd(LCB_SET, "counter", 7, "0", 1);
    lcb_store_cmd_t *storecmds[] = { &storecmd };

    lcb_store(instance, NULL, 1, storecmds);
    lcb_wait(instance);
    for (int ii = 0; ii < 100; ++ii) {
        lcb_arithmetic_cmd_t acmd("counter", 7, 1);
        lcb_arithmetic_cmd_t *acmds[] = { &acmd };
        lcb_arithmetic(instance, NULL, 1, acmds);
        lcb_wait(instance);
    }
    if (fp) {
        fprintf(fp, "              +---------+---------+\n");
    }
    lcb_get_timings(instance, fp, timings_callback);
    if (fp) {
        fprintf(fp, "              +--------------------\n");
    }
    lcb_disable_timings(instance);
    lcb_destroy(instance);
}


extern "C" {
    static void timeout_error_callback(lcb_t instance,
                                       lcb_error_t err,
                                       const char *errinfo)
    {
        if (err == LCB_ETIMEDOUT) {
            return;
        }
        std::cerr << "Error " << lcb_strerror(instance, err);
        if (errinfo) {
            std::cerr << errinfo;
        }
        std::cerr << std::endl;
        abort();
    }

    int timeout_seqno = 0;
    int timeout_stats_done = 0;

    static void timeout_store_callback(lcb_t,
                                       const void *cookie,
                                       lcb_storage_t,
                                       lcb_error_t error,
                                       const lcb_store_resp_t *)
    {
        lcb_io_opt_t io = (lcb_io_opt_t)cookie;

        ASSERT_EQ(LCB_SUCCESS, error);
        timeout_seqno--;
        if (timeout_stats_done && timeout_seqno == 0) {
            io->stop_event_loop(io);
        }
    }

    static void timeout_stat_callback(lcb_t instance,
                                      const void *cookie,
                                      lcb_error_t error,
                                      const lcb_server_stat_resp_t *resp)
    {
        lcb_error_t err;
        lcb_io_opt_t io = (lcb_io_opt_t)cookie;
        char *statkey;
        lcb_size_t nstatkey;

        ASSERT_EQ(0, resp->version);
        const char *server_endpoint = resp->v.v0.server_endpoint;
        const void *key = resp->v.v0.key;
        lcb_size_t nkey = resp->v.v0.nkey;
        const void *bytes = resp->v.v0.bytes;
        lcb_size_t nbytes = resp->v.v0.nbytes;

        ASSERT_EQ(LCB_SUCCESS, error);
        if (server_endpoint != NULL) {
            nstatkey = strlen(server_endpoint) + nkey + 2;
            statkey = new char[nstatkey];
            snprintf(statkey, nstatkey, "%s-%s", server_endpoint,
                     (const char *)key);

            lcb_store_cmd_t storecmd(LCB_SET, statkey, nstatkey, bytes, nbytes);
            lcb_store_cmd_t *storecmds[] = { &storecmd };
            err = lcb_store(instance, io, 1, storecmds);
            ASSERT_EQ(LCB_SUCCESS, err);
            timeout_seqno++;
            delete []statkey;
        } else {
            timeout_stats_done = 1;
        }
    }
}

TEST_F(MockUnitTest, testTimeout)
{
    // @todo we need to have a test that actually tests the timeout callback..
    lcb_t instance;
    lcb_io_opt_t io;
    createConnection(instance);

    (void)lcb_set_error_callback(instance, timeout_error_callback);
    (void)lcb_set_stat_callback(instance, timeout_stat_callback);
    (void)lcb_set_store_callback(instance, timeout_store_callback);

    io = (lcb_io_opt_t)lcb_get_cookie(instance);

    lcb_server_stats_cmd_t stat;
    lcb_server_stats_cmd_t* commands[] = {&stat };

    ASSERT_EQ(LCB_SUCCESS, lcb_server_stats(instance, io, 1, commands));
    io->run_event_loop(io);
    lcb_destroy(instance);
}

extern "C" {
    static char *verbosity_endpoint;

    static void verbosity_all_callback(lcb_t instance,
                                       const void *cookie,
                                       lcb_error_t error,
                                       const lcb_verbosity_resp_t *resp)
    {
        int *counter = (int *)cookie;
        ASSERT_EQ(0, resp->version);
        ASSERT_EQ(LCB_SUCCESS, error);
        if (resp->v.v0.server_endpoint == NULL) {
            EXPECT_EQ(MockUnitTest::numNodes, *counter);
            lcb_io_opt_t io;
            io = (lcb_io_opt_t)lcb_get_cookie(instance);
            io->stop_event_loop(io);
            return;
        } else if (verbosity_endpoint == NULL) {
            verbosity_endpoint = strdup(resp->v.v0.server_endpoint);
        }
        ++(*counter);
    }

    static void verbosity_single_callback(lcb_t instance,
                                          const void *,
                                          lcb_error_t error,
                                          const lcb_verbosity_resp_t *resp)
    {
        ASSERT_EQ(0, resp->version);
        ASSERT_EQ(LCB_SUCCESS, error);
        if (resp->v.v0.server_endpoint == NULL) {
            lcb_io_opt_t io;
            io = (lcb_io_opt_t)lcb_get_cookie(instance);
            io->stop_event_loop(io);
        } else {
            EXPECT_STREQ(verbosity_endpoint, resp->v.v0.server_endpoint);
        }
    }
}

TEST_F(MockUnitTest, testVerbosity)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_verbosity_callback(instance, verbosity_all_callback);

    int counter = 0;

    lcb_verbosity_cmd_t cmd(LCB_VERBOSITY_DEBUG);
    lcb_verbosity_cmd_t* commands[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_set_verbosity(instance, &counter, 1, commands));

    lcb_io_opt_t io;
    io = (lcb_io_opt_t)lcb_get_cookie(instance);
    io->run_event_loop(io);

    EXPECT_EQ(numNodes, counter);
    EXPECT_NE((char *)NULL, verbosity_endpoint);

    (void)lcb_set_verbosity_callback(instance, verbosity_single_callback);

    lcb_verbosity_cmd_t cmd2(LCB_VERBOSITY_DEBUG, verbosity_endpoint);
    lcb_verbosity_cmd_t* commands2[] = { &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_set_verbosity(instance, &counter, 1, commands2));
    io->run_event_loop(io);
    free((void *)verbosity_endpoint);

    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testIssue59)
{
    // lcb_wait() blocks forever if there is nothing queued
    lcb_t instance;
    createConnection(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_destroy(instance);
}

extern "C" {
    struct rvbuf {
        lcb_error_t error;
        lcb_cas_t cas1;
        lcb_cas_t cas2;
    };

    static void df_store_callback1(lcb_t instance,
                                   const void *cookie,
                                   lcb_storage_t,
                                   lcb_error_t error,
                                   const lcb_store_resp_t *)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        rv->error = error;
        lcb_io_opt_t io = (lcb_io_opt_t)lcb_get_cookie(instance);
        io->stop_event_loop(io);
    }

    static void df_store_callback2(lcb_t instance,
                                   const void *cookie,
                                   lcb_storage_t,
                                   lcb_error_t error,
                                   const lcb_store_resp_t *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        rv->error = error;
        rv->cas2 = resp->v.v0.cas;
        lcb_io_opt_t io = (lcb_io_opt_t)lcb_get_cookie(instance);
        io->stop_event_loop(io);
    }

    static void df_get_callback(lcb_t instance,
                                const void *cookie,
                                lcb_error_t error,
                                const lcb_get_resp_t *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        const char *value = "{\"bar\"=>1, \"baz\"=>2}";
        lcb_size_t nvalue = strlen(value);
        lcb_error_t err;

        rv->error = error;
        rv->cas1 = resp->v.v0.cas;
        lcb_store_cmd_t storecmd(LCB_SET, resp->v.v0.key, resp->v.v0.nkey,
                                 value, nvalue, 0, 0, resp->v.v0.cas);
        lcb_store_cmd_t *storecmds[] = { &storecmd };

        err = lcb_store(instance, rv, 1, storecmds);
        ASSERT_EQ(LCB_SUCCESS, err);
    }
}

TEST_F(MockUnitTest, testDoubleFreeError)
{
    lcb_error_t err;
    struct rvbuf rv;
    const char *key = "test_compare_and_swap_async_", *value = "{\"bar\" => 1}";
    lcb_size_t nkey = strlen(key), nvalue = strlen(value);
    lcb_io_opt_t io;
    lcb_t instance;

    createConnection(instance);
    io = (lcb_io_opt_t)lcb_get_cookie(instance);

    /* prefill the bucket */
    (void)lcb_set_store_callback(instance, df_store_callback1);

    lcb_store_cmd_t storecmd(LCB_SET, key, nkey, value, nvalue);
    lcb_store_cmd_t *storecmds[] = { &storecmd };

    err = lcb_store(instance, &rv, 1, storecmds);
    ASSERT_EQ(LCB_SUCCESS, err);
    io->run_event_loop(io);
    ASSERT_EQ(LCB_SUCCESS, rv.error);

    /* run exercise
     *
     * 1. get the valueue and its cas
     * 2. atomic set new valueue using old cas
     */
    (void)lcb_set_store_callback(instance, df_store_callback2);
    (void)lcb_set_get_callback(instance, df_get_callback);

    lcb_get_cmd_t getcmd(key, nkey);
    lcb_get_cmd_t *getcmds[] = { &getcmd };

    err = lcb_get(instance, &rv, 1, getcmds);
    ASSERT_EQ(LCB_SUCCESS, err);
    rv.cas1 = rv.cas2 = 0;
    io->run_event_loop(io);
    ASSERT_EQ(LCB_SUCCESS, rv.error);
    ASSERT_GT(rv.cas1, 0);
    ASSERT_GT(rv.cas2, 0);
    ASSERT_NE(rv.cas1, rv.cas2);
}
