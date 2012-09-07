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
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>

#include "server.h"
#include "mock-unit-test.h"

class GetUnitTest : public MockUnitTest
{
protected:
    static void SetUpTestCase() {
        MockUnitTest::SetUpTestCase();
    }
};

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

TEST_F(GetUnitTest, testGetMiss)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_get_callback(instance, testGetMissGetCallback);
    int numcallbacks = 0;

    removeKey(instance, "testGetMiss1");
    removeKey(instance, "testGetMiss2");

    lcb_get_cmd_t cmd1("testGetMiss1");
    lcb_get_cmd_t cmd2("testGetMiss2");
    lcb_get_cmd_t *cmds[] = { &cmd1, &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_get(instance, &numcallbacks, 2, cmds));

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

TEST_F(GetUnitTest, testGetHit)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_get_callback(instance, testGetHitGetCallback);
    int numcallbacks = 0;

    storeKey(instance, "testGetKey1", "foo");
    storeKey(instance, "testGetKey2", "foo");
    lcb_get_cmd_t cmd1("testGetKey1");
    lcb_get_cmd_t cmd2("testGetKey2");
    lcb_get_cmd_t *cmds[] = { &cmd1, &cmd2 };
    EXPECT_EQ(LCB_SUCCESS, lcb_get(instance, &numcallbacks, 2, cmds));

    lcb_wait(instance);
    EXPECT_EQ(2, numcallbacks);
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

TEST_F(GetUnitTest, testTouchMiss)
{
    std::string key("testTouchMissKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_touch_callback(instance, testTouchMissCallback);
    removeKey(instance, key);

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

TEST_F(GetUnitTest, testTouchHit)
{
    std::string key("testTouchHitKey");
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_touch_callback(instance, testTouchHitCallback);
    storeKey(instance, key, "foo");

    int numcallbacks = 0;
    lcb_touch_cmd_t cmd(key.data(), key.length(), 666);
    lcb_touch_cmd_t* cmds[] = { &cmd };
    EXPECT_EQ(LCB_SUCCESS, lcb_touch(instance, &numcallbacks, 1, cmds));
    lcb_wait(instance);
    EXPECT_EQ(1, numcallbacks);
}

