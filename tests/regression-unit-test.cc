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
#include "mock-environment.h"
#include "testutil.h"

class RegressionUnitTest : public MockUnitTest
{
protected:
    static void SetUpTestCase() {
        MockUnitTest::SetUpTestCase();
    }
};

static bool callbackInvoked = false;

extern "C" {
static void get_callback(lcb_t, const void *cookie,
                         lcb_error_t err, const lcb_get_resp_t *)
{
    EXPECT_EQ(err, LCB_KEY_ENOENT);
    int *counter_p = reinterpret_cast<int*>(const_cast<void*>(cookie));
    EXPECT_TRUE(counter_p != NULL);
    EXPECT_GT(*counter_p, 0);
    *counter_p -= 1;
    callbackInvoked = true;
}

static void stats_callback(lcb_t, const void *cookie, lcb_error_t err,
                           const lcb_server_stat_resp_t *resp)
{
    EXPECT_EQ(err, LCB_SUCCESS);
    if (resp->v.v0.nkey == 0) {
        int *counter_p = reinterpret_cast<int*>(const_cast<void*>(cookie));
        *counter_p -= 1;
    }
    callbackInvoked = true;
}

}

TEST_F(RegressionUnitTest, CCBC_150)
{
    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);

    callbackInvoked = false;
    lcb_set_get_callback(instance, get_callback);
    lcb_set_stat_callback(instance, stats_callback);

    lcb_get_cmd_t getCmd1("testGetMiss1");
    lcb_get_cmd_t *getCmds[] = { &getCmd1 };

    lcb_server_stats_cmd_t statCmd;
    lcb_server_stats_cmd_t *statCmds[] = { &statCmd };
    int ii;

    // Lets spool up a lot of commands in one of the buffers so that we
    // know we need to search for it a few times when we get responses..
    int callbackCounter = 1000;
    void *ptr = &callbackCounter;

    for (ii = 0; ii < 1000; ++ii) {
        EXPECT_EQ(LCB_SUCCESS, lcb_get(instance, ptr, 1, getCmds));
    }

    callbackCounter++;
    EXPECT_EQ(LCB_SUCCESS, lcb_server_stats(instance, ptr, 1, statCmds));

    callbackCounter += 1000;
    for (ii = 0; ii < 1000; ++ii) {
        EXPECT_EQ(LCB_SUCCESS, lcb_get(instance, ptr, 1, getCmds));
    }

    callbackCounter++;
    EXPECT_EQ(LCB_SUCCESS, lcb_server_stats(instance, ptr, 1, statCmds));

    callbackCounter++;
    EXPECT_EQ(LCB_SUCCESS, lcb_server_stats(instance, ptr, 1, statCmds));

    EXPECT_EQ(LCB_SUCCESS, lcb_wait(instance));
    ASSERT_TRUE(callbackInvoked);
    ASSERT_EQ(callbackCounter, 0);
}
