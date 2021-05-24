/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016-2020 Couchbase, Inc.
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
#include <libcouchbase/couchbase.h>
#include <map>
#include "iotests.h"
#include "internal.h"

class SchedUnitTests : public MockUnitTest
{
};

static bool hasPendingOps(lcb_INSTANCE *instance)
{
    for (size_t ii = 0; ii < LCBT_NSERVERS(instance); ++ii) {
        if (instance->get_server(ii)->has_pending()) {
            return true;
        }
    }
    return false;
}

static void opCallback(lcb_INSTANCE *, int, const lcb_RESPSTORE *resp)
{
    size_t *counter;
    lcb_respstore_cookie(resp, (void **)&counter);
    *counter += 1;
}

TEST_F(SchedUnitTests, testSched)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    lcb_STATUS rc;
    size_t counter;
    createConnection(hw, &instance);

    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)opCallback);

    // lcb_store
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, "key", 3);
    lcb_cmdstore_value(scmd, "val", 3);

    rc = lcb_store(instance, &counter, scmd);
    ASSERT_EQ(LCB_SUCCESS, rc);
    ASSERT_TRUE(hasPendingOps(instance));
    lcb_wait(instance, LCB_WAIT_NOCHECK);
    ASSERT_FALSE(hasPendingOps(instance));

    lcb_sched_enter(instance);
    rc = lcb_store(instance, &counter, scmd);
    ASSERT_EQ(LCB_SUCCESS, rc);
    ASSERT_FALSE(hasPendingOps(instance));
    lcb_sched_leave(instance);
    ASSERT_TRUE(hasPendingOps(instance));
    lcb_wait(instance, LCB_WAIT_NOCHECK);
    ASSERT_FALSE(hasPendingOps(instance));

    // Try with multiple operations..
    counter = 0;
    for (size_t ii = 0; ii < 5; ++ii) {
        rc = lcb_store(instance, &counter, scmd);
    }

    ASSERT_TRUE(hasPendingOps(instance));
    lcb_sched_enter(instance);
    rc = lcb_store(instance, &counter, scmd);
    lcb_sched_fail(instance);
    lcb_wait(instance, LCB_WAIT_NOCHECK);
    ASSERT_EQ(5, counter);

    lcb_cmdstore_destroy(scmd);
}

static void counterCallback(lcb_INSTANCE *, int, const lcb_RESPCOUNTER *resp)
{
    size_t *counter;
    lcb_respcounter_cookie(resp, (void **)&counter);
    *counter += 1;
}

TEST_F(SchedUnitTests, testScheduleIncrementBeforeConnection)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    lcb_STATUS rc;

    MockEnvironment::getInstance()->createConnection(hw, &instance);

    lcb_CMDCOUNTER *cmd;
    lcb_install_callback(instance, LCB_CALLBACK_COUNTER, (lcb_RESPCALLBACK)counterCallback);
    lcb_cmdcounter_create(&cmd);
    lcb_cmdcounter_key(cmd, "key", 3);
    lcb_cmdcounter_delta(cmd, 1);
    size_t counter = 0;
    rc = lcb_counter(instance, &counter, cmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, rc);
    lcb_cmdcounter_destroy(cmd);
    ASSERT_FALSE(hasPendingOps(instance));
    ASSERT_TRUE(instance->has_deferred_operations());
    ASSERT_EQ(0, counter);

    ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(LCB_SUCCESS, lcb_get_bootstrap_status(instance));
    ASSERT_FALSE(instance->has_deferred_operations());
    ASSERT_FALSE(hasPendingOps(instance));
    ASSERT_EQ(1, counter);
}

static void existsCallback(lcb_INSTANCE *, int, const lcb_RESPEXISTS *resp)
{
    size_t *counter;
    lcb_respexists_cookie(resp, (void **)&counter);
    *counter += 1;
}

TEST_F(SchedUnitTests, testScheduleExistsBeforeConnection)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    lcb_STATUS rc;

    MockEnvironment::getInstance()->createConnection(hw, &instance);

    lcb_CMDEXISTS *cmd;
    lcb_install_callback(instance, LCB_CALLBACK_EXISTS, (lcb_RESPCALLBACK)existsCallback);
    lcb_cmdexists_create(&cmd);
    lcb_cmdexists_key(cmd, "key", 3);
    size_t counter = 0;
    rc = lcb_exists(instance, &counter, cmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, rc);
    lcb_cmdexists_destroy(cmd);
    ASSERT_FALSE(hasPendingOps(instance));
    ASSERT_TRUE(instance->has_deferred_operations());

    ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(LCB_SUCCESS, lcb_get_bootstrap_status(instance));
    ASSERT_FALSE(instance->has_deferred_operations());
    ASSERT_FALSE(hasPendingOps(instance));
    ASSERT_EQ(1, counter);
}

static void getCallback(lcb_INSTANCE *, int, const lcb_RESPGET *resp)
{
    size_t *counter;
    lcb_respget_cookie(resp, (void **)&counter);
    *counter += 1;
}

TEST_F(SchedUnitTests, testScheduleGetBeforeConnection)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    lcb_STATUS rc;

    MockEnvironment::getInstance()->createConnection(hw, &instance);

    lcb_CMDGET *cmd;
    lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)getCallback);
    lcb_cmdget_create(&cmd);
    lcb_cmdget_key(cmd, "key", 3);
    size_t counter = 0;
    rc = lcb_get(instance, &counter, cmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, rc);
    lcb_cmdget_destroy(cmd);
    ASSERT_FALSE(hasPendingOps(instance));
    ASSERT_TRUE(instance->has_deferred_operations());

    ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(LCB_SUCCESS, lcb_get_bootstrap_status(instance));
    ASSERT_FALSE(instance->has_deferred_operations());
    ASSERT_FALSE(hasPendingOps(instance));
    ASSERT_EQ(1, counter);
}
