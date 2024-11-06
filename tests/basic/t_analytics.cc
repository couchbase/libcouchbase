/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015-2024 Couchbase, Inc.
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
#include <cstdint>
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>

#include "../iotests/testutil.h"
#include "analytics/analytics_handle.hh"

class AnalyticsQuery : public ::testing::Test
{
};

struct MockInstance {
    lcb_INSTANCE *instance{nullptr};

    MockInstance()
    {
        lcb_assert(lcb_create(&instance, nullptr) == LCB_SUCCESS);
    }

    ~MockInstance()
    {
        lcb_destroy(instance);
    }
};

TEST_F(AnalyticsQuery, testSettingTimeout)
{
    MockInstance mock;

    lcb_CMDANALYTICS *cmd = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cmdanalytics_create(&cmd));

    std::string statement = "SELECT 42 AS the_answer;";
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cmdanalytics_statement(cmd, statement.c_str(), statement.size()));

    uint32_t timeout_ms{25000123};
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cmdanalytics_timeout(cmd, timeout_ms));

    auto *req = new lcb_ANALYTICS_HANDLE_(mock.instance, cmd->cookie(), cmd);
    Json::Value json = req->json_const();
    json.removeMember("client_context_id");
    ASSERT_EQ(R"({"statement":"SELECT 42 AS the_answer;","timeout":"25000123us"})", Json::FastWriter().write(json));
}

TEST_F(AnalyticsQuery, testDefaultTimeout)
{
    MockInstance mock;

    lcb_CMDANALYTICS *cmd = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cmdanalytics_create(&cmd));

    std::string statement = "SELECT 42 AS the_answer;";
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cmdanalytics_statement(cmd, statement.c_str(), statement.size()));

    auto *req = new lcb_ANALYTICS_HANDLE_(mock.instance, cmd->cookie(), cmd);
    Json::Value json = req->json_const();
    json.removeMember("client_context_id");
    ASSERT_EQ(R"({"statement":"SELECT 42 AS the_answer;","timeout":"75000000us"})", Json::FastWriter().write(json));
}

TEST_F(AnalyticsQuery, testTimeoutThroughThePayload)
{
    MockInstance mock;

    lcb_CMDANALYTICS *cmd = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cmdanalytics_create(&cmd));

    std::string raw_payload{R"({"statement":"SELECT 42 AS the_answer;","timeout":"23s"})"};
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cmdanalytics_payload(cmd, raw_payload.data(), raw_payload.size()));

    auto *req = new lcb_ANALYTICS_HANDLE_(mock.instance, cmd->cookie(), cmd);
    Json::Value json = req->json_const();
    json.removeMember("client_context_id");
    ASSERT_EQ(R"({"statement":"SELECT 42 AS the_answer;","timeout":"23s"})", Json::FastWriter().write(json));
    ASSERT_EQ(23000000, req->timeout_us());
}
