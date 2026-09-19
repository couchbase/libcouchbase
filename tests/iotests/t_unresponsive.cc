/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2026 Couchbase, Inc.
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

/*
 * A peer that acknowledges at the TCP level and stops answering is invisible
 * to every socket-level timeout, because the kernel has no unacknowledged data
 * to give up on. Server::check_unresponsive() is what notices it. The mock's
 * hiccup command produces exactly that state: the connection stays up and the
 * response is withheld.
 */

#include "iotests.h"
#include "internal.h"
#include <lcbio/connect.h>
#include <lcbio/ctx.h>
#include <mcserver/mcserver.h>

#include <map>

namespace
{
/* Socket id per KV pipeline, for the pipelines that currently hold one. A
 * changed or vanished id means the connection was rebuilt. */
std::map<size_t, lcb_U64> kv_socket_ids(lcb_INSTANCE *instance)
{
    std::map<size_t, lcb_U64> ids;
    for (size_t ii = 0; ii < LCBT_NSERVERS(instance); ++ii) {
        lcb::Server *server = instance->get_server(ii);
        if (server != nullptr && server->connctx != nullptr && server->connctx->sock != nullptr) {
            ids[ii] = server->connctx->sock->id;
        }
    }
    return ids;
}

int connections_rebuilt(const std::map<size_t, lcb_U64> &before, const std::map<size_t, lcb_U64> &after)
{
    int n = 0;
    for (const auto &entry : before) {
        auto now = after.find(entry.first);
        if (now == after.end() || now->second != entry.second) {
            ++n;
        }
    }
    return n;
}

/* Run one operation into its deadline and return once it has failed. */
void expire_one_operation(lcb_INSTANCE *instance, const char *key)
{
    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(cmd, key, strlen(key));
    lcb_cmdstore_value(cmd, "v", 1);
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, nullptr, cmd));
    lcb_cmdstore_destroy(cmd);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
}

/* Let the peer answer again and run one operation through, so that whichever
 * connection the next operation will use is the one being inspected.
 *
 * The deadline is lifted first. An operation that expired here would purge
 * the pipeline a second time and start another detection cycle, deciding the
 * outcome under test rather than reporting it. Completion-mode plugins also
 * finalise an errored context on a later tick than event-mode ones, and only
 * running the loop again settles that difference. The outcome of this
 * operation is not the subject: a rebuilt connection has to re-select the
 * bucket first. */
void settle(lcb_INSTANCE *instance, const char *key)
{
    MockEnvironment::getInstance()->hiccupNodes(0, 0);
    lcb_U32 op_timeout = 10000000;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &op_timeout));

    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(cmd, key, strlen(key));
    lcb_cmdstore_value(cmd, "v", 1);
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_store(instance, nullptr, cmd));
    lcb_cmdstore_destroy(cmd);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
}

void configure(lcb_INSTANCE *instance, lcb_U32 op_timeout, lcb_U32 unresponsive_timeout, int close)
{
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &op_timeout));
    ASSERT_STATUS_EQ(LCB_SUCCESS,
                     lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_UNRESPONSIVE_TIMEOUT, &unresponsive_timeout));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_UNRESPONSIVE_CLOSE, &close));
}
} // namespace

class UnresponsiveUnitTest : public MockUnitTest
{
};

/* Detection alone leaves the connection in place: the default must not start
 * closing sockets on anyone who upgrades. */
TEST_F(UnresponsiveUnitTest, testReportOnlyKeepsConnection)
{
    SKIP_UNLESS_MOCK()

    HandleWrap hw;
    createConnection(hw);
    lcb_INSTANCE *instance = hw.getLcb();
    MockEnvironment *mock = MockEnvironment::getInstance();

    removeKey(instance, "unresponsive-report"); /* warms the connection */
    configure(instance, 1000000, 400000, 0);

    std::map<size_t, lcb_U64> before = kv_socket_ids(instance);
    ASSERT_FALSE(before.empty());

    mock->hiccupNodes(1500, 1);
    expire_one_operation(instance, "unresponsive-report");
    settle(instance, "unresponsive-report");

    EXPECT_EQ(0, connections_rebuilt(before, kv_socket_ids(instance)));
}

/* With closing enabled the stalled connection is torn down, so the next
 * operation cannot inherit it. */
TEST_F(UnresponsiveUnitTest, testCloseRebuildsConnection)
{
    SKIP_UNLESS_MOCK()

    HandleWrap hw;
    createConnection(hw);
    lcb_INSTANCE *instance = hw.getLcb();
    MockEnvironment *mock = MockEnvironment::getInstance();

    removeKey(instance, "unresponsive-close"); /* warms the connection */
    configure(instance, 1000000, 400000, 1);

    std::map<size_t, lcb_U64> before = kv_socket_ids(instance);
    ASSERT_FALSE(before.empty());

    mock->hiccupNodes(1500, 1);
    expire_one_operation(instance, "unresponsive-close");
    settle(instance, "unresponsive-close");

    EXPECT_GE(connections_rebuilt(before, kv_socket_ids(instance)), 1);
}

/* A connection that is answering must never be reported, however short the
 * threshold: the check keys on silence, not on the deadline being missed. */
TEST_F(UnresponsiveUnitTest, testHealthyConnectionSurvivesShortThreshold)
{
    HandleWrap hw;
    createConnection(hw);
    lcb_INSTANCE *instance = hw.getLcb();

    storeKey(instance, "unresponsive-healthy", "v"); /* warms the connection */
    configure(instance, 5000000, 1, 1);

    std::map<size_t, lcb_U64> before = kv_socket_ids(instance);
    ASSERT_FALSE(before.empty());

    for (int ii = 0; ii < 10; ++ii) {
        storeKey(instance, "unresponsive-healthy", "v");
    }

    EXPECT_EQ(0, connections_rebuilt(before, kv_socket_ids(instance)));
}

TEST_F(UnresponsiveUnitTest, testCntlRoundTrip)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createConnection(hw, &instance);

    lcb_U32 set_timeout = 4500000;
    int set_close = 1;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_UNRESPONSIVE_TIMEOUT, &set_timeout));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_UNRESPONSIVE_CLOSE, &set_close));

    lcb_U32 get_timeout = 0;
    int get_close = 0;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_UNRESPONSIVE_TIMEOUT, &get_timeout));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_UNRESPONSIVE_CLOSE, &get_close));
    EXPECT_EQ(set_timeout, get_timeout);
    EXPECT_EQ(set_close, get_close);
}

TEST_F(UnresponsiveUnitTest, testConnectionStringKeys)
{
    lcb_CREATEOPTS *opts = nullptr;
    MockEnvironment::getInstance()->makeConnectParams(opts, nullptr);

    std::string connstr(opts->connstr, opts->connstr_len);
    char sep = (connstr.find('?') == std::string::npos) ? '?' : '&';
    connstr.append(1, sep).append("unresponsive_timeout=7s&unresponsive_close=true");
    lcb_createopts_connstr(opts, connstr.c_str(), connstr.size());

    lcb_INSTANCE *instance = nullptr;
    ASSERT_EQ(LCB_SUCCESS, lcb_create(&instance, opts));
    lcb_createopts_destroy(opts);

    lcb_U32 timeout = 0;
    int close = 0;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_UNRESPONSIVE_TIMEOUT, &timeout));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_UNRESPONSIVE_CLOSE, &close));
    EXPECT_EQ((lcb_U32)7000000, timeout);
    EXPECT_EQ(1, close);

    lcb_destroy(instance);
}
