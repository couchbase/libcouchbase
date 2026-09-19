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
 * Every operation timeout asks for a configuration refresh, and CCCP fetches
 * the map over whichever KV connection it lands on. Landing on a connection
 * that is not delivering costs a config_node_timeout before another node is
 * tried, which is the one thing a client needs to be quick about while part of
 * the cluster is unreachable.
 *
 * Silence is forced here by rewinding sock->atime rather than by stalling the
 * peer, so the outcome does not depend on the mock's timing.
 */

#include "iotests.h"
#include "internal.h"
#include "bootstrap.h"
#include <lcbio/connect.h>

#include <set>
#include <lcbio/ctx.h>
#include <mcserver/mcserver.h>

class CccpUnresponsiveUnitTest : public MockUnitTest
{
};

namespace
{
/* One key per KV node, so that every pipeline holds a connection. Silencing
 * only the connected ones would leave whichever node CCCP round-robins to
 * looking healthy. */
void warm_all_pipelines(lcb_INSTANCE *instance)
{
    std::set<int> connected;
    for (int ii = 0; ii < 5000 && connected.size() < LCBT_NSERVERS(instance); ++ii) {
        char key[64];
        snprintf(key, sizeof(key), "cccp-warm-%d", ii);
        lcb_cntl_vbinfo_t vbi{};
        vbi.v.v0.key = key;
        vbi.v.v0.nkey = strlen(key);
        if (lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_VBMAP, &vbi) != LCB_SUCCESS) {
            continue;
        }
        if (connected.insert(vbi.v.v0.server_index).second) {
            storeKey(instance, key, "v");
        }
    }
    ASSERT_EQ(LCBT_NSERVERS(instance), connected.size());
}

/* Present every KV connection as having been silent since the epoch. */
void silence_all_connections(lcb_INSTANCE *instance)
{
    for (size_t ii = 0; ii < LCBT_NSERVERS(instance); ++ii) {
        lcb::Server *server = instance->get_server(ii);
        if (server != nullptr && server->connctx != nullptr && server->connctx->sock != nullptr) {
            server->connctx->sock->atime = 0;
        }
    }
}

int queued_config_requests(lcb_INSTANCE *instance)
{
    int n = 0;
    for (size_t ii = 0; ii < LCBT_NSERVERS(instance); ++ii) {
        lcb::Server *server = instance->get_server(ii);
        if (server == nullptr) {
            continue;
        }
        sllist_node *ll;
        SLLIST_FOREACH(&server->requests, ll)
        {
            const mc_PACKET *pkt = SLLIST_ITEM(ll, mc_PACKET, slnode);
            protocol_binary_request_header hdr = {};
            mcreq_read_hdr(pkt, &hdr);
            if (hdr.request.opcode == PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG) {
                ++n;
            }
        }
    }
    return n;
}

int refresh_and_count_config_requests(lcb_INSTANCE *instance, lcb_U32 unresponsive_timeout)
{
    EXPECT_STATUS_EQ(LCB_SUCCESS,
                     lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_UNRESPONSIVE_TIMEOUT, &unresponsive_timeout));
    warm_all_pipelines(instance);
    silence_all_connections(instance);
    instance->bootstrap(lcb::BS_REFRESH_ALWAYS);
    return queued_config_requests(instance);
}
} // namespace

/* With the check on, no silent connection is asked for the map. */
TEST_F(CccpUnresponsiveUnitTest, testSilentConnectionIsNotUsedForRefresh)
{
    SKIP_UNLESS_MOCK()

    HandleWrap hw;
    createConnection(hw);
    EXPECT_EQ(0, refresh_and_count_config_requests(hw.getLcb(), 1000000));
}

/* With the check off the same refresh goes down the silent connection, which
 * is the behaviour being replaced. */
TEST_F(CccpUnresponsiveUnitTest, testCheckDisabledStillUsesSilentConnection)
{
    SKIP_UNLESS_MOCK()

    HandleWrap hw;
    createConnection(hw);
    EXPECT_EQ(1, refresh_and_count_config_requests(hw.getLcb(), 0));
}
