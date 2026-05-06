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
 * Connstart::handler applies the keepalive timings and TCP_USER_TIMEOUT to
 * each new socket, and nothing in the library reads them back afterwards. The
 * kernel is the only witness, so these tests getsockopt them off the socket
 * and check the cntl and connection-string plumbing that feeds them.
 *
 * Linux only: TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT and TCP_USER_TIMEOUT
 * are Linux spellings. Completion-mode plugins do not expose the kernel fd,
 * so the options never reach their sockets.
 */

#include "iotests.h"

#if defined(__linux__)

#include "internal.h"
#include <lcbio/iotable.h>
#include <lcbio/connect.h>
#include <lcbio/ctx.h>
#include <mcserver/mcserver.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

class KeepaliveUnitTest : public MockUnitTest
{
};

namespace
{
int get_int_sockopt(int fd, int level, int optname)
{
    int value = 0;
    socklen_t len = sizeof(value);
    EXPECT_EQ(0, ::getsockopt(fd, level, optname, &value, &len));
    return value;
}

/* First KV socket whose fd the kernel options could have reached.
 * -1 marks a completion-mode plugin, which is out of scope rather than a
 * failure; -2 means no KV connection is up yet. */
int find_event_kv_fd(lcb_INSTANCE *instance)
{
    for (size_t ii = 0; ii < LCBT_NSERVERS(instance); ++ii) {
        lcb::Server *server = instance->get_server(ii);
        if (server == nullptr || server->connctx == nullptr) {
            continue;
        }
        lcbio_CTX *ctx = server->connctx;
        if (ctx->sock == nullptr || ctx->sock->io == nullptr) {
            continue;
        }
        if (!ctx->sock->io->is_E()) {
            return -1;
        }
        if (ctx->sock->u.fd == INVALID_SOCKET) {
            continue;
        }
        return (int)ctx->sock->u.fd;
    }
    return -2;
}

/* makeConnectParams() yields a connection string with or without a query
 * depending on whether the harness runs against the mock or a real cluster. */
std::string append_query(const std::string &orig, const std::string &extra)
{
    char sep = (orig.find('?') == std::string::npos) ? '?' : '&';
    return orig + sep + extra;
}
} // namespace

/* Every KV socket carries the configured timings, not the kernel's. */
TEST_F(KeepaliveUnitTest, testDefaultsApplied)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createConnection(hw, &instance);

    storeKey(instance, "ka-defaults", "v");

    int fd = find_event_kv_fd(instance);
    if (fd == -1) {
        SUCCEED() << "completion-mode plugin: the kernel fd is not exposed";
        return;
    }
    ASSERT_GE(fd, 0) << "no active event-based KV socket to inspect";

    EXPECT_NE(0, get_int_sockopt(fd, SOL_SOCKET, SO_KEEPALIVE));
    EXPECT_EQ((int)LCB_DEFAULT_TCP_KEEPALIVE_IDLE, get_int_sockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE));
    EXPECT_EQ((int)LCB_DEFAULT_TCP_KEEPALIVE_INTERVAL, get_int_sockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL));
    EXPECT_EQ((int)LCB_DEFAULT_TCP_KEEPALIVE_COUNT, get_int_sockopt(fd, IPPROTO_TCP, TCP_KEEPCNT));
    EXPECT_EQ((int)LCB_DEFAULT_TCP_USER_TIMEOUT, get_int_sockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT));
}

/* The keywords registered in lookup_str_table reach the settings. */
TEST_F(KeepaliveUnitTest, testConnectionStringKeys)
{
    lcb_CREATEOPTS *opts = nullptr;
    MockEnvironment::getInstance()->makeConnectParams(opts, nullptr);

    std::string connstr(opts->connstr, opts->connstr_len);
    connstr = append_query(connstr, "tcp_keepalive_idle=13"
                                    "&tcp_keepalive_interval=2"
                                    "&tcp_keepalive_count=4"
                                    "&tcp_user_timeout=7000");
    lcb_createopts_connstr(opts, connstr.c_str(), connstr.size());

    lcb_INSTANCE *instance = nullptr;
    ASSERT_EQ(LCB_SUCCESS, lcb_create(&instance, opts));
    lcb_createopts_destroy(opts);

    lcb_U32 idle = 0, intvl = 0, cnt = 0, user_tmo = 0;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_TCP_KEEPALIVE_IDLE, &idle));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_TCP_KEEPALIVE_INTERVAL, &intvl));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_TCP_KEEPALIVE_COUNT, &cnt));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_TCP_USER_TIMEOUT, &user_tmo));
    EXPECT_EQ((lcb_U32)13, idle);
    EXPECT_EQ((lcb_U32)2, intvl);
    EXPECT_EQ((lcb_U32)4, cnt);
    EXPECT_EQ((lcb_U32)7000, user_tmo);

    lcb_destroy(instance);
}

/* Each control id reaches its own handler: the dispatch table is positional
 * and a missing entry silently shifts every id after it. */
TEST_F(KeepaliveUnitTest, testCntlRoundTrip)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createConnection(hw, &instance);

    lcb_U32 set_idle = 17, set_intvl = 3, set_cnt = 5, set_user_tmo = 9000;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_TCP_KEEPALIVE_IDLE, &set_idle));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_TCP_KEEPALIVE_INTERVAL, &set_intvl));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_TCP_KEEPALIVE_COUNT, &set_cnt));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_TCP_USER_TIMEOUT, &set_user_tmo));

    lcb_U32 get_idle = 0, get_intvl = 0, get_cnt = 0, get_user_tmo = 0;
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_TCP_KEEPALIVE_IDLE, &get_idle));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_TCP_KEEPALIVE_INTERVAL, &get_intvl));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_TCP_KEEPALIVE_COUNT, &get_cnt));
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_TCP_USER_TIMEOUT, &get_user_tmo));

    EXPECT_EQ(set_idle, get_idle);
    EXPECT_EQ(set_intvl, get_intvl);
    EXPECT_EQ(set_cnt, get_cnt);
    EXPECT_EQ(set_user_tmo, get_user_tmo);
}

#endif /* __linux__ */
