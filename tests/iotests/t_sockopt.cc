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
 * Applying a socket option has to report the outcome the plugin gave it.
 * lcbio_TABLE::C_cntl once returned `cntl(...) == 0`, so on completion-mode
 * plugins a success was reported as a failure and a failure as a success --
 * invisible from the kernel's side, because the option was applied either way.
 * Asserting only that the kernel agrees would pass against that bug, so the
 * return value is checked first and the effect second.
 */

#include "iotests.h"

#if defined(__linux__)

#include "internal.h"
#include <lcbio/iotable.h>
#include <lcbio/connect.h>
#include <lcbio/ctx.h>
#include <lcbio/ioutils.h>
#include <mcserver/mcserver.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

class SockoptUnitTest : public MockUnitTest
{
};

namespace
{
lcbio_SOCKET *first_kv_socket(lcb_INSTANCE *instance)
{
    for (size_t ii = 0; ii < LCBT_NSERVERS(instance); ++ii) {
        lcb::Server *server = instance->get_server(ii);
        if (server != nullptr && server->connctx != nullptr && server->connctx->sock != nullptr) {
            return server->connctx->sock;
        }
    }
    return nullptr;
}

int socket_fd(lcbio_SOCKET *sock)
{
    if (sock->io->is_E()) {
        return (int)sock->u.fd;
    }
    return sock->u.sd != nullptr ? (int)sock->u.sd->socket : INVALID_SOCKET;
}
} // namespace

/* Same assertion on every I/O model: applying an option succeeds, and the
 * kernel carries it. */
TEST_F(SockoptUnitTest, testEnableSockoptReportsSuccess)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createConnection(hw, &instance);
    storeKey(instance, "sockopt-probe", "v");

    lcbio_SOCKET *sock = first_kv_socket(instance);
    ASSERT_TRUE(sock != nullptr) << "no active KV socket to inspect";

    ASSERT_STATUS_EQ(LCB_SUCCESS, lcbio_enable_sockopt(sock, LCB_IO_CNTL_TCP_NODELAY));

    int fd = socket_fd(sock);
    ASSERT_NE(INVALID_SOCKET, fd);
    int nodelay = 0;
    socklen_t len = sizeof(nodelay);
    ASSERT_EQ(0, ::getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, &len));
    EXPECT_NE(0, nodelay);
}

#endif /* __linux__ */
