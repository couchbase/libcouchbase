/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2020 Couchbase, Inc.
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

#include "socktest.h"

#ifndef LCB_NO_SSL

#include <lcbio/ssl.h>
#include <cstdlib>
using namespace LCBTest;
using std::string;
using std::vector;

class SSLTest : public SockTest
{
  protected:
    void SetUp() override
    {
        lcbio_ssl_global_init();
        lcb_STATUS errp = LCB_SUCCESS;
        // Initialize the SSL stuff

        SockTest::SetUp();
        loop->settings->sslopts = LCB_SSL_ENABLED | LCB_SSL_NOVERIFY;
        loop->settings->ssl_ctx = lcbio_ssl_new(nullptr, nullptr, nullptr, nullptr, 0, 1, &errp, loop->settings);
        loop->server->factory = TestServer::sslSocketFactory;
        EXPECT_FALSE(loop->settings->ssl_ctx == nullptr) << lcb_strerror_short(errp);
    }

    void TearDown() override
    {
        lcbio_ssl_free(loop->settings->ssl_ctx);
        loop->settings->ssl_ctx = nullptr;
        SockTest::TearDown();
    }
};

TEST_F(SSLTest, testBasic)
{
    // Copy/pasted from SockConnTest::testBasic

    ESocket sock;

    // We can connect
    loop->connect(&sock);
    ASSERT_FALSE(sock.sock == nullptr);
    ASSERT_TRUE(sock.creq == nullptr);
    ASSERT_EQ(1, sock.sock->refcount);

    // We can send data
    string sendStr("Hello World");
    RecvFuture rf(sendStr.size());
    FutureBreakCondition wbc(&rf);

    sock.conn->setRecv(&rf);
    sock.put(sendStr);
    sock.schedule();
    loop->setBreakCondition(&wbc);
    loop->start();
    rf.wait();
    ASSERT_TRUE(rf.isOk());
    ASSERT_EQ(rf.getString(), sendStr);

    // We can receive data
    string recvStr("Goodbye World!");
    SendFuture sf(recvStr);
    ReadBreakCondition rbc(&sock, recvStr.size());
    sock.conn->setSend(&sf);
    sock.reqrd(recvStr.size());
    sock.schedule();
    loop->setBreakCondition(&rbc);
    loop->start();
    sf.wait();
    ASSERT_TRUE(sf.isOk());
    ASSERT_EQ(sock.getReceived(), recvStr);

    // Clean it all up
    sock.close();
}

namespace
{
/* lcbio_ssl_new() reads the variable with getenv(), so the CRT's own copy of
 * the environment is what has to change. SetEnvironmentVariable() updates the
 * Win32 block and leaves that copy alone, which is why the other tests here
 * cannot be followed. _putenv() copies the string it is given, and an empty
 * value removes the variable. */
void setMinimumTlsEnv(const char *value)
{
#ifdef _WIN32
    std::string assignment("LCB_SSL_MINIMUM_TLS=");
    if (value != nullptr) {
        assignment += value;
    }
    _putenv(assignment.c_str());
#else
    if (value == nullptr) {
        unsetenv("LCB_SSL_MINIMUM_TLS");
    } else {
        setenv("LCB_SSL_MINIMUM_TLS", value, 1);
    }
#endif
}

/* The floor is only observable on the context, because reaching it means a
 * handshake the peer has to take part in. Comparing the settings against each
 * other rather than against OpenSSL's version constants keeps the assertion
 * independent of which header the test was compiled with. */
int minProtoFor(lcb_settings *settings, const char *minimum_tls)
{
    setMinimumTlsEnv(minimum_tls);
    lcb_STATUS err = LCB_SUCCESS;
    lcbio_pSSLCTX ctx = lcbio_ssl_new(nullptr, nullptr, nullptr, nullptr, 0, 1, &err, settings);
    EXPECT_FALSE(ctx == nullptr) << lcb_strerror_short(err);
    int version = lcbio_ssl_min_proto_version(ctx);
    lcbio_ssl_free(ctx);
    setMinimumTlsEnv(nullptr);
    return version;
}
} // namespace

/**
 * The default refuses TLS 1.0 and 1.1, and LCB_SSL_MINIMUM_TLS moves the floor
 * in both directions from there.
 */
TEST_F(SSLTest, minimumProtocolFollowsTheEnvironment)
{
    lcb_settings *settings = loop->settings;

    int by_default = minProtoFor(settings, nullptr);
    ASSERT_EQ(by_default, minProtoFor(settings, "tlsv1.2"));
    ASSERT_LT(minProtoFor(settings, "tlsv1"), by_default);
    ASSERT_LT(minProtoFor(settings, "tlsv1.1"), by_default);
    ASSERT_LT(minProtoFor(settings, "tlsv1"), minProtoFor(settings, "tlsv1.1"));
    ASSERT_GT(minProtoFor(settings, "tlsv1.3"), by_default);
}

/**
 * A value that names no protocol leaves the floor where it was. Lowering it
 * would turn a typo into a downgrade.
 */
TEST_F(SSLTest, unrecognizedMinimumProtocolKeepsTheDefault)
{
    lcb_settings *settings = loop->settings;

    int by_default = minProtoFor(settings, nullptr);
    ASSERT_EQ(by_default, minProtoFor(settings, "tlsv1.4"));
    ASSERT_EQ(by_default, minProtoFor(settings, "TLS1.2"));
}

#else
class SSLTest : public ::testing::Test
{
};
TEST_F(SSLTest, DISABLED_testBasic)
{
    EXPECT_FALSE(true);
}
#endif
