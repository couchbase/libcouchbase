/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012-2019 Couchbase, Inc.
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
#include "internal.h"
#include "iotests.h"

class RegressionUnitTest : public MockUnitTest
{
};

static bool callbackInvoked = false;

extern "C" {
    static void get_callback(lcb_t, lcb_CALLBACKTYPE, const lcb_RESPGET *resp)
    {
        EXPECT_EQ(resp->rc, LCB_KEY_ENOENT);
        int *counter_p = reinterpret_cast<int *>(const_cast<void *>(resp->cookie));
        EXPECT_TRUE(counter_p != NULL);
        EXPECT_GT(*counter_p, 0);
        *counter_p -= 1;
        callbackInvoked = true;
    }

    static void stats_callback(lcb_t, lcb_CALLBACKTYPE, const lcb_RESPSTATS *resp)
    {
        EXPECT_EQ(resp->rc, LCB_SUCCESS);
        if (resp->nkey == 0) {
            int *counter_p = reinterpret_cast<int *>(const_cast<void *>(resp->cookie));
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
    lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);
    lcb_install_callback3(instance, LCB_CALLBACK_STATS, (lcb_RESPCALLBACK)stats_callback);
    lcb_uint32_t tmoval = 15000000;
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmoval);

    std::string key = "testGetMiss1";
    lcb_CMDGET getCmd1 = {0};
    LCB_CMD_SET_KEY(&getCmd1, key.c_str(), key.size());

    lcb_CMDSTATS statCmd = {0};
    int ii;

    // Lets spool up a lot of commands in one of the buffers so that we
    // know we need to search for it a few times when we get responses..
    int callbackCounter = 1000;
    void *ptr = &callbackCounter;

    for (ii = 0; ii < 1000; ++ii) {
        EXPECT_EQ(LCB_SUCCESS, lcb_get3(instance, ptr, &getCmd1));
    }

    callbackCounter++;
    EXPECT_EQ(LCB_SUCCESS, lcb_stats3(instance, ptr, &statCmd));

    callbackCounter += 1000;
    for (ii = 0; ii < 1000; ++ii) {
        EXPECT_EQ(LCB_SUCCESS, lcb_get3(instance, ptr, &getCmd1));
    }

    callbackCounter++;
    EXPECT_EQ(LCB_SUCCESS, lcb_stats3(instance, ptr, &statCmd));

    callbackCounter++;
    EXPECT_EQ(LCB_SUCCESS, lcb_stats3(instance, ptr, &statCmd));

    EXPECT_EQ(LCB_SUCCESS, lcb_wait(instance));
    ASSERT_TRUE(callbackInvoked);
    ASSERT_EQ(0, callbackCounter);
}

struct ccbc_275_info_st {
    int call_count;
    lcb_error_t last_err;
};

extern "C" {
static void get_callback_275(lcb_t instance, lcb_CALLBACKTYPE, const lcb_RESPGET *resp)
{
    struct ccbc_275_info_st *info = (struct ccbc_275_info_st *)resp->cookie;
    info->call_count++;
    info->last_err = resp->rc;
    lcb_breakout(instance);
}

}

TEST_F(RegressionUnitTest, CCBC_275)
{
    SKIP_UNLESS_MOCK();
    lcb_t instance;
    lcb_error_t err;
    struct lcb_create_st crOpts;
    const char *argv[] = { "--buckets", "protected:secret:couchbase", NULL };
    MockEnvironment mock_o(argv, "protected"), *mock = &mock_o;
    struct ccbc_275_info_st info = { 0, LCB_SUCCESS };

    mock->makeConnectParams(crOpts, NULL);
    crOpts.v.v0.user = "protected";
    crOpts.v.v0.passwd = "secret";
    crOpts.v.v0.bucket = "protected";
    doLcbCreate(&instance, &crOpts, mock);

    err = lcb_connect(instance);
    ASSERT_EQ(LCB_SUCCESS, err);

    err = lcb_wait(instance);
    ASSERT_EQ(LCB_SUCCESS, err);

    std::string key = "key_CCBC_275";
    lcb_CMDGET cmd = {0};
    LCB_CMD_SET_KEY(&cmd, key.c_str(), key.size());

    // Set timeout for a short interval
    lcb_uint32_t tmo_usec = 100000;
    lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmo_usec);

    // In the past this issue would result in several symptoms:
    // (1) the client would crash (ringbuffer_consumed in failout_server)
    // (2) the client would hang
    // (3) the subsequent lcb_wait would return immediately.
    // So far I've managed to reproduce (1), not clear on (2) and (3)
    mock->hiccupNodes(1000, 1);
    lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback_275);

    ASSERT_EQ(LCB_SUCCESS, lcb_get3(instance, &info, &cmd));
    lcb_wait(instance);
    ASSERT_EQ(1, info.call_count);

    ASSERT_ERRISA(info.last_err, LCB_ERRTYPE_NETWORK);

    // Make sure we've fully purged and disconnected the server
    struct lcb_cntl_vbinfo_st vbi;
    memset(&vbi, 0, sizeof(vbi));
    vbi.v.v0.key = key.c_str();
    vbi.v.v0.nkey = key.size();
    err = lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_VBMAP, &vbi);
    ASSERT_EQ(LCB_SUCCESS, err);
//    ASSERT_EQ(LCB_CONNSTATE_UNINIT,
//              instance->servers[vbi.v.v0.server_index].connection.state);

    // Restore the timeout to something sane
    tmo_usec = 5000000;
    err = lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmo_usec);
    ASSERT_EQ(LCB_SUCCESS, err);

    mock->hiccupNodes(0, 0);
    info.call_count = 0;
    ASSERT_EQ(LCB_SUCCESS, lcb_get3(instance, &info, &cmd));
    lcb_wait(instance);
    ASSERT_EQ(1, info.call_count);

    ASSERT_EQ(LCB_KEY_ENOENT, info.last_err);

    lcb_destroy(instance);
}


TEST_F(MockUnitTest, testIssue59)
{
    // lcb_wait() blocks forever if there is nothing queued
    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);

    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
}


extern "C" {
    struct rvbuf {
        lcb_error_t error;
        lcb_cas_t cas1;
        lcb_cas_t cas2;
        char *bytes;
        lcb_size_t nbytes;
        lcb_int32_t counter;
    };

    static void df_store_callback1(lcb_t instance, lcb_CALLBACKTYPE, const lcb_RESPSTORE *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)resp->cookie;
        rv->error = resp->rc;
        lcb_stop_loop(instance);
    }

    static void df_store_callback2(lcb_t instance, lcb_CALLBACKTYPE, const lcb_RESPSTORE *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)resp->cookie;
        rv->error = resp->rc;
        rv->cas2 = resp->cas;
        lcb_stop_loop(instance);
    }

    static void df_get_callback(lcb_t instance, lcb_CALLBACKTYPE, const lcb_RESPSTORE *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)resp->cookie;
        const char *value = "{\"bar\"=>1, \"baz\"=>2}";
        lcb_size_t nvalue = strlen(value);
        rv->error = resp->rc;
        rv->cas1 = resp->cas;
        lcb_CMDSTORE storecmd = {0};
        LCB_CMD_SET_KEY(&storecmd, resp->key, resp->nkey);
        LCB_CMD_SET_VALUE(&storecmd, value, nvalue);
        storecmd.operation = LCB_SET;
        storecmd.cas = resp->cas;
        ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, rv, &storecmd));
    }
}

TEST_F(MockUnitTest, testDoubleFreeError)
{
    lcb_error_t err;
    struct rvbuf rv;
    const char *key = "test_compare_and_swap_async_", *value = "{\"bar\" => 1}";
    lcb_size_t nkey = strlen(key), nvalue = strlen(value);
    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);

    /* prefill the bucket */
    (void)lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)df_store_callback1);

    lcb_CMDSTORE storecmd = {0};
    LCB_CMD_SET_KEY(&storecmd, key, nkey);
    LCB_CMD_SET_VALUE(&storecmd, value, nvalue);
    storecmd.operation = LCB_SET;

    ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, &rv, &storecmd));
    lcb_run_loop(instance);
    ASSERT_EQ(LCB_SUCCESS, rv.error);

    /* run exercise
     *
     * 1. get the valueue and its cas
     * 2. atomic set new valueue using old cas
     */
    (void)lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)df_store_callback2);
    (void)lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)df_get_callback);

    lcb_CMDGET getcmd = {0};
    LCB_CMD_SET_KEY(&getcmd, key, nkey);

    ASSERT_EQ(LCB_SUCCESS, lcb_get3(instance, &rv, &getcmd));
    rv.cas1 = rv.cas2 = 0;
    lcb_run_loop(instance);
    ASSERT_EQ(LCB_SUCCESS, rv.error);
    ASSERT_GT(rv.cas1, 0);
    ASSERT_GT(rv.cas2, 0);
    ASSERT_NE(rv.cas1, rv.cas2);
}

TEST_F(MockUnitTest, testBrokenFirstNodeInList)
{
    SKIP_UNLESS_MOCK();
    MockEnvironment *mock = MockEnvironment::getInstance();
    lcb_create_st options;
    mock->makeConnectParams(options, NULL);
    std::string nodes = options.v.v0.host;
    nodes = "1.2.3.4:4321;" + nodes;
    options.v.v0.host = nodes.c_str();

    lcb_t instance;
    doLcbCreate(&instance, &options, mock);
    lcb_cntl_setu32(instance, LCB_CNTL_OP_TIMEOUT, LCB_MS2US(200));
    ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
    lcb_destroy(instance);
}
