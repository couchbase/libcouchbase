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

/**
 * Keep these around in case we do something useful here in the future
 */
void MockUnitTest::SetUpTestCase() { }
void MockUnitTest::TearDownTestCase() { }

extern "C" {
    static void error_callback(lcb_t instance,
                               lcb_error_t err,
                               const char *errinfo)
    {
        std::cerr << "Error " << lcb_strerror(instance, err);
        if (errinfo) {
            std::cerr << errinfo;
        }

        ASSERT_TRUE(false);
    }
}

void MockUnitTest::createConnection(lcb_t &instance)
{
    MockEnvironment::getInstance()->createConnection(instance);
    (void)lcb_set_error_callback(instance, error_callback);
    ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
    lcb_wait(instance);
}

extern "C" {
    static void flags_store_callback(lcb_t,
                                     const void *,
                                     lcb_storage_t operation,
                                     lcb_error_t error,
                                     const lcb_store_resp_t *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, error);
        ASSERT_EQ(5, resp->v.v0.nkey);
        ASSERT_EQ(0, memcmp(resp->v.v0.key, "flags", 5));
        ASSERT_EQ(LCB_SET, operation);
    }

    static void flags_get_callback(lcb_t, const void *,
                                   lcb_error_t error,
                                   const lcb_get_resp_t *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, error);
        ASSERT_EQ(5, resp->v.v0.nkey);
        ASSERT_EQ(0, memcmp(resp->v.v0.key, "flags", 5));
        ASSERT_EQ(1, resp->v.v0.nbytes);
        ASSERT_EQ(0, memcmp(resp->v.v0.bytes, "x", 1));
        ASSERT_EQ(0xdeadbeef, resp->v.v0.flags);
    }
}

TEST_F(MockUnitTest, testFlags)
{
    lcb_t instance;
    createConnection(instance);
    (void)lcb_set_get_callback(instance, flags_get_callback);
    (void)lcb_set_store_callback(instance, flags_store_callback);

    lcb_store_cmd_t storeCommand(LCB_SET, "flags", 5, "x", 1, 0xdeadbeef);
    lcb_store_cmd_t *storeCommands[] = { &storeCommand };

    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, NULL, 1, storeCommands));
    // Wait for it to be persisted
    lcb_wait(instance);

    lcb_get_cmd_t cmd("flags", 5);
    lcb_get_cmd_t *cmds[] = { &cmd };
    ASSERT_EQ(LCB_SUCCESS, lcb_get(instance, NULL, 1, cmds));

    /* Wait for it to be received */
    lcb_wait(instance);
}


extern "C" {
    static void syncmode_store_callback(lcb_t,
                                        const void *cookie,
                                        lcb_storage_t,
                                        lcb_error_t error,
                                        const lcb_store_resp_t *)
    {
        int *status = (int *)cookie;
        *status = error;
    }
}

TEST_F(MockUnitTest, testSyncmodeDefault)
{

    lcb_t instance;
    createConnection(instance);
    ASSERT_EQ(LCB_ASYNCHRONOUS, lcb_behavior_get_syncmode(instance));
    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testSyncmodeBehaviorToggle)
{
    lcb_t instance;
    createConnection(instance);
    lcb_behavior_set_syncmode(instance, LCB_SYNCHRONOUS);
    ASSERT_EQ(LCB_SYNCHRONOUS, lcb_behavior_get_syncmode(instance));
    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testSyncStore)
{
    lcb_t instance;
    createConnection(instance);
    lcb_behavior_set_syncmode(instance, LCB_SYNCHRONOUS);
    ASSERT_EQ(LCB_SYNCHRONOUS, lcb_behavior_get_syncmode(instance));

    lcb_set_store_callback(instance, syncmode_store_callback);

    int cookie = 0xffff;
    lcb_store_cmd_t cmd(LCB_SET, "key", 3);
    lcb_store_cmd_t *cmds[] = { &cmd };
    lcb_error_t ret = lcb_store(instance, &cookie, 1, cmds);
    ASSERT_EQ(LCB_SUCCESS, ret);
    ASSERT_EQ((int)LCB_SUCCESS, cookie);
    cookie = 0xffff;

    cmd.v.v0.operation = LCB_ADD;
    ret = lcb_store(instance, &cookie, 1, cmds);
    ASSERT_TRUE(ret == LCB_KEY_EEXISTS &&
                cookie == LCB_KEY_EEXISTS);
    lcb_destroy(instance);
}

extern "C" {
    static void timings_callback(lcb_t,
                                 const void *cookie,
                                 lcb_timeunit_t timeunit,
                                 lcb_uint32_t min,
                                 lcb_uint32_t max,
                                 lcb_uint32_t total,
                                 lcb_uint32_t maxtotal)
    {
        FILE *fp = (FILE *)cookie;
        if (fp != NULL) {
            fprintf(fp, "[%3u - %3u]", min, max);

            switch (timeunit) {
            case LCB_TIMEUNIT_NSEC:
                fprintf(fp, "ns");
                break;
            case LCB_TIMEUNIT_USEC:
                fprintf(fp, "us");
                break;
            case LCB_TIMEUNIT_MSEC:
                fprintf(fp, "ms");
                break;
            case LCB_TIMEUNIT_SEC:
                fprintf(fp, "s");
                break;
            default:
                ;
            }

            int num = (int)((float)20.0 * (float)total / (float)maxtotal);

            fprintf(fp, " |");
            for (int ii = 0; ii < num; ++ii) {
                fprintf(fp, "#");
            }

            fprintf(fp, " - %u\n", total);
        }
    }
}

TEST_F(MockUnitTest, testTimings)
{
    FILE *fp = stdout;
    if (getenv("LCB_VERBOSE_TESTS") == NULL) {
        fp = NULL;
    }

    lcb_t instance;
    createConnection(instance);
    lcb_enable_timings(instance);

    lcb_store_cmd_t storecmd(LCB_SET, "counter", 7, "0", 1);
    lcb_store_cmd_t *storecmds[] = { &storecmd };

    lcb_store(instance, NULL, 1, storecmds);
    lcb_wait(instance);
    for (int ii = 0; ii < 100; ++ii) {
        lcb_arithmetic_cmd_t acmd("counter", 7, 1);
        lcb_arithmetic_cmd_t *acmds[] = { &acmd };
        lcb_arithmetic(instance, NULL, 1, acmds);
        lcb_wait(instance);
    }
    if (fp) {
        fprintf(fp, "              +---------+---------+\n");
    }
    lcb_get_timings(instance, fp, timings_callback);
    if (fp) {
        fprintf(fp, "              +--------------------\n");
    }
    lcb_disable_timings(instance);
    lcb_destroy(instance);
}


extern "C" {
    static void timeout_error_callback(lcb_t instance,
                                       lcb_error_t err,
                                       const char *errinfo)
    {
        if (err == LCB_ETIMEDOUT) {
            return;
        }
        std::cerr << "Error " << lcb_strerror(instance, err);
        if (errinfo) {
            std::cerr << errinfo;
        }
        std::cerr << std::endl;
        abort();
    }

    int timeout_seqno = 0;
    int timeout_stats_done = 0;

    static void timeout_store_callback(lcb_t,
                                       const void *cookie,
                                       lcb_storage_t,
                                       lcb_error_t error,
                                       const lcb_store_resp_t *)
    {
        lcb_io_opt_t io = (lcb_io_opt_t)cookie;

        ASSERT_EQ(LCB_SUCCESS, error);
        timeout_seqno--;
        if (timeout_stats_done && timeout_seqno == 0) {
            io->v.v0.stop_event_loop(io);
        }
    }

    static void timeout_stat_callback(lcb_t instance,
                                      const void *cookie,
                                      lcb_error_t error,
                                      const lcb_server_stat_resp_t *resp)
    {
        lcb_error_t err;
        lcb_io_opt_t io = (lcb_io_opt_t)cookie;
        char *statkey;
        lcb_size_t nstatkey;

        ASSERT_EQ(0, resp->version);
        const char *server_endpoint = resp->v.v0.server_endpoint;
        const void *key = resp->v.v0.key;
        lcb_size_t nkey = resp->v.v0.nkey;
        const void *bytes = resp->v.v0.bytes;
        lcb_size_t nbytes = resp->v.v0.nbytes;

        ASSERT_EQ(LCB_SUCCESS, error);
        if (server_endpoint != NULL) {
            nstatkey = strlen(server_endpoint) + nkey + 2;
            statkey = new char[nstatkey];
            snprintf(statkey, nstatkey, "%s-%s", server_endpoint,
                     (const char *)key);

            lcb_store_cmd_t storecmd(LCB_SET, statkey, nstatkey, bytes, nbytes);
            lcb_store_cmd_t *storecmds[] = { &storecmd };
            err = lcb_store(instance, io, 1, storecmds);
            ASSERT_EQ(LCB_SUCCESS, err);
            timeout_seqno++;
            delete []statkey;
        } else {
            timeout_stats_done = 1;
        }
    }
}

TEST_F(MockUnitTest, testTimeout)
{
    // @todo we need to have a test that actually tests the timeout callback..
    lcb_t instance;
    lcb_io_opt_t io;
    createConnection(instance);

    (void)lcb_set_error_callback(instance, timeout_error_callback);
    (void)lcb_set_stat_callback(instance, timeout_stat_callback);
    (void)lcb_set_store_callback(instance, timeout_store_callback);

    io = (lcb_io_opt_t)lcb_get_cookie(instance);

    lcb_server_stats_cmd_t stat;
    lcb_server_stats_cmd_t *commands[] = {&stat };

    ASSERT_EQ(LCB_SUCCESS, lcb_server_stats(instance, io, 1, commands));
    io->v.v0.run_event_loop(io);
    lcb_destroy(instance);
}


TEST_F(MockUnitTest, testIssue59)
{
    // lcb_wait() blocks forever if there is nothing queued
    lcb_t instance;
    createConnection(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_wait(instance);
    lcb_destroy(instance);
}

extern "C" {
    struct rvbuf {
        lcb_error_t error;
        lcb_cas_t cas1;
        lcb_cas_t cas2;
    };

    static void df_store_callback1(lcb_t instance,
                                   const void *cookie,
                                   lcb_storage_t,
                                   lcb_error_t error,
                                   const lcb_store_resp_t *)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        rv->error = error;
        lcb_io_opt_t io = (lcb_io_opt_t)lcb_get_cookie(instance);
        io->v.v0.stop_event_loop(io);
    }

    static void df_store_callback2(lcb_t instance,
                                   const void *cookie,
                                   lcb_storage_t,
                                   lcb_error_t error,
                                   const lcb_store_resp_t *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        rv->error = error;
        rv->cas2 = resp->v.v0.cas;
        lcb_io_opt_t io = (lcb_io_opt_t)lcb_get_cookie(instance);
        io->v.v0.stop_event_loop(io);
    }

    static void df_get_callback(lcb_t instance,
                                const void *cookie,
                                lcb_error_t error,
                                const lcb_get_resp_t *resp)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        const char *value = "{\"bar\"=>1, \"baz\"=>2}";
        lcb_size_t nvalue = strlen(value);
        lcb_error_t err;

        rv->error = error;
        rv->cas1 = resp->v.v0.cas;
        lcb_store_cmd_t storecmd(LCB_SET, resp->v.v0.key, resp->v.v0.nkey,
                                 value, nvalue, 0, 0, resp->v.v0.cas);
        lcb_store_cmd_t *storecmds[] = { &storecmd };

        err = lcb_store(instance, rv, 1, storecmds);
        ASSERT_EQ(LCB_SUCCESS, err);
    }
}

TEST_F(MockUnitTest, testDoubleFreeError)
{
    lcb_error_t err;
    struct rvbuf rv;
    const char *key = "test_compare_and_swap_async_", *value = "{\"bar\" => 1}";
    lcb_size_t nkey = strlen(key), nvalue = strlen(value);
    lcb_io_opt_t io;
    lcb_t instance;

    createConnection(instance);
    io = (lcb_io_opt_t)lcb_get_cookie(instance);

    /* prefill the bucket */
    (void)lcb_set_store_callback(instance, df_store_callback1);

    lcb_store_cmd_t storecmd(LCB_SET, key, nkey, value, nvalue);
    lcb_store_cmd_t *storecmds[] = { &storecmd };

    err = lcb_store(instance, &rv, 1, storecmds);
    ASSERT_EQ(LCB_SUCCESS, err);
    io->v.v0.run_event_loop(io);
    ASSERT_EQ(LCB_SUCCESS, rv.error);

    /* run exercise
     *
     * 1. get the valueue and its cas
     * 2. atomic set new valueue using old cas
     */
    (void)lcb_set_store_callback(instance, df_store_callback2);
    (void)lcb_set_get_callback(instance, df_get_callback);

    lcb_get_cmd_t getcmd(key, nkey);
    lcb_get_cmd_t *getcmds[] = { &getcmd };

    err = lcb_get(instance, &rv, 1, getcmds);
    ASSERT_EQ(LCB_SUCCESS, err);
    rv.cas1 = rv.cas2 = 0;
    io->v.v0.run_event_loop(io);
    ASSERT_EQ(LCB_SUCCESS, rv.error);
    ASSERT_GT(rv.cas1, 0);
    ASSERT_GT(rv.cas2, 0);
    ASSERT_NE(rv.cas1, rv.cas2);
}

TEST_F(MockUnitTest, testBrokenFirstNodeInList)
{
    MockEnvironment *mock = MockEnvironment::getInstance();
    lcb_create_st options;
    mock->makeConnectParams(options, NULL);
    std::string nodes = options.v.v0.host;
    nodes = "1.2.3.4;" + nodes;
    options.v.v0.host = nodes.c_str();

    lcb_t instance;
    ASSERT_EQ(LCB_SUCCESS, lcb_create(&instance, &options));
    lcb_set_timeout(instance, 200000); /* 200 ms */
    ASSERT_EQ(LCB_SUCCESS, lcb_connect(instance));
    lcb_destroy(instance);
}
