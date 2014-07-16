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
#include "iotests.h"
#include <map>

#include "internal.h" /* vbucket_* things from lcb_t */
#include <lcbio/iotable.h>
#include "bucketconfig/bc_http.h"

#define LOGARGS(instance, lvl) \
    instance->settings, "tests-MUT", LCB_LOG_##lvl, __FILE__, __LINE__


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
    HandleWrap hw;
    createConnection(hw, instance);

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
}



struct async_ctx {
    int count;
    lcbio_pTABLE table;
};

extern "C" {
static void dtor_callback(const void *cookie)
{
    async_ctx *ctx = (async_ctx *)cookie;
    ctx->count++;
    IOT_STOP(ctx->table);
}
}

TEST_F(MockUnitTest, testAsyncDestroy)
{
    lcb_t instance;
    createConnection(instance);
    lcbio_pTABLE iot = instance->iotable;
    lcb_settings *settings = instance->settings;

    storeKey(instance, "foo", "bar");
    // Now destroy the instance
    async_ctx ctx;
    ctx.count = 0;
    ctx.table = iot;
    lcb_set_destroy_callback(instance, dtor_callback);
    lcb_destroy_async(instance, &ctx);
    lcb_settings_ref(settings);
    lcbio_table_ref(iot);
    lcb_run_loop(instance);
    lcb_settings_unref(settings);
    lcbio_table_unref(iot);
    ASSERT_EQ(1, ctx.count);
}

TEST_F(MockUnitTest, testGetHostInfo)
{
    lcb_t instance;
    createConnection(instance);
    lcb_config_transport_t tx;
    const char *hoststr = lcb_get_node(instance, LCB_NODE_HTCONFIG, 0);
    ASSERT_FALSE(hoststr == NULL);

    hoststr = lcb_get_node(instance, LCB_NODE_HTCONFIG_CONNECTED, 0);
    lcb_error_t err = lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_CONFIG_TRANSPORT, &tx);

    ASSERT_EQ(LCB_SUCCESS, err);
    if (tx == LCB_CONFIG_TRANSPORT_HTTP) {
        ASSERT_FALSE(hoststr == NULL);
        hoststr = lcb_get_node(instance, LCB_NODE_HTCONFIG_CONNECTED, 99);
        ASSERT_FALSE(hoststr == NULL);
    } else {
        if (hoststr) {
            printf("%s\n", hoststr);
        }
        ASSERT_TRUE(hoststr == NULL);
    }

    // Get any data node
    using std::map;
    using std::string;
    map<string,bool> smap;

    // Ensure we only get unique nodes
    for (size_t ii = 0; ii < lcb_get_num_nodes(instance); ii++) {
        const char *cur = lcb_get_node(instance, LCB_NODE_DATA, ii);
        ASSERT_FALSE(cur == NULL);
        ASSERT_FALSE(smap[cur]);
        smap[cur] = true;
    }
    lcb_destroy(instance);

    // Try with no connection
    err = lcb_create(&instance, NULL);
    ASSERT_EQ(LCB_SUCCESS, err);

    hoststr = lcb_get_node(instance, LCB_NODE_HTCONFIG_CONNECTED, 0);
    ASSERT_TRUE(NULL == hoststr);

    hoststr = lcb_get_node(instance, LCB_NODE_HTCONFIG, 0);
    ASSERT_TRUE(NULL == hoststr);



    // These older API functions are special as they should never return NULL
    hoststr = lcb_get_host(instance);
    ASSERT_FALSE(hoststr == NULL);
    ASSERT_STREQ("localhost", hoststr);

    hoststr = lcb_get_port(instance);
    ASSERT_FALSE(hoststr == NULL);
    ASSERT_STREQ("8091", hoststr);

    lcb_destroy(instance);
}

TEST_F(MockUnitTest, testEmptyKeys)
{
    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);

    union {
        lcb_CMDGET get;
        lcb_CMDSTORE store;
        lcb_CMDCOUNTER counter;
        lcb_CMDENDURE endure;
        lcb_CMDOBSERVE observe;
        lcb_CMDTOUCH touch;
        lcb_CMDUNLOCK unlock;
        lcb_CMDGETREPLICA rget;
        lcb_CMDBASE base;
        lcb_CMDSTATS stats;
    } u;
    memset(&u, 0, sizeof u);

    lcb_sched_enter(instance);

    ASSERT_EQ(LCB_EMPTY_KEY, lcb_get3(instance, NULL, &u.get));
    ASSERT_EQ(LCB_EMPTY_KEY, lcb_store3(instance, NULL, &u.store));
    ASSERT_EQ(LCB_EMPTY_KEY, lcb_counter3(instance, NULL, &u.counter));
    ASSERT_EQ(LCB_EMPTY_KEY, lcb_touch3(instance, NULL, &u.touch));
    ASSERT_EQ(LCB_EMPTY_KEY, lcb_unlock3(instance, NULL, &u.unlock));
    ASSERT_EQ(LCB_EMPTY_KEY, lcb_rget3(instance, NULL, &u.rget));

    // Observe and such
    lcb_MULTICMD_CTX *ctx = lcb_observe3_ctxnew(instance);
    ASSERT_EQ(LCB_EMPTY_KEY, ctx->addcmd(ctx, &u.observe));
    ctx->fail(ctx);

    lcb_durability_opts_t dopts;
    memset(&dopts, 0, sizeof dopts);
    dopts.v.v0.persist_to = 1;

    ctx = lcb_endure3_ctxnew(instance, &dopts, NULL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(LCB_EMPTY_KEY, ctx->addcmd(ctx, &u.endure));
    ctx->fail(ctx);

    ASSERT_EQ(LCB_SUCCESS, lcb_stats3(instance, NULL, &u.stats));
    lcb_sched_fail(instance);
}
