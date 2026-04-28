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

/**
 * Regression tests for the I/O plugin destructor (lcb_destroy_io_ops →
 * iops_lcb_dtor). These exercise the destructor's behavior in the presence of
 * the higher-layer lcbio_TIMER leak that occurs in real KV teardown when a
 * Server's connctx is left with pending completions (see CCBC ticket "libuv:
 * hang in iops_lcb_dtor from leaked SSL timer handles" / commit 4f86e69e).
 *
 * The leak shape: an lcbio_TIMER is allocated via lcbio_timer_new (which goes
 * through the plugin's create_timer hook and registers a uv_handle_t /
 * watcher), and lcbio_timer_destroy is never called for it. The plugin
 * destructor must still complete in bounded time without aborting or
 * hanging. Without the libuv-plugin fix, the destructor would either spin
 * forever (UV_RUN_ONCE blocking on a uv_loop_alive()==1 loop with no events
 * to process) or assert in uv_loop_close (UV_EBUSY).
 *
 * The test is plugin-agnostic at the surface — it uses the IOPS / lcbio
 * APIs only. Event-mode plugins (select, libev, libevent) handle the leak
 * trivially because their watcher abstraction does not pin the loop the way
 * an active uv_timer_t does, so this test passes on all plugins. Its
 * regression-guard value is specific to completion-mode plugins (libuv,
 * IOCP).
 */

#include "socktest.h"
#include <chrono>

using namespace LCBTest;

namespace
{
struct DtorTimer {
    static void cb(void * /* arg */) {}
};

/**
 * Allocate an lcbio_TIMER through the iotable's plugin hooks. We deliberately
 * never call lcbio_timer_destroy on the returned pointer; the test is
 * verifying that the plugin destructor copes with the leak.
 */
lcbio_TIMER *make_leaked_timer(lcbio_pTABLE iot)
{
    return lcbio_timer_new(iot, nullptr, DtorTimer::cb);
}

/**
 * Time-bounded assertion: invoke the destructor sequence and assert it
 * completes within max_ms. We expose a generous margin (the actual fixed
 * code completes in well under a millisecond) so this is robust on slow
 * CI runners; the contract under test is "does not hang and does not
 * abort", not "fast".
 */
void teardown_within(lcb_io_opt_t io, lcbio_pTABLE iot, unsigned max_ms)
{
    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();

    lcbio_table_unref(iot);
    lcb_destroy_io_ops(io);

    auto t1 = clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    ASSERT_LT(elapsed_ms, (long long)max_ms)
        << "lcb_destroy_io_ops took " << elapsed_ms << "ms; expected < " << max_ms << "ms";
}
} // namespace

class SockTeardownTest : public ::testing::Test
{
};

/**
 * Baseline: no leaked timers. Plugin teardown should be near-instant on every
 * plugin. This pins down the lower bound and catches gross destructor
 * regressions even before the leak-handling logic kicks in.
 */
TEST_F(SockTeardownTest, NoLeakedTimers)
{
    lcb_initialize_socket_subsystem();

    lcb_io_opt_t io = nullptr;
    ASSERT_EQ(LCB_SUCCESS, lcb_create_io_ops(&io, nullptr));
    ASSERT_NE(nullptr, io);

    lcbio_pTABLE iot = lcbio_table_new(io);
    ASSERT_NE(nullptr, iot);

    teardown_within(io, iot, /* max_ms */ 1000);
}

/**
 * Regression guard for the libuv iops_lcb_dtor force-close path. Allocate
 * several lcbio_TIMER objects through the iotable, never destroy them, then
 * tear down the iotable + io_ops. With the fix in place, the libuv plugin's
 * destructor walks the loop and force-closes the leftover uv_timer_t handles
 * via timer_close_cb, balancing the iops_refcount and letting uv_loop_close
 * succeed. Without the fix, this either spins indefinitely (default-ref'd
 * timers, no events) or asserts in uv_loop_delete (uv_unref'd timers,
 * iops_refcount > 1 at delete time).
 *
 * Seven leaked timers matches the count observed in real KV teardown of an
 * SSL-connected three-node cluster: ~3 per active connctx (one
 * lcbio_CTX::as_err + two SSL completion timers as_read/as_write). Picking
 * a slightly higher number gives the test some margin if the per-connctx
 * count grows over time.
 */
TEST_F(SockTeardownTest, LeakedTimersDoNotHangDestroy)
{
    lcb_initialize_socket_subsystem();

    lcb_io_opt_t io = nullptr;
    ASSERT_EQ(LCB_SUCCESS, lcb_create_io_ops(&io, nullptr));
    ASSERT_NE(nullptr, io);

    lcbio_pTABLE iot = lcbio_table_new(io);
    ASSERT_NE(nullptr, iot);

    /* Leak ten timers. They will never have lcbio_timer_destroy called on
     * them; their underlying plugin handles (uv_timer_t in libuv,
     * lcb_io_event watcher in event-mode plugins) are still registered with
     * the loop when the destructor runs. */
    for (int i = 0; i < 10; ++i) {
        lcbio_TIMER *t = make_leaked_timer(iot);
        ASSERT_NE(nullptr, t);
        (void)t;
    }

    teardown_within(io, iot, /* max_ms */ 1000);
}

/**
 * As above, but with a mix of armed-and-leaked and unarmed-and-leaked
 * timers. lcbio_timer_rearm goes through the plugin's update_timer hook
 * which on libuv calls uv_timer_start (handle becomes "active"). The
 * destructor must close active timer handles too, not just inactive ones.
 */
TEST_F(SockTeardownTest, ArmedLeakedTimersDoNotHangDestroy)
{
    lcb_initialize_socket_subsystem();

    lcb_io_opt_t io = nullptr;
    ASSERT_EQ(LCB_SUCCESS, lcb_create_io_ops(&io, nullptr));
    ASSERT_NE(nullptr, io);

    lcbio_pTABLE iot = lcbio_table_new(io);
    ASSERT_NE(nullptr, iot);

    /* Five armed timers with a far-future deadline (60s) so they will not
     * fire before destruction. Plus five inactive ones. */
    for (int i = 0; i < 5; ++i) {
        lcbio_TIMER *t = make_leaked_timer(iot);
        ASSERT_NE(nullptr, t);
        lcbio_timer_rearm(t, 60u * 1000u * 1000u /* usec */);
    }
    for (int i = 0; i < 5; ++i) {
        lcbio_TIMER *t = make_leaked_timer(iot);
        ASSERT_NE(nullptr, t);
        (void)t;
    }

    teardown_within(io, iot, /* max_ms */ 1000);
}
