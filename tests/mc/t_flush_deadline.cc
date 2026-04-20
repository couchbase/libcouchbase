/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2017-Present Couchbase, Inc.
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
 * Regression tests for CCBC-1684
 *   "Intermittent libcouchbase SDK application crash due to seemingly slow
 *    packet flush deadline update"
 *
 * When LCB_CNTL_RESET_TIMEOUT_ON_WAIT is on, on_flush_done passes a non-zero
 * `now` into mcreq_flush_done_ex, which used to rewrite pkt->start but
 * leave pkt->deadline alone.  If the flush callback ran after the original
 * deadline (easy with a short per-op timeout and any event-loop stall), the
 * resulting start > deadline tripped an assert in mcreq_reset_timeouts on
 * the next lcb_wait().
 */

#include "mctest.h"
#include "mc/mcreq-flush-inl.h"

class McFlushDeadline : public ::testing::Test
{
};

struct FlushDeadlineCookie {
    int ncalled{0};
    void *exp_kbuf{nullptr};
};

extern "C" {
static void flush_deadline_buf_free_cb(mc_PIPELINE *, const void *cookie, void *kbuf, void *)
{
    auto *ck = (FlushDeadlineCookie *)cookie;
    EXPECT_EQ(ck->exp_kbuf, kbuf);
    ck->ncalled++;
}
}

static void prep_packet(CQWrap &cq, PacketWrap &pw, FlushDeadlineCookie &cookie, const char *key)
{
    pw.setContigKey(key);
    ASSERT_TRUE(pw.reservePacket(&cq));
    cookie.exp_kbuf = pw.pktbuf;
    pw.setCookie(&cookie);
    pw.setHeaderSize();
    pw.copyHeader();
}

/*
 * After a flush-with-now, pkt->deadline must remain >= pkt->start even when
 * the flush happened "after" the original deadline.  The fix rebases both
 * start and deadline together and preserves the remaining timeout budget.
 *
 * This test fails on the pre-fix tree with:
 *   - EXPECT_GE(rd->deadline, rd->start) — invariant broken
 *   - mcreq_reset_timeouts abort() — the application crash
 */
TEST_F(McFlushDeadline, flushPreservesInvariant)
{
    CQWrap cq;
    PacketWrap pw;
    FlushDeadlineCookie cookie;
    cq.setBufFreeCallback(flush_deadline_buf_free_cb);

    prep_packet(cq, pw, cookie, "cbse22622");
    mcreq_enqueue_packet(pw.pipeline, pw.pkt);

    /* Seed a tight timeout window (5ms), mirroring the reproducer. */
    const hrtime_t operation_timeout_ns = 5ULL * 1000 * 1000;
    const hrtime_t orig_start = 1000000000ULL; /* 1s, arbitrary epoch */
    MCREQ_PKT_RDATA(pw.pkt)->start = orig_start;
    MCREQ_PKT_RDATA(pw.pkt)->deadline = orig_start + operation_timeout_ns;

    nb_IOV iov[4];
    unsigned to_flush = mcreq_flush_iov_fill(pw.pipeline, iov, 4, nullptr);
    ASSERT_GT(to_flush, 0u);

    /* Simulate on_flush_done firing far after the original deadline, as
     * would happen under LCB_CNTL_RESET_TIMEOUT_ON_WAIT=1 with a stalled
     * event loop.  Pre-fix: pkt->start became flush_time but pkt->deadline
     * stayed at orig_start + 5ms, leaving start > deadline. */
    const hrtime_t flush_time = orig_start + 10 * operation_timeout_ns;
    mcreq_flush_done_ex(pw.pipeline, to_flush, to_flush, flush_time);

    mc_REQDATA *rd = MCREQ_PKT_RDATA(pw.pkt);
    EXPECT_EQ(rd->start, flush_time);
    EXPECT_GE(rd->deadline, rd->start) << "invariant deadline >= start must hold after flush";
    EXPECT_EQ(rd->deadline - rd->start, operation_timeout_ns)
        << "flush must preserve the packet's remaining timeout budget";

    /* Most importantly: a subsequent mcreq_reset_timeouts must not abort.
     * This is the actual application-visible crash from CCBC-1684. */
    mcreq_reset_timeouts(pw.pipeline, flush_time + 42);
    EXPECT_EQ(MCREQ_PKT_RDATA(pw.pkt)->start, flush_time + 42);
    EXPECT_EQ(MCREQ_PKT_RDATA(pw.pkt)->deadline, flush_time + 42 + operation_timeout_ns);

    mcreq_pipeline_remove(pw.pipeline, pw.pkt->opaque);
    mcreq_packet_handled(pw.pipeline, pw.pkt);
    EXPECT_EQ(cookie.ncalled, 1);
}

/*
 * Defence-in-depth: mcreq_reset_timeouts must not abort if an earlier bug
 * (or a buggy caller outside mc/) left a packet with start > deadline.  It
 * must clamp old_timeout to 0 so the packet shows up as an immediate
 * timeout rather than taking the whole process down.
 */
TEST_F(McFlushDeadline, resetTimeoutsClampsBrokenInvariant)
{
    CQWrap cq;
    PacketWrap pw;
    FlushDeadlineCookie cookie;
    cq.setBufFreeCallback(flush_deadline_buf_free_cb);

    prep_packet(cq, pw, cookie, "clamp");
    mcreq_enqueue_packet(pw.pipeline, pw.pkt);

    /* Manually install a broken invariant, as mcreq__pktflush_callback
     * used to produce before this fix. */
    const hrtime_t broken_start = 5000000000ULL;
    const hrtime_t broken_deadline = 1000000000ULL;
    MCREQ_PKT_RDATA(pw.pkt)->start = broken_start;
    MCREQ_PKT_RDATA(pw.pkt)->deadline = broken_deadline;
    ASSERT_GT(broken_start, broken_deadline);

    const hrtime_t now = 10000000000ULL;
    mcreq_reset_timeouts(pw.pipeline, now); /* must not abort() */

    mc_REQDATA *rd = MCREQ_PKT_RDATA(pw.pkt);
    EXPECT_EQ(rd->start, now);
    EXPECT_EQ(rd->deadline, now) << "clamped old_timeout is 0, so deadline == start (immediate timeout)";

    /* Flush and clean up the packet so CQWrap's netbuf_is_clean assertion
     * holds at teardown. */
    nb_IOV iov[4];
    unsigned to_flush = mcreq_flush_iov_fill(pw.pipeline, iov, 4, nullptr);
    mcreq_flush_done(pw.pipeline, to_flush, to_flush);
    mcreq_pipeline_remove(pw.pipeline, pw.pkt->opaque);
    mcreq_packet_handled(pw.pipeline, pw.pkt);
}

/*
 * The fix must not change behaviour when LCB_CNTL_RESET_TIMEOUT_ON_WAIT is
 * off: mcreq__pktflush_callback is called with now == 0 and must leave
 * start/deadline untouched.
 */
TEST_F(McFlushDeadline, flushWithoutNowIsInert)
{
    CQWrap cq;
    PacketWrap pw;
    FlushDeadlineCookie cookie;
    cq.setBufFreeCallback(flush_deadline_buf_free_cb);

    prep_packet(cq, pw, cookie, "inert");
    mcreq_enqueue_packet(pw.pipeline, pw.pkt);

    const hrtime_t orig_start = 1000000000ULL;
    const hrtime_t orig_deadline = orig_start + 2500000000ULL; /* 2.5s */
    MCREQ_PKT_RDATA(pw.pkt)->start = orig_start;
    MCREQ_PKT_RDATA(pw.pkt)->deadline = orig_deadline;

    nb_IOV iov[4];
    unsigned to_flush = mcreq_flush_iov_fill(pw.pipeline, iov, 4, nullptr);
    mcreq_flush_done_ex(pw.pipeline, to_flush, to_flush, 0 /* now == 0 */);

    mc_REQDATA *rd = MCREQ_PKT_RDATA(pw.pkt);
    EXPECT_EQ(rd->start, orig_start);
    EXPECT_EQ(rd->deadline, orig_deadline);

    mcreq_pipeline_remove(pw.pipeline, pw.pkt->opaque);
    mcreq_packet_handled(pw.pipeline, pw.pkt);
}
