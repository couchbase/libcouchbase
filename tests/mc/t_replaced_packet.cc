/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2026-Present Couchbase, Inc.
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
 * Regression tests for commit c5480c4e
 *   "Fix packet replacement and memory management in retry queue"
 *
 * mcreq_set_cid used to free a packet whose bytes were still referenced by
 * the netbuf PDU queue (and, on IOCP, by an in-flight kernel write).  The
 * fix introduced MCREQ_F_REPLACED, which every relevant walker (flush
 * callback, pipeline timeout, queuectx drain) now skips.
 */

#include "mctest.h"
#include "mc/mcreq-flush-inl.h"

class McReplacedPacket : public ::testing::Test
{
};

struct ReplacedCookie {
    int ncalled{0};
    void *exp_kbuf{nullptr};
};

extern "C" {
static void replaced_buf_free_cb(mc_PIPELINE *, const void *cookie, void *kbuf, void *)
{
    auto *ck = (ReplacedCookie *)cookie;
    EXPECT_EQ(ck->exp_kbuf, kbuf);
    ck->ncalled++;
}

static void replaced_fail_cb(mc_PIPELINE *, mc_PACKET *, lcb_STATUS, void *arg)
{
    /* Used only to prove the fail callback is NOT invoked for replaced packets. */
    ++*static_cast<int *>(arg);
}
}

static void prep_packet(CQWrap &cq, PacketWrap &pw, ReplacedCookie &cookie, const char *key)
{
    pw.setContigKey(key);
    ASSERT_TRUE(pw.reservePacket(&cq));
    cookie.exp_kbuf = pw.pktbuf;
    pw.setCookie(&cookie);
    pw.setHeaderSize();
    pw.copyHeader();
}

/*
 * A MCREQ_F_REPLACED packet must be ignored by mcreq__pktflush_callback:
 *   - its start/deadline must not be rewritten even when `now` is passed,
 *   - its bytes must still be consumed so packets behind it can flush,
 *   - MCREQ_F_FLUSHED must be set so the packet is eventually cleanable.
 */
TEST_F(McReplacedPacket, ignoredByFlushCallback)
{
    CQWrap cq;
    PacketWrap pw;
    ReplacedCookie cookie;
    cq.setBufFreeCallback(replaced_buf_free_cb);

    prep_packet(cq, pw, cookie, "replaced");
    mcreq_enqueue_packet(pw.pipeline, pw.pkt);

    const hrtime_t orig_start = 42000000000ULL;
    const hrtime_t orig_deadline = orig_start + 1000000ULL;
    MCREQ_PKT_RDATA(pw.pkt)->start = orig_start;
    MCREQ_PKT_RDATA(pw.pkt)->deadline = orig_deadline;
    pw.pkt->flags |= MCREQ_F_REPLACED;

    nb_IOV iov[4];
    unsigned to_flush = mcreq_flush_iov_fill(pw.pipeline, iov, 4, nullptr);
    ASSERT_GT(to_flush, 0u);

    /* `now` is non-zero, just like on_flush_done would pass when
     * readj_ts_wait is on. */
    mcreq_flush_done_ex(pw.pipeline, to_flush, to_flush, orig_start + 9999);

    EXPECT_NE(0u, pw.pkt->flags & MCREQ_F_FLUSHED) << "replaced packet must be marked flushed so it can be cleaned up";
    EXPECT_EQ(MCREQ_PKT_RDATA(pw.pkt)->start, orig_start)
        << "replaced packet's start must not be rewritten by the flush walker";
    EXPECT_EQ(MCREQ_PKT_RDATA(pw.pkt)->deadline, orig_deadline)
        << "replaced packet's deadline must not be rewritten by the flush walker";

    mcreq_pipeline_remove(pw.pipeline, pw.pkt->opaque);
    mcreq_packet_handled(pw.pipeline, pw.pkt);
}

/*
 * mcreq_pipeline_timeout must silently release a replaced packet: no
 * fail callback, no accounting, no double-retry attempt.
 *
 * Production scenario (mcreq_set_cid flow): the packet has already been
 * fully flushed to the wire when it is marked REPLACED.  We reproduce that
 * here by flushing the packet first, then flipping the flag, then calling
 * pipeline_timeout.
 */
TEST_F(McReplacedPacket, skippedByPipelineTimeout)
{
    CQWrap cq;
    PacketWrap pw;
    ReplacedCookie cookie;
    cq.setBufFreeCallback(replaced_buf_free_cb);

    prep_packet(cq, pw, cookie, "replaced-tmo");
    mcreq_enqueue_packet(pw.pipeline, pw.pkt);

    nb_IOV iov[4];
    unsigned to_flush = mcreq_flush_iov_fill(pw.pipeline, iov, 4, nullptr);
    mcreq_flush_done(pw.pipeline, to_flush, to_flush);
    ASSERT_NE(0u, pw.pkt->flags & MCREQ_F_FLUSHED);

    /* Now flip the packet into the REPLACED state, mimicking what
     * mcreq_set_cid does when it encounters a flushed packet. */
    pw.pkt->flags |= MCREQ_F_REPLACED;

    int failcb_calls = 0;
    unsigned n = mcreq_pipeline_timeout(pw.pipeline, LCB_ERR_TIMEOUT, replaced_fail_cb, &failcb_calls,
                                        /* now = 0 forces every packet to be treated as timed out */ 0);
    /* Replaced packets are freed silently, so they don't count in the
     * timed-out tally. */
    EXPECT_EQ(0u, n);
    EXPECT_EQ(0, failcb_calls) << "failcb must not be called for MCREQ_F_REPLACED packets";

    /* After the timeout path the packet has been wiped+released.  The
     * CQWrap destructor's netbuf_is_clean check will confirm there are no
     * leaks in the request/PDU/send queues. */
}
