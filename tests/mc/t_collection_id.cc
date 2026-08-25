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
#include "mctest.h"
#include "mc/mcreq-flush-inl.h"

#include <cstdint>
#include <string>
#include <vector>

class McCollectionId : public ::testing::Test
{
};

namespace
{
/**
 * Enqueues a GET whose key carries the leb128 prefix for the default
 * collection onto a pipeline that has been told the server does not support
 * collections, and returns the header and key the pipeline holds afterwards.
 *
 * mcreq_enqueue_packet() strips the prefix on that path, rewriting keylen and
 * bodylen in a header that sits wherever the pipeline's buffer had room -- so
 * this is also what covers reading and writing it at an offset that is not
 * aligned for its type.
 */
struct Enqueued {
    mc_PIPELINE *pipeline;
    mc_PACKET *pkt;
    std::uintptr_t header_address;
    std::uint16_t keylen;
    std::uint32_t bodylen;
    std::string key;
};

Enqueued enqueue_prefixed_get(CQWrap &cq, const std::string &key)
{
    PacketWrap pw;
    /* The leb128 encoding of collection 0, which is what the pipeline strips. */
    const std::string prefixed = std::string(1, '\0') + key;
    pw.setCopyKey(prefixed.c_str());
    pw.keybuf = {LCB_KV_COPY, {prefixed.data(), prefixed.size()}};
    pw.hdr.request.opcode = PROTOCOL_BINARY_CMD_GET;
    pw.hdr.request.magic = PROTOCOL_BINARY_REQ;
    pw.hdr.request.keylen = htons(static_cast<std::uint16_t>(prefixed.size()));
    pw.hdr.request.bodylen = htonl(static_cast<std::uint32_t>(prefixed.size()));

    EXPECT_TRUE(pw.reservePacket(&cq));
    pw.copyHeader();
    pw.pkt->flags |= MCREQ_F_HASCID;
    pw.pipeline->collections = MCREQ_COLLECTIONS_UNSUPPORTTED;
    mcreq_enqueue_packet(pw.pipeline, pw.pkt);

    const char *buf = SPAN_BUFFER(&pw.pkt->kh_span);
    protocol_binary_request_header out{};
    memcpy(&out, buf, sizeof(out));

    Enqueued result{};
    result.pipeline = pw.pipeline;
    result.pkt = pw.pkt;
    result.header_address = reinterpret_cast<std::uintptr_t>(buf);
    result.keylen = ntohs(out.request.keylen);
    result.bodylen = ntohl(out.request.bodylen);
    result.key.assign(buf + sizeof(out), result.keylen);
    return result;
}
} // namespace

TEST_F(McCollectionId, strippedFromPacketAtAnyHeaderAlignment)
{
    CQWrap cq;

    /* A packet's header and key share one span, and the spans are packed, so
     * the key length decides where the next header starts. Varying it covers
     * an offset that is not aligned for the header's own type as well as one
     * that is. */
    bool saw_unaligned = false;
    std::vector<Enqueued> enqueued;
    for (int ii = 0; ii < 8; ++ii) {
        const std::string key = "collection-id-" + std::string(ii + 1, 'k');
        enqueued.push_back(enqueue_prefixed_get(cq, key));
        saw_unaligned = saw_unaligned || (enqueued.back().header_address % 8) != 0;

        EXPECT_EQ(key.size(), enqueued.back().keylen);
        EXPECT_EQ(key.size(), enqueued.back().bodylen);
        EXPECT_EQ(key, enqueued.back().key);
    }
    EXPECT_TRUE(saw_unaligned) << "every header happened to be aligned, so the case this covers was never reached";

    for (auto &one : enqueued) {
        nb_IOV iov[4];
        unsigned to_flush = mcreq_flush_iov_fill(one.pipeline, iov, 4, nullptr);
        mcreq_flush_done(one.pipeline, to_flush, to_flush);
        mcreq_pipeline_remove(one.pipeline, one.pkt->opaque);
        mcreq_packet_handled(one.pipeline, one.pkt);
    }
}
