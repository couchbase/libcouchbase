/** for ntohl/htonl */
#ifndef _WIN32
#include <netinet/in.h>
#else
#include "winsock2.h"
#endif

#include <libcouchbase/couchbase.h>
#include "config.h"
#include <gtest/gtest.h>
#include "packetutils.h"

class Packet : public ::testing::Test
{
};

class Pkt
{
  public:
    Pkt() : pkt(nullptr), len(0) {}

    void getq(const std::string &value, lcb_uint32_t opaque, lcb_uint16_t status = 0, uint64_t cas = 0,
              lcb_uint32_t flags = 0)
    {
        protocol_binary_response_getq msg;
        protocol_binary_response_header *hdr = &msg.message.header;
        memset(&msg, 0, sizeof(msg));

        hdr->response.magic = PROTOCOL_BINARY_RES;
        hdr->response.opaque = opaque;
        hdr->response.status = htons(status);
        hdr->response.opcode = PROTOCOL_BINARY_CMD_GETQ;
        hdr->response.cas = lcb_htonll(cas);
        hdr->response.bodylen = htonl((lcb_uint32_t)value.size() + 4);
        hdr->response.extlen = 4;
        msg.message.body.flags = htonl(flags);

        // Pack the response
        clear();
        len = sizeof(msg.bytes) + value.size();
        pkt = new char[len];

        EXPECT_TRUE(pkt != nullptr);

        memcpy(pkt, msg.bytes, sizeof(msg.bytes));

        memcpy((char *)pkt + sizeof(msg.bytes), value.c_str(), (unsigned long)value.size());
    }

    void get(const std::string &key, const std::string &value, lcb_uint32_t opaque, lcb_uint16_t status = 0,
             uint64_t cas = 0, lcb_uint32_t flags = 0)
    {
        protocol_binary_response_getq msg;
        protocol_binary_response_header *hdr = &msg.message.header;
        hdr->response.magic = PROTOCOL_BINARY_RES;
        hdr->response.opaque = opaque;
        hdr->response.cas = lcb_htonll(cas);
        hdr->response.opcode = PROTOCOL_BINARY_CMD_GET;
        hdr->response.keylen = htons((lcb_uint16_t)key.size());
        hdr->response.extlen = 4;
        hdr->response.bodylen = htonl(key.size() + value.size() + 4);
        hdr->response.status = htons(status);
        msg.message.body.flags = flags;

        clear();
        len = sizeof(msg.bytes) + value.size() + key.size();
        pkt = new char[len];
        char *ptr = pkt;

        memcpy(ptr, msg.bytes, sizeof(msg.bytes));
        ptr += sizeof(msg.bytes);
        memcpy(ptr, key.c_str(), (unsigned long)key.size());
        ptr += key.size();
        memcpy(ptr, value.c_str(), (unsigned long)value.size());
    }

    void rbWrite(rdb_IOROPE *ior)
    {
        rdb_copywrite(ior, pkt, len);
    }

    void rbWriteHeader(rdb_IOROPE *ior)
    {
        rdb_copywrite(ior, pkt, 24);
    }

    void rbWriteBody(rdb_IOROPE *ior)
    {
        rdb_copywrite(ior, pkt + 24, len - 24);
    }

    void writeGenericHeader(unsigned long bodylen, rdb_IOROPE *ior)
    {
        protocol_binary_response_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.response.opcode = 0;
        hdr.response.bodylen = htonl(bodylen);
        rdb_copywrite(ior, hdr.bytes, sizeof(hdr.bytes));
    }

    /**
     * Writes a bare header with arbitrary length fields, as a peer that
     * disagrees with the protocol -- or a desynchronised stream -- produces.
     * PROTOCOL_BINARY_ARES splits the two key-length bytes into a
     * framing-extras length followed by a key length.
     */
    void writeRawHeader(rdb_IOROPE *ior, uint8_t magic, uint8_t keylen, uint8_t ffextlen, uint8_t extlen,
                        uint8_t datatype, uint32_t bodylen)
    {
        protocol_binary_response_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.response.magic = magic;
        hdr.response.opcode = PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG;
        hdr.response.extlen = extlen;
        hdr.response.datatype = datatype;
        hdr.response.bodylen = htonl(bodylen);
        if (magic == PROTOCOL_BINARY_ARES) {
            hdr.bytes[2] = ffextlen;
            hdr.bytes[3] = keylen;
        } else {
            hdr.response.keylen = htons(keylen);
        }
        rdb_copywrite(ior, hdr.bytes, sizeof(hdr.bytes));
    }

    ~Pkt()
    {
        clear();
    }

    void clear()
    {
        delete[] pkt;
        pkt = nullptr;
        len = 0;
    }

    size_t size() const
    {
        return len;
    }

  private:
    char *pkt;
    size_t len;
    Pkt(Pkt &) = delete;
};

TEST_F(Packet, testParseBasic)
{
    std::string value = "foo";
    rdb_IOROPE ior;
    rdb_init(&ior, rdb_libcalloc_new());

    Pkt pkt;
    pkt.getq(value, 0);
    pkt.rbWrite(&ior);

    lcb::MemcachedResponse pi;
    unsigned wanted;
    ASSERT_TRUE(pi.load(&ior, &wanted));

    ASSERT_EQ(0, pi.status());
    ASSERT_EQ(PROTOCOL_BINARY_CMD_GETQ, pi.opcode());
    ASSERT_EQ(0, pi.opaque());
    ASSERT_EQ(7, pi.bodylen());
    ASSERT_EQ(3, pi.vallen());
    ASSERT_EQ(0, pi.keylen());
    ASSERT_EQ(4, pi.extlen());
    ASSERT_EQ(pi.bodylen(), rdb_get_nused(&ior));
    ASSERT_EQ(0, strncmp(value.c_str(), pi.value(), 3));

    pi.release(&ior);
    ASSERT_EQ(0, rdb_get_nused(&ior));
    rdb_cleanup(&ior);
}

TEST_F(Packet, testParsePartial)
{
    rdb_IOROPE ior;
    Pkt pkt;
    rdb_init(&ior, rdb_libcalloc_new());

    std::string value;
    value.insert(0, 1024, '*');

    lcb::MemcachedResponse pi;

    // Test where we're missing just one byte
    pkt.writeGenericHeader(10, &ior);
    unsigned wanted;
    ASSERT_FALSE(pi.load(&ior, &wanted));

    for (int ii = 0; ii < 9; ii++) {
        char c = 'O';
        rdb_copywrite(&ior, &c, 1);
        ASSERT_FALSE(pi.load(&ior, &wanted));
    }
    char tmp = 'O';
    rdb_copywrite(&ior, &tmp, 1);
    ASSERT_TRUE(pi.load(&ior, &wanted));
    pi.release(&ior);
    rdb_cleanup(&ior);
}

TEST_F(Packet, testKeys)
{
    rdb_IOROPE ior;
    rdb_init(&ior, rdb_libcalloc_new());
    std::string key = "a simple key";
    std::string value = "a simple value";
    Pkt pkt;
    pkt.get(key, value, 1000, PROTOCOL_BINARY_RESPONSE_ETMPFAIL, 0xdeadbeef, 50);
    pkt.rbWrite(&ior);

    lcb::MemcachedResponse pi;
    unsigned wanted;
    ASSERT_TRUE(pi.load(&ior, &wanted));

    ASSERT_EQ(key.size(), pi.keylen());
    ASSERT_EQ(0, memcmp(key.c_str(), pi.key(), pi.keylen()));
    ASSERT_EQ(value.size(), pi.vallen());
    ASSERT_EQ(0, memcmp(value.c_str(), pi.value(), pi.vallen()));
    ASSERT_EQ(0xdeadbeef, pi.cas());
    ASSERT_EQ(PROTOCOL_BINARY_RESPONSE_ETMPFAIL, pi.status());
    ASSERT_EQ(PROTOCOL_BINARY_CMD_GET, pi.opcode());
    ASSERT_EQ(4, pi.extlen());
    ASSERT_EQ(4 + key.size() + value.size(), pi.bodylen());
    ASSERT_NE(pi.body<const char *>(), pi.value());
    ASSERT_EQ(4 + key.size(), pi.value() - pi.body<const char *>());

    pi.release(&ior);
    rdb_cleanup(&ior);
}

/*
 * A header declaring no body leaves MemcachedResponse::payload unset. Reading
 * the value of such a packet must not produce a pointer into the first page,
 * and its length must not wrap: config response handlers pass both straight to
 * snappy::Uncompress() and to the std::string constructor.
 */
TEST_F(Packet, testBodylessPacketHasNoValue)
{
    rdb_IOROPE ior;
    rdb_init(&ior, rdb_libcalloc_new());

    Pkt pkt;
    pkt.writeRawHeader(&ior, PROTOCOL_BINARY_RES, 0, 0, 8, 0, 0);

    lcb::MemcachedResponse pi;
    unsigned wanted;
    ASSERT_TRUE(pi.load(&ior, &wanted));

    ASSERT_EQ(0, pi.bodylen());
    ASSERT_EQ(8, pi.extlen());
    ASSERT_EQ(nullptr, pi.value());
    ASSERT_EQ(0, pi.vallen());

    pi.release(&ior);
    rdb_cleanup(&ior);
}

TEST_F(Packet, testBodylessFlexibleFramingPacketHasNoValue)
{
    rdb_IOROPE ior;
    rdb_init(&ior, rdb_libcalloc_new());

    Pkt pkt;
    pkt.writeRawHeader(&ior, PROTOCOL_BINARY_ARES, 0, 8, 0, 0, 0);

    lcb::MemcachedResponse pi;
    unsigned wanted;
    ASSERT_TRUE(pi.load(&ior, &wanted));

    ASSERT_EQ(0, pi.keylen());
    ASSERT_EQ(8, pi.ffextlen());
    ASSERT_EQ(nullptr, pi.value());
    ASSERT_EQ(0, pi.vallen());

    pi.release(&ior);
    rdb_cleanup(&ior);
}

/*
 * A read buffer that could not be allocated leaves payload null while the
 * header still declares a body. value() and vallen() are read as a pair -- the
 * caller reads vallen() bytes from value() -- so the count must follow the
 * pointer to zero. snappy::Uncompress(nullptr, n) with n > 0 dereferences on
 * its first byte.
 */
/* payload is protected, so the state load() leaves behind when the read buffer
 * could not be allocated -- a header declaring a body, with nothing read into
 * it -- can only be installed from a derived class. */
struct UnallocatedResponse : lcb::MemcachedResponse {
    UnallocatedResponse(uint8_t extlen, uint32_t bodylen, uint8_t datatype = 0)
    {
        res.response.magic = PROTOCOL_BINARY_RES;
        res.response.opcode = PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG;
        res.response.extlen = extlen;
        res.response.datatype = datatype;
        res.response.bodylen = htonl(bodylen);
        payload = nullptr;
    }
};

TEST_F(Packet, testUnallocatedPayloadHasNoValueLength)
{
    UnallocatedResponse pi(4, 64);

    ASSERT_EQ(64, pi.bodylen());
    ASSERT_EQ(nullptr, pi.value());
    ASSERT_EQ(0, pi.vallen());
}

/*
 * The pair matters more than either half: inflated_value() hands value() and
 * vallen() straight to snappy, and snappy::Uncompress(nullptr, n) with n > 0
 * dereferences on its first byte.
 */
TEST_F(Packet, testUnallocatedPayloadInflatesToNothing)
{
    UnallocatedResponse pi(4, 64, PROTOCOL_BINARY_DATATYPE_COMPRESSED);

    ASSERT_EQ(nullptr, pi.value());
    ASSERT_EQ(0, pi.vallen());
    ASSERT_TRUE(pi.inflated_value().empty());
}

/*
 * Length fields that overrun the body are the same hazard without a null
 * payload: the subtraction is unsigned, so vallen() must clamp rather than
 * report a value the caller would then read.
 */
TEST_F(Packet, testLengthFieldsOverrunningBodyHaveNoValue)
{
    rdb_IOROPE ior;
    rdb_init(&ior, rdb_libcalloc_new());

    Pkt pkt;
    pkt.writeRawHeader(&ior, PROTOCOL_BINARY_RES, 0, 0, 8, 0, 4);
    char body[4] = {0};
    rdb_copywrite(&ior, body, sizeof(body));

    lcb::MemcachedResponse pi;
    unsigned wanted;
    ASSERT_TRUE(pi.load(&ior, &wanted));

    ASSERT_EQ(4, pi.bodylen());
    ASSERT_EQ(8, pi.extlen());
    ASSERT_EQ(0, pi.vallen());

    pi.release(&ior);
    rdb_cleanup(&ior);
}

/*
 * The crash site: inflated_value() on a body-less packet whose datatype claims
 * snappy compression handed (value(), vallen()) to the decompressor.
 */
TEST_F(Packet, testInflatedValueOfBodylessPacketIsEmpty)
{
    rdb_IOROPE ior;
    rdb_init(&ior, rdb_libcalloc_new());

    Pkt pkt;
    pkt.writeRawHeader(&ior, PROTOCOL_BINARY_RES, 0, 0, 8, PROTOCOL_BINARY_DATATYPE_COMPRESSED, 0);

    lcb::MemcachedResponse pi;
    unsigned wanted;
    ASSERT_TRUE(pi.load(&ior, &wanted));

    ASSERT_TRUE(pi.inflated_value().empty());

    pi.release(&ior);
    rdb_cleanup(&ior);
}

/**
 * Loads a header with the given length fields and reports whether the packet
 * satisfies the invariant the read path enforces before dispatching it.
 */
static bool lengths_consistent(uint8_t magic, uint8_t keylen, uint8_t ffextlen, uint8_t extlen, uint32_t bodylen)
{
    char body[32] = {0};
    rdb_IOROPE ior;
    rdb_init(&ior, rdb_libcalloc_new());

    Pkt pkt;
    pkt.writeRawHeader(&ior, magic, keylen, ffextlen, extlen, 0, bodylen);
    if (bodylen) {
        rdb_copywrite(&ior, body, bodylen);
    }

    lcb::MemcachedResponse pi;
    unsigned wanted;
    EXPECT_TRUE(pi.load(&ior, &wanted));
    bool consistent = pi.has_consistent_lengths();

    pi.release(&ior);
    rdb_cleanup(&ior);
    return consistent;
}

/*
 * ffext(), ext(), key() and value() each offset into the payload by some
 * combination of the header length fields, so a body that does not cover them
 * puts every one of those accessors out of bounds -- and past NULL when the
 * packet declares no body, since payload is then never assigned.
 */
TEST_F(Packet, testLengthFieldsAreCheckedAgainstTheBody)
{
    /* a body that covers the length fields, exactly or with a value after them */
    ASSERT_TRUE(lengths_consistent(PROTOCOL_BINARY_RES, 0, 0, 0, 0));
    ASSERT_TRUE(lengths_consistent(PROTOCOL_BINARY_RES, 0, 0, 8, 8));
    ASSERT_TRUE(lengths_consistent(PROTOCOL_BINARY_RES, 4, 0, 4, 16));
    ASSERT_TRUE(lengths_consistent(PROTOCOL_BINARY_ARES, 4, 4, 4, 16));

    /* fields that overrun it */
    ASSERT_FALSE(lengths_consistent(PROTOCOL_BINARY_RES, 0, 0, 8, 0));
    ASSERT_FALSE(lengths_consistent(PROTOCOL_BINARY_RES, 8, 0, 0, 0));
    ASSERT_FALSE(lengths_consistent(PROTOCOL_BINARY_ARES, 0, 8, 0, 0));
    ASSERT_FALSE(lengths_consistent(PROTOCOL_BINARY_RES, 0, 0, 8, 4));
}
