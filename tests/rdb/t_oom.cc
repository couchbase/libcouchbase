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
#include "rdbtest.h"
#include <rdb/bigalloc.h>

/* LCB_TEST_WRAP_ALLOC is defined only when the linker redirects the allocator
 * through --wrap, which reaches the calls compiled into this binary and leaves
 * the loader and the C library on the real one. Interposing malloc by defining
 * it here instead would also catch the allocations made before main(), while
 * the interposer has no way to reach the real allocator yet. */
#if defined(LCB_TEST_WRAP_ALLOC)

extern "C" {
void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *ptr, size_t size);
}

namespace
{
/* Off except inside FailingAllocations below, so nothing else in this binary
 * -- the test framework included -- sees a refused allocation. */
bool refuse_allocations = false;

struct FailingAllocations {
    FailingAllocations()
    {
        refuse_allocations = true;
    }
    ~FailingAllocations()
    {
        refuse_allocations = false;
    }
};
} // namespace

extern "C" {
void *__wrap_malloc(size_t size)
{
    return refuse_allocations ? nullptr : __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
    return refuse_allocations ? nullptr : __real_calloc(count, size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    return refuse_allocations ? nullptr : __real_realloc(ptr, size);
}
}

class RdbOomTest : public ::testing::Test
{
};

/**
 * A segment whose root could not be allocated must not reach the caller. It
 * used to, and because RDB_SEG_RBUF() is root plus start it read back as a
 * small non-null address inside the first page rather than as a failure.
 */
TEST_F(RdbOomTest, segmentAllocationRefused)
{
    rdb_ALLOCATOR *allocators[] = {rdb_bigalloc_new(), rdb_chunkalloc_new(8192)};
    for (auto *alloc : allocators) {
        rdb_ROPESEG *seg;
        {
            FailingAllocations refusing;
            seg = alloc->s_alloc(alloc, 4096);
        }
        EXPECT_EQ(nullptr, seg);
        alloc->a_release(alloc);
    }
}

/**
 * With no buffer to read into, rdb_rdstart() must report that it has no space
 * rather than hand out a segment it did not get, and the rope must be left
 * usable once allocation succeeds again.
 */
TEST_F(RdbOomTest, readStartWithoutABuffer)
{
    IORope rope(rdb_bigalloc_new());
    nb_IOV iov[4];

    unsigned niov;
    {
        FailingAllocations refusing;
        niov = rdb_rdstart(&rope, iov, 4);
    }
    ASSERT_EQ(0U, niov);

    niov = rdb_rdstart(&rope, iov, 4);
    ASSERT_GT(niov, 0U);
    ASSERT_NE(nullptr, iov[0].iov_base);
    ASSERT_GT(iov[0].iov_len, 0U);

    memset(iov[0].iov_base, 'x', iov[0].iov_len);
    rdb_rdend(&rope, iov[0].iov_len);
    ASSERT_EQ(iov[0].iov_len, rope.usedSize());
    rdb_consumed(&rope, iov[0].iov_len);
}

/**
 * The allocator itself is an allocation. A socket whose allocator could not be
 * created has no way to obtain a read buffer, now or later.
 */
TEST_F(RdbOomTest, allocatorFactoryRefused)
{
    rdb_ALLOCATOR *big;
    rdb_ALLOCATOR *chunked;
    {
        FailingAllocations refusing;
        big = rdb_bigalloc_new();
        chunked = rdb_chunkalloc_new(8192);
    }
    ASSERT_EQ(nullptr, big);
    ASSERT_EQ(nullptr, chunked);
}

/**
 * A rope built from a refused factory reports no space rather than reaching
 * through the allocator it does not have, and tears down without faulting.
 */
TEST_F(RdbOomTest, ropeWithoutAnAllocatorReadsNothing)
{
    rdb_IOROPE ior;
    nb_IOV iov[4];

    rdb_init(&ior, nullptr);
    ASSERT_EQ(0U, rdb_rdstart(&ior, iov, 4));
    rdb_cleanup(&ior);
}

/**
 * Gathering bytes that span several segments needs a segment to gather into.
 * When that cannot be allocated the rope keeps the bytes where they were, and
 * the first segment holds fewer than were asked for. Returning it would hand
 * the caller a short buffer to read a long body out of.
 */
TEST_F(RdbOomTest, consolidationRefusedReturnsNothing)
{
    IORope rope(rdb_chunkalloc_new(4));
    const char payload[] = "0123456789abcdef";
    const unsigned wanted = sizeof(payload) - 1;

    rdb_copywrite(&rope, const_cast<char *>(payload), wanted);
    ASSERT_EQ(wanted, rope.usedSize());

    char *consolidated;
    {
        FailingAllocations refusing;
        consolidated = rdb_get_consolidated(&rope, wanted);
    }
    ASSERT_EQ(nullptr, consolidated);

    /* The bytes are still there, and readable once allocation succeeds. */
    consolidated = rdb_get_consolidated(&rope, wanted);
    ASSERT_NE(nullptr, consolidated);
    ASSERT_EQ(0, memcmp(consolidated, payload, wanted));
    rdb_consumed(&rope, wanted);
}
#endif
