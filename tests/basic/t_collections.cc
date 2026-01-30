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

#include "config.h"
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#define LIBCOUCHBASE_INTERNAL 1
#include "internal.h"
#include "collections.h"

class CollectionCacheTest : public ::testing::Test
{
};

TEST_F(CollectionCacheTest, defaultCollectionIsPrepopulated)
{
    lcb::CollectionCache cache;
    const std::string &name = cache.id_to_name(0);
    EXPECT_EQ("_default._default", name);
}

TEST_F(CollectionCacheTest, unknownIdReturnsEmptyString)
{
    lcb::CollectionCache cache;
    const std::string &name = cache.id_to_name(0xdeadbeef);
    EXPECT_TRUE(name.empty());
}

TEST_F(CollectionCacheTest, idToNameReturnsStableReferenceForSameId)
{
    lcb::CollectionCache cache;
    cache.put("myscope.mycollection", 42);

    const std::string &first = cache.id_to_name(42);
    const std::string &second = cache.id_to_name(42);

    EXPECT_EQ(&first, &second);
    EXPECT_EQ("myscope.mycollection", first);
}

TEST_F(CollectionCacheTest, emptyStringSentinelIsStableAcrossMisses)
{
    lcb::CollectionCache cache;
    const std::string &first_miss = cache.id_to_name(1000);
    const std::string &second_miss = cache.id_to_name(2000);

    EXPECT_TRUE(first_miss.empty());
    EXPECT_TRUE(second_miss.empty());
    EXPECT_EQ(&first_miss, &second_miss);
}

TEST_F(CollectionCacheTest, putOfUnrelatedIdDoesNotInvalidateExistingReference)
{
    lcb::CollectionCache cache;
    cache.put("scope_a.coll_a", 10);
    const std::string &ref_a = cache.id_to_name(10);
    const std::string *addr_before = &ref_a;

    cache.put("scope_b.coll_b", 20);
    cache.put("scope_c.coll_c", 30);

    const std::string &ref_a_after = cache.id_to_name(10);
    EXPECT_EQ(addr_before, &ref_a_after);
    EXPECT_EQ("scope_a.coll_a", ref_a_after);
}

TEST_F(CollectionCacheTest, putOverwritingSameIdUpdatesValueVisibleThroughReference)
{
    lcb::CollectionCache cache;
    cache.put("old.path", 7);
    const std::string &ref = cache.id_to_name(7);
    EXPECT_EQ("old.path", ref);

    cache.put("new.path", 7);
    const std::string &ref_after = cache.id_to_name(7);
    EXPECT_EQ("new.path", ref_after);
}

TEST_F(CollectionCacheTest, eraseMakesIdToNameReturnEmptySentinel)
{
    lcb::CollectionCache cache;
    cache.put("scope.coll", 99);
    EXPECT_EQ("scope.coll", cache.id_to_name(99));

    cache.erase(99);

    const std::string &after_erase = cache.id_to_name(99);
    const std::string &other_miss = cache.id_to_name(0xaaaa);
    EXPECT_TRUE(after_erase.empty());
    EXPECT_EQ(&after_erase, &other_miss);
}

TEST_F(CollectionCacheTest, putIsReflectedInGet)
{
    lcb::CollectionCache cache;
    cache.put("s.c", 5);

    uint32_t cid = 0;
    ASSERT_TRUE(cache.get("s.c", &cid));
    EXPECT_EQ(5u, cid);

    EXPECT_EQ("s.c", cache.id_to_name(5));
}

TEST_F(CollectionCacheTest, getReturnsFalseForUnknownPath)
{
    lcb::CollectionCache cache;
    uint32_t cid = 0xffffffff;
    EXPECT_FALSE(cache.get("no.such.path", &cid));
}

TEST_F(CollectionCacheTest, eraseRemovesBothForwardAndReverseMappings)
{
    lcb::CollectionCache cache;
    cache.put("scope.coll", 77);
    cache.erase(77);

    uint32_t cid = 0xffffffff;
    EXPECT_FALSE(cache.get("scope.coll", &cid));
    EXPECT_TRUE(cache.id_to_name(77).empty());
}
