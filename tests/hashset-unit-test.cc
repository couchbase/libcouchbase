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
#include "hashset.h"
#include <gtest/gtest.h>

class Hashset : public ::testing::Test
{
public:
    virtual void SetUp(void) {
        set = hashset_create();
        ASSERT_NE((hashset_t)NULL, set);
    }

    virtual void TearDown(void) {
        hashset_destroy(set);
    }

protected:
    hashset_t set;
};

TEST_F(Hashset, trivial)
{
    char *missing = (char *)"missing";
    char *items[] = {(char *)"zero", (char *)"one",
                     (char *)"two", (char *)"three", NULL
                    };
    char *foo = (char *)"foo";
    size_t ii, nitems = 4;

    for (ii = 0; ii < nitems; ++ii) {
        hashset_add(set, items[ii]);
    }

    for (ii = 0; ii < nitems; ++ii) {
        assert(hashset_is_member(set, items[ii]));
    }

    EXPECT_EQ(0, hashset_is_member(set, missing));
    EXPECT_EQ(1, hashset_remove(set, items[1]));
    EXPECT_EQ(3, hashset_num_items(set));
    EXPECT_EQ(0, hashset_remove(set, items[1]));

    EXPECT_EQ(1, hashset_add(set, foo));
    EXPECT_EQ(0, hashset_add(set, foo));
}

TEST_F(Hashset, testGaps)
{
    /* fill the hashset */
    EXPECT_NE(0, hashset_add(set, (void *)0xbabe));
    EXPECT_NE(0, hashset_add(set, (void *)0xbeef));
    EXPECT_NE(0, hashset_add(set, (void *)0xbad));
    EXPECT_NE(0, hashset_add(set, (void *)0xf00d));
    /* 0xf00d (nil) (nil) (nil) (nil) 0xbad 0xbabe 0xbeef */

    /* make a gap */
    EXPECT_NE(0, hashset_remove(set, (void *)0xbeef));
    /* 0xf00d (nil) (nil) (nil) (nil) 0xbad 0xbabe 0x1 */

    /* check that 0xf00d is still reachable */
    EXPECT_TRUE(hashset_is_member(set, (void *)0xf00d));

    /* add 0xbeef back */
    EXPECT_NE(0, hashset_add(set, (void *)0xbeef));
    /* 0xf00d (nil) (nil) (nil) (nil) 0xbad 0xbabe 0xbeef */

    /* verify */
    EXPECT_TRUE(hashset_is_member(set, (void *)0xbeef));
    EXPECT_TRUE(hashset_is_member(set, (void *)0xf00d));
}

TEST_F(Hashset, testExceptions)
{
    EXPECT_EQ(-1, hashset_add(set, (void *)0));
    EXPECT_EQ(-1, hashset_add(set, (void *)1));
}

TEST_F(Hashset, testRehashingItemsPlacedBeyondNumItems)
{
    EXPECT_TRUE(hashset_add(set, (void *)20644128));
    EXPECT_TRUE(hashset_add(set, (void *)21747760));
    EXPECT_TRUE(hashset_add(set, (void *)17204864));
    EXPECT_TRUE(hashset_add(set, (void *)22937440));
    EXPECT_TRUE(hashset_add(set, (void *)14734272));
    EXPECT_TRUE(hashset_add(set, (void *)13948320));
    EXPECT_TRUE(hashset_add(set, (void *)18116496));
    EXPECT_TRUE(hashset_add(set, (void *)18229952));
    EXPECT_TRUE(hashset_add(set, (void *)20390128));
    EXPECT_TRUE(hashset_add(set, (void *)23523264));
    EXPECT_TRUE(hashset_add(set, (void *)22866784));
    EXPECT_TRUE(hashset_add(set, (void *)17501248));
    EXPECT_TRUE(hashset_add(set, (void *)17168832));
    EXPECT_TRUE(hashset_add(set, (void *)13389824));
    EXPECT_TRUE(hashset_add(set, (void *)15795136));
    EXPECT_TRUE(hashset_add(set, (void *)15154464));
    EXPECT_TRUE(hashset_add(set, (void *)22507840));
    EXPECT_TRUE(hashset_add(set, (void *)22977920));
    EXPECT_TRUE(hashset_add(set, (void *)20527584));
    EXPECT_TRUE(hashset_add(set, (void *)21557872));
    EXPECT_TRUE(hashset_add(set, (void *)23089952));
    EXPECT_TRUE(hashset_add(set, (void *)21606240));
    EXPECT_TRUE(hashset_add(set, (void *)25168704));
    EXPECT_TRUE(hashset_add(set, (void *)25198096));
    EXPECT_TRUE(hashset_add(set, (void *)25248000));
    EXPECT_TRUE(hashset_add(set, (void *)25260976));
    EXPECT_TRUE(hashset_add(set, (void *)25905520));
    EXPECT_TRUE(hashset_add(set, (void *)25934608));
    EXPECT_TRUE(hashset_add(set, (void *)26015264));
    EXPECT_TRUE(hashset_add(set, (void *)26044352));
    EXPECT_TRUE(hashset_add(set, (void *)24784800));
    EXPECT_TRUE(hashset_add(set, (void *)24813888));
    EXPECT_TRUE(hashset_add(set, (void *)24663936));
    EXPECT_TRUE(hashset_add(set, (void *)24693536));
    EXPECT_TRUE(hashset_add(set, (void *)24743792));
    EXPECT_TRUE(hashset_add(set, (void *)24756480));

    EXPECT_TRUE(hashset_is_member(set, (void *)20644128));
    EXPECT_TRUE(hashset_is_member(set, (void *)21747760));
    EXPECT_TRUE(hashset_is_member(set, (void *)17204864));
    EXPECT_TRUE(hashset_is_member(set, (void *)22937440));
    EXPECT_TRUE(hashset_is_member(set, (void *)14734272));
    EXPECT_TRUE(hashset_is_member(set, (void *)13948320));
    EXPECT_TRUE(hashset_is_member(set, (void *)18116496));
    EXPECT_TRUE(hashset_is_member(set, (void *)18229952));
    EXPECT_TRUE(hashset_is_member(set, (void *)20390128));
    EXPECT_TRUE(hashset_is_member(set, (void *)23523264));
    EXPECT_TRUE(hashset_is_member(set, (void *)22866784));
    EXPECT_TRUE(hashset_is_member(set, (void *)17501248));
    EXPECT_TRUE(hashset_is_member(set, (void *)17168832));
    EXPECT_TRUE(hashset_is_member(set, (void *)13389824));
    EXPECT_TRUE(hashset_is_member(set, (void *)15795136));
    EXPECT_TRUE(hashset_is_member(set, (void *)15154464));
    EXPECT_TRUE(hashset_is_member(set, (void *)22507840));
    EXPECT_TRUE(hashset_is_member(set, (void *)22977920));
    EXPECT_TRUE(hashset_is_member(set, (void *)20527584));
    EXPECT_TRUE(hashset_is_member(set, (void *)21557872));
    EXPECT_TRUE(hashset_is_member(set, (void *)23089952));
    EXPECT_TRUE(hashset_is_member(set, (void *)21606240));
    EXPECT_TRUE(hashset_is_member(set, (void *)25168704));
    EXPECT_TRUE(hashset_is_member(set, (void *)25198096));
    EXPECT_TRUE(hashset_is_member(set, (void *)25248000));
    EXPECT_TRUE(hashset_is_member(set, (void *)25260976));
    EXPECT_TRUE(hashset_is_member(set, (void *)25905520));
    EXPECT_TRUE(hashset_is_member(set, (void *)25934608));
    EXPECT_TRUE(hashset_is_member(set, (void *)26015264));
    EXPECT_TRUE(hashset_is_member(set, (void *)26044352));
    EXPECT_TRUE(hashset_is_member(set, (void *)24784800));
    EXPECT_TRUE(hashset_is_member(set, (void *)24813888));
    EXPECT_TRUE(hashset_is_member(set, (void *)24663936));
    EXPECT_TRUE(hashset_is_member(set, (void *)24693536));
    EXPECT_TRUE(hashset_is_member(set, (void *)24743792));
    EXPECT_TRUE(hashset_is_member(set, (void *)24756480));
}
