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
    char *missing = (char*)"missing";
    char * items[] = {(char*)"zero", (char*)"one",
                      (char*)"two", (char*)"three", NULL};
    char *foo = (char*)"foo";
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
