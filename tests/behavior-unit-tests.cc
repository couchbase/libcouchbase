/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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

class Behavior : public ::testing::Test
{
public:
    virtual void SetUp() {
        instance = libcouchbase_create(NULL, NULL, NULL, NULL, NULL);
    }

    virtual void TearDown() {
        libcouchbase_destroy(instance);
    }

protected:
    libcouchbase_t instance;

};

TEST_F(Behavior, CheckDefaultValues)
{
    EXPECT_EQ(LIBCOUCHBASE_ASYNCHRONOUS,
              libcouchbase_behavior_get_syncmode(instance));
    EXPECT_EQ(LIBCOUCHBASE_IPV6_DISABLED,
              libcouchbase_behavior_get_ipv6(instance));
}

TEST_F(Behavior, CheckSyncmode)
{
    libcouchbase_behavior_set_syncmode(instance, LIBCOUCHBASE_SYNCHRONOUS);
    EXPECT_EQ(LIBCOUCHBASE_SYNCHRONOUS,
              libcouchbase_behavior_get_syncmode(instance));
    libcouchbase_behavior_set_syncmode(instance, LIBCOUCHBASE_ASYNCHRONOUS);
    EXPECT_EQ(LIBCOUCHBASE_ASYNCHRONOUS,
              libcouchbase_behavior_get_syncmode(instance));
}

TEST_F(Behavior, CheckIPv6)
{
    libcouchbase_behavior_set_ipv6(instance, LIBCOUCHBASE_IPV6_ONLY);
    EXPECT_EQ(LIBCOUCHBASE_IPV6_ONLY,
              libcouchbase_behavior_get_ipv6(instance));

    libcouchbase_behavior_set_ipv6(instance, LIBCOUCHBASE_IPV6_ALLOW);
    EXPECT_EQ(LIBCOUCHBASE_IPV6_ALLOW,
              libcouchbase_behavior_get_ipv6(instance));

    libcouchbase_behavior_set_ipv6(instance, LIBCOUCHBASE_IPV6_DISABLED);
    EXPECT_EQ(LIBCOUCHBASE_IPV6_DISABLED,
              libcouchbase_behavior_get_ipv6(instance));
}
