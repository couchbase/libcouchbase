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
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>

class Behavior : public ::testing::Test
{
public:
    virtual void SetUp() {
#ifdef BUILD_PLUGINS
        ASSERT_EQ(LCB_SUCCESS, lcb_create(&instance, NULL));
#else
        /* there no IO plugins, so creating connection isn't supported */
        ASSERT_EQ(LCB_NOT_SUPPORTED, lcb_create(&instance, NULL));
#endif
    }

    virtual void TearDown() {
#ifdef BUILD_PLUGINS
        lcb_destroy(instance);
#endif
    }

protected:
    lcb_t instance;

};

#ifdef BUILD_PLUGINS
TEST_F(Behavior, CheckDefaultValues)
{
    EXPECT_EQ(LCB_ASYNCHRONOUS, lcb_behavior_get_syncmode(instance));
    EXPECT_EQ(LCB_IPV6_DISABLED, lcb_behavior_get_ipv6(instance));
    return;
}

TEST_F(Behavior, CheckSyncmode)
{
    lcb_behavior_set_syncmode(instance, LCB_SYNCHRONOUS);
    EXPECT_EQ(LCB_SYNCHRONOUS, lcb_behavior_get_syncmode(instance));
    lcb_behavior_set_syncmode(instance, LCB_ASYNCHRONOUS);
    EXPECT_EQ(LCB_ASYNCHRONOUS, lcb_behavior_get_syncmode(instance));
}

TEST_F(Behavior, CheckIPv6)
{
    lcb_behavior_set_ipv6(instance, LCB_IPV6_ONLY);
    EXPECT_EQ(LCB_IPV6_ONLY, lcb_behavior_get_ipv6(instance));

    lcb_behavior_set_ipv6(instance, LCB_IPV6_ALLOW);
    EXPECT_EQ(LCB_IPV6_ALLOW, lcb_behavior_get_ipv6(instance));

    lcb_behavior_set_ipv6(instance, LCB_IPV6_DISABLED);
    EXPECT_EQ(LCB_IPV6_DISABLED, lcb_behavior_get_ipv6(instance));
}
#endif
