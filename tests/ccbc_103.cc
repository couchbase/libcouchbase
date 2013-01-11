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

#define EVENT_LISTS_UNIT_TESTS 1
#include "plugins/io/win32/event_lists.h"

class CCBC_103 : public ::testing::Test
{
};

TEST_F(CCBC_103, events)
{
    winsock_io_cookie instance;
    winsock_event e1, e2, e3, e4;

    link_event(&instance, &e1);
    ASSERT_EQ(&e1, instance.events);

    link_event(&instance, &e2);
    ASSERT_EQ(&e2, instance.events);

    link_event(&instance, &e3);
    ASSERT_EQ(&e3, instance.events);

    link_event(&instance, &e4);
    ASSERT_EQ(&e4, instance.events);

    ASSERT_EQ(1, event_contains(&instance, &e1));
    ASSERT_EQ(1, event_contains(&instance, &e2));
    ASSERT_EQ(1, event_contains(&instance, &e3));
    ASSERT_EQ(1, event_contains(&instance, &e4));

    // Try to unlink the one in the middle
    unlink_event(&instance, &e2);
    ASSERT_EQ(1, event_contains(&instance, &e1));
    ASSERT_EQ(0, event_contains(&instance, &e2));
    ASSERT_EQ(1, event_contains(&instance, &e3));
    ASSERT_EQ(1, event_contains(&instance, &e4));

    // Try to unlink the last one
    unlink_event(&instance, &e1);
    ASSERT_EQ(0, event_contains(&instance, &e1));
    ASSERT_EQ(0, event_contains(&instance, &e2));
    ASSERT_EQ(1, event_contains(&instance, &e3));
    ASSERT_EQ(1, event_contains(&instance, &e4));

    // try to unlink the current head
    unlink_event(&instance, &e4);
    ASSERT_EQ(0, event_contains(&instance, &e1));
    ASSERT_EQ(0, event_contains(&instance, &e2));
    ASSERT_EQ(1, event_contains(&instance, &e3));
    ASSERT_EQ(0, event_contains(&instance, &e4));

    // try to unlink the last one
    unlink_event(&instance, &e3);
    ASSERT_EQ(0, event_contains(&instance, &e1));
    ASSERT_EQ(0, event_contains(&instance, &e2));
    ASSERT_EQ(0, event_contains(&instance, &e3));
    ASSERT_EQ(0, event_contains(&instance, &e4));

    // And we should be able to add all back
    link_event(&instance, &e1);
    link_event(&instance, &e2);
    link_event(&instance, &e3);
    link_event(&instance, &e4);
    ASSERT_EQ(1, event_contains(&instance, &e1));
    ASSERT_EQ(1, event_contains(&instance, &e2));
    ASSERT_EQ(1, event_contains(&instance, &e3));
    ASSERT_EQ(1, event_contains(&instance, &e4));
}

TEST_F(CCBC_103, timers)
{
    winsock_io_cookie instance;
    winsock_timer e1, e2, e3, e4;

    link_timer(&instance, &e1);
    ASSERT_EQ(&e1, instance.timers);

    link_timer(&instance, &e2);
    ASSERT_EQ(&e2, instance.timers);

    link_timer(&instance, &e3);
    ASSERT_EQ(&e3, instance.timers);

    link_timer(&instance, &e4);
    ASSERT_EQ(&e4, instance.timers);

    ASSERT_EQ(1, timer_contains(&instance, &e1));
    ASSERT_EQ(1, timer_contains(&instance, &e2));
    ASSERT_EQ(1, timer_contains(&instance, &e3));
    ASSERT_EQ(1, timer_contains(&instance, &e4));

    // Try to unlink the one in the middle
    unlink_timer(&instance, &e2);
    ASSERT_EQ(1, timer_contains(&instance, &e1));
    ASSERT_EQ(0, timer_contains(&instance, &e2));
    ASSERT_EQ(1, timer_contains(&instance, &e3));
    ASSERT_EQ(1, timer_contains(&instance, &e4));

    // Try to unlink the last one
    unlink_timer(&instance, &e1);
    ASSERT_EQ(0, timer_contains(&instance, &e1));
    ASSERT_EQ(0, timer_contains(&instance, &e2));
    ASSERT_EQ(1, timer_contains(&instance, &e3));
    ASSERT_EQ(1, timer_contains(&instance, &e4));

    // try to unlink the current head
    unlink_timer(&instance, &e4);
    ASSERT_EQ(0, timer_contains(&instance, &e1));
    ASSERT_EQ(0, timer_contains(&instance, &e2));
    ASSERT_EQ(1, timer_contains(&instance, &e3));
    ASSERT_EQ(0, timer_contains(&instance, &e4));

    // try to unlink the last one
    unlink_timer(&instance, &e3);
    ASSERT_EQ(0, timer_contains(&instance, &e1));
    ASSERT_EQ(0, timer_contains(&instance, &e2));
    ASSERT_EQ(0, timer_contains(&instance, &e3));
    ASSERT_EQ(0, timer_contains(&instance, &e4));

    // And we should be able to add all back
    link_timer(&instance, &e1);
    link_timer(&instance, &e2);
    link_timer(&instance, &e3);
    link_timer(&instance, &e4);
    ASSERT_EQ(1, timer_contains(&instance, &e1));
    ASSERT_EQ(1, timer_contains(&instance, &e2));
    ASSERT_EQ(1, timer_contains(&instance, &e3));
    ASSERT_EQ(1, timer_contains(&instance, &e4));
}
