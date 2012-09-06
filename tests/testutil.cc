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

#include "mock-unit-test.h"
/*
 * Helper functions
 */
extern "C" {
    static void storeKeyCallback(lcb_t, const void *cookie,
                                 lcb_storage_t operation,
                                 lcb_error_t error,
                                 const lcb_store_resp_t *)
    {
        int *counter = (int*)cookie;
        ASSERT_EQ(LCB_SET, operation);
        ASSERT_EQ(LCB_SUCCESS, error);
        ++(*counter);
    }

    static void removeKeyCallback(lcb_t, const void *cookie,
                                  lcb_error_t error,
                                  const lcb_remove_resp_t *)
    {
        int *counter = (int*)cookie;
        ASSERT_TRUE(error == LCB_SUCCESS || error == LCB_KEY_ENOENT);
        ++(*counter);
    }

    static void getKeyCallback(lcb_t, const void *cookie,
                               lcb_error_t error,
                               const lcb_get_resp_t *resp)
    {
        Item *item = (Item*)cookie;
        ASSERT_EQ(LCB_SUCCESS, error);
        item->assign(resp);
    }
}

void storeKey(lcb_t instance, const std::string &key, const std::string &value)
{
    int counter = 0;
    lcb_store_cmd_t cmd(LCB_SET, key.data(), key.length(),
                        value.data(), value.length());
    lcb_store_cmd_t* cmds[] = { &cmd };
    lcb_store_callback cb = lcb_set_store_callback(instance, storeKeyCallback);
    EXPECT_EQ(LCB_SUCCESS, lcb_store(instance, &counter, 1, cmds));
    lcb_wait(instance);
    (void)lcb_set_store_callback(instance, cb);
    ASSERT_EQ(1, counter);
}

void removeKey(lcb_t instance, const std::string &key)
{
    int counter = 0;
    lcb_remove_cmd_t cmd(key.data(), key.length());
    lcb_remove_cmd_t* cmds[] = { &cmd };
    lcb_remove_callback cb = lcb_set_remove_callback(instance,
                                                     removeKeyCallback);
    EXPECT_EQ(LCB_SUCCESS, lcb_remove(instance, &counter, 1, cmds));
    lcb_wait(instance);
    (void)lcb_set_remove_callback(instance, cb);
    ASSERT_EQ(1, counter);
}

void getKey(lcb_t instance, const std::string &key, Item &item)
{
    item.cas = 0xdeadbeef;

    lcb_get_cmd_t cmd(key.data(), key.length());
    lcb_get_cmd_t* cmds[] = { &cmd };
    lcb_get_callback cb = lcb_set_get_callback(instance, getKeyCallback);
    EXPECT_EQ(LCB_SUCCESS, lcb_get(instance, &item, 1, cmds));
    lcb_wait(instance);
    (void)lcb_set_get_callback(instance, cb);
    ASSERT_NE(0xdeadbeef, item.cas);
}
