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
#include <map>
#include "iotests.h"

class LockUnitTest : public MockUnitTest
{
};

extern "C" {
    static void getLockedCallback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPGET *resp)
    {
        Item *itm = (Item *)resp->cookie;
        itm->assign(resp);
    }

    static void unlockCallback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPUNLOCK *resp)
    {
        *(lcb_error_t *)resp->cookie = resp->rc;
    }
}

/**
 * @test
 * Lock (lock and unlock)
 *
 * @pre
 * Set a key, and get the value specifying the lock option with a timeout
 * of @c 10.
 *
 * @post
 * Lock operation succeeds.
 *
 * @pre Unlock the key using the CAS from the previous get result.
 * @post Unlock succeeds
 */
TEST_F(LockUnitTest, testSimpleLockAndUnlock)
{
    LCB_TEST_REQUIRE_FEATURE("lock")

    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);

    std::string key = "lockKey";
    std::string value = "lockValue";

    removeKey(instance, key);
    storeKey(instance, key, value);

    lcb_CMDGET cmd = {0};
    LCB_KREQ_SIMPLE(&cmd.key, key.c_str(), key.size());
    cmd.lock = 1;
    cmd.exptime = 10;
    Item itm;

    lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)getLockedCallback);

    ASSERT_EQ(LCB_SUCCESS, lcb_get3(instance, &itm, &cmd));
    lcb_wait(instance);
    ASSERT_EQ(LCB_SUCCESS, itm.err);

    lcb_CMDUNLOCK ucmd = {0};
    LCB_KREQ_SIMPLE(&ucmd.key, key.c_str(), key.size());
    ucmd.cas = itm.cas;

    lcb_error_t reserr = LCB_ERROR;
    lcb_install_callback3(instance, LCB_CALLBACK_UNLOCK, (lcb_RESPCALLBACK)unlockCallback);
    ASSERT_EQ(LCB_SUCCESS, lcb_unlock3(instance, &reserr, &ucmd));
    lcb_wait(instance);
    ASSERT_EQ(LCB_SUCCESS, reserr);
}

/**
 * @test Lock (Missing CAS)
 *
 * @pre
 * Store a key and attempt to unlock it with an invalid CAS
 *
 * @post
 * Error result of @c ETMPFAIL
 */
TEST_F(LockUnitTest, testUnlockMissingCas)
{
    LCB_TEST_REQUIRE_FEATURE("lock")

    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);

    lcb_error_t reserr = LCB_ERROR;
    std::string key = "lockKey2";
    std::string value = "lockValue";

    storeKey(instance, key, value);

    lcb_CMDUNLOCK cmd = {0};
    LCB_KREQ_SIMPLE(&cmd.key, key.c_str(), key.size());
    cmd.cas = 0;

    lcb_install_callback3(instance, LCB_CALLBACK_UNLOCK, (lcb_RESPCALLBACK)unlockCallback);

    ASSERT_EQ(LCB_SUCCESS, lcb_unlock3(instance, &reserr, &cmd));
    lcb_wait(instance);
    if (CLUSTER_VERSION_IS_HIGHER_THAN(MockEnvironment::VERSION_50)) {
        ASSERT_EQ(LCB_EINVAL_MCD, reserr);
    } else {
        ASSERT_EQ(LCB_ETMPFAIL, reserr);
    }
}

extern "C" {
    static void lockedStorageCallback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPSTORE *resp)
    {
        Item *itm = (Item *)resp->cookie;
        itm->assignKC<lcb_RESPSTORE>(resp);
    }
}
/**
 * @test Lock (Storage Contention)
 *
 * @pre
 * Store a key, perform a GET operation with the lock option, specifying a
 * timeout of @c 10.
 *
 * Then attempt to store the key (without specifying any CAS).
 *
 * @post Store operation fails with @c KEY_EEXISTS. Getting the key retains
 * the old value.
 *
 * @pre store the key using the CAS specified from the first GET
 * @post Storage succeeds. Get returns new value.
 */
TEST_F(LockUnitTest, testStorageLockContention)
{
    LCB_TEST_REQUIRE_FEATURE("lock")

    lcb_t instance;
    HandleWrap hw;
    lcb_error_t err;

    createConnection(hw, instance);
    Item itm;
    std::string key = "lockedKey", value = "lockedValue",
                newvalue = "newUnlockedValue";

    /* undo any funny business on our key */
    removeKey(instance, key);
    storeKey(instance, key, value);

    lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)getLockedCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_UNLOCK, (lcb_RESPCALLBACK)unlockCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)lockedStorageCallback);

    /* get the key and lock it */
    lcb_CMDGET gcmd = {0};
    LCB_KREQ_SIMPLE(&gcmd.key, key.c_str(), key.size());
    gcmd.lock = 1;
    gcmd.exptime = 10;
    ASSERT_EQ(LCB_SUCCESS, lcb_get3(instance, &itm, &gcmd));
    lcb_wait(instance);
    ASSERT_EQ(LCB_SUCCESS, itm.err);
    ASSERT_GT(itm.cas, 0);

    /* now try to set the key, while the lock is still in place */
    lcb_CMDSTORE scmd = {0};
    LCB_KREQ_SIMPLE(&scmd.key, key.c_str(), key.size());
    LCB_CMD_SET_VALUE(&scmd, newvalue.c_str(), newvalue.size());
    scmd.operation = LCB_SET;
    Item s_itm;
    ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, &s_itm, &scmd));
    lcb_wait(instance);
    ASSERT_EQ(LCB_KEY_EEXISTS, s_itm.err);

    /* verify the value is still the old value */
    Item ritem;
    getKey(instance, key, ritem);
    ASSERT_EQ(ritem.val, value);

    /* now try to set it with the correct cas, implicitly unlocking the key */
    scmd.cas = itm.cas;
    ASSERT_EQ(LCB_SUCCESS, lcb_store3(instance, &s_itm, &scmd));
    lcb_wait(instance);
    ASSERT_EQ(LCB_SUCCESS, itm.err);

    /* verify the value is now the new value */
    getKey(instance, key, ritem);
    ASSERT_EQ(ritem.val, newvalue);
}

/**
 * @test
 * Lock (Unlocking)
 *
 * @pre
 * Store a key, get it with the lock option, specifying an expiry of @c 10.
 * Try to unlock the key (using the @c lcb_unlock function) without a valid
 * CAS.
 *
 * @post Unlock fails with @c ETMPFAIL
 *
 * @pre
 * Unlock the key using the valid cas retrieved from the first lock operation.
 * Then try to store the key with a new value.
 *
 * @post Unlock succeeds and retrieval of key yields new value.
 */
TEST_F(LockUnitTest, testUnlLockContention)
{
    LCB_TEST_REQUIRE_FEATURE("lock")

    lcb_t instance;
    HandleWrap hw;
    lcb_error_t err, reserr = LCB_ERROR;
    createConnection(hw, instance);

    std::string key = "lockedKey2", value = "lockedValue2";
    storeKey(instance, key, value);
    Item gitm;

    lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)getLockedCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_UNLOCK, (lcb_RESPCALLBACK)unlockCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)lockedStorageCallback);

    lcb_CMDGET gcmd = {0};
    LCB_KREQ_SIMPLE(&gcmd.key, key.c_str(), key.size());
    gcmd.lock = 1;
    gcmd.exptime = 10;

    ASSERT_EQ(LCB_SUCCESS, lcb_get3(instance, &gitm, &gcmd));
    lcb_wait(instance);
    ASSERT_EQ(LCB_SUCCESS, gitm.err);

    lcb_cas_t validCas = gitm.cas;
    ASSERT_EQ(LCB_SUCCESS, lcb_get3(instance, &gitm, &gcmd));
    lcb_wait(instance);
    ASSERT_EQ(LCB_ETMPFAIL, gitm.err);

    lcb_CMDUNLOCK ucmd = {0};
    LCB_KREQ_SIMPLE(&ucmd.key, key.c_str(), key.size());
    ucmd.cas = validCas;

    ASSERT_EQ(LCB_SUCCESS, lcb_unlock3(instance, &reserr, &ucmd));
    lcb_wait(instance);
    ASSERT_EQ(reserr, LCB_SUCCESS);

    std::string newval = "lockedValueNew2";
    storeKey(instance, key, newval);
    getKey(instance, key, gitm);
    ASSERT_EQ(gitm.val, newval);
}
