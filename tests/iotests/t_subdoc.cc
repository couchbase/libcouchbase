/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc.
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
#include <libcouchbase/couchbase.h>
#include <libcouchbase/api3.h>
#include "iotests.h"
#include <string>

class SubdocUnitTest : public MockUnitTest {
public:
    SubdocUnitTest() {
        key = "subdocItem";
        value = "{"
                    "\"dictkey\":\"dictval\","
                    "\"array\":["
                        "1,2,3,4,[10,20,30,[100,200,300]]"
                        "]"
                "}";

        nonJsonKey = "nonJsonItem";
    }
protected:
    std::string key;
    std::string value;
    std::string nonJsonKey;
    bool createSubdocConnection(HandleWrap& hw, lcb_t& instance);
};

struct Result {
    lcb_error_t rc;
    lcb_CAS cas;
    std::string value;
    Result() {
        clear();
    }
    void clear() {
        rc = LCB_ERROR;
        cas = 0;
        value.clear();
    }
};

struct MultiResult {
    std::vector<Result> results;
    size_t last_errix;
    lcb_CAS cas;
    lcb_error_t rc;

    void clear() {
        last_errix = -1;
        cas = 0;
        results.clear();
    }

    MultiResult() { clear(); }
};

extern "C" {
static void
singleCallback(lcb_t, int cbtype, const lcb_RESPBASE *rb)
{
    Result *res = reinterpret_cast<Result*>(rb->cookie);
    res->rc = rb->rc;
    res->cas = rb->cas;
    if (cbtype == LCB_CALLBACK_GET ||
            cbtype == LCB_CALLBACK_SDGET ||
            cbtype == LCB_CALLBACK_SDCOUNTER) {
        const lcb_RESPGET *rg = reinterpret_cast<const lcb_RESPGET*>(rb);
        if (rg->nvalue) {
            res->value.assign(reinterpret_cast<const char*>(rg->value), rg->nvalue);
        }
    }
}

static void
multiMutateCallback(lcb_t, int, const lcb_RESPBASE *rb)
{
    MultiResult *mr = reinterpret_cast<MultiResult*>(rb->cookie);
    const lcb_RESPSDMMUTATE *resp = reinterpret_cast<const lcb_RESPSDMMUTATE*>(rb);
    mr->rc = rb->rc;

    if (resp->rc != LCB_SUCCESS) {
        mr->last_errix = resp->failed_ix;
    } else {
        mr->cas = resp->cas;
    }
}

static void
multiLookupCallback(lcb_t, int cbtype, const lcb_RESPBASE *rb)
{
    MultiResult *mr = reinterpret_cast<MultiResult*>(rb->cookie);
    const lcb_RESPSDMLOOKUP *resp = reinterpret_cast<const lcb_RESPSDMLOOKUP*>(rb);
    mr->rc = resp->rc;
    if (mr->rc == LCB_SUCCESS || mr->rc == LCB_SUBDOC_MULTI_FAILURE) {
        mr->cas = resp->cas;
        lcb_SDMLOOKUP_RESULT cur_res;
        size_t iterval = 0;
        while (lcb_sdmlookup_next(resp->responses, &cur_res, &iterval)) {
            Result res;
            res.rc = cur_res.status;
            res.value.assign(reinterpret_cast<const char*>(cur_res.value),
                cur_res.nvalue);
            mr->results.push_back(res);
        }
    }
}

}

bool
SubdocUnitTest::createSubdocConnection(HandleWrap& hw, lcb_t& instance)
{
    createConnection(hw, instance);
    lcb_install_callback3(instance, LCB_CALLBACK_SDGET, singleCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_SDSTORE, singleCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_SDCOUNTER, singleCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_SDEXISTS, singleCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_SDREMOVE, singleCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_SDMLOOKUP, multiLookupCallback);
    lcb_install_callback3(instance, LCB_CALLBACK_SDMMUTATE, multiMutateCallback);

    lcb_CMDSDGET cmd = { 0 };
    LCB_CMD_SET_KEY(&cmd, "foo", 3);
    LCB_SDCMD_SET_PATH(&cmd, "pth", 3);

    lcb_sched_enter(instance);
    Result res;
    lcb_error_t rc = lcb_sdget3(instance, &res, &cmd);
    EXPECT_EQ(LCB_SUCCESS, rc);
    if (rc != LCB_SUCCESS) {
        return false;
    }
    lcb_sched_leave(instance);
    lcb_wait(instance);

    if (res.rc == LCB_NOT_SUPPORTED || res.rc == LCB_UNKNOWN_COMMAND) {
        return false;
    }

    storeKey(instance, key, value);
    storeKey(instance, nonJsonKey, "non-json-value");

    return true;
}

#define CREATE_SUBDOC_CONNECTION(hw, instance) \
    do { \
        if (!createSubdocConnection(hw, instance)) { \
            fprintf(stderr, "Subdoc not supported on cluster!\n"); \
            return; \
        } \
    } while (0);

template <typename T> lcb_error_t
schedwait(lcb_t instance, Result *res, const T *cmd,
    lcb_error_t (*fn)(lcb_t, const void *, const T*))
{
    res->clear();
    lcb_sched_enter(instance);
    lcb_error_t rc = fn(instance, res, cmd);
    if (rc == LCB_SUCCESS) {
        lcb_sched_leave(instance);
        lcb_wait(instance);
    } else {
        lcb_sched_fail(instance);
    }
    return rc;
}

static std::string
getPathValue(lcb_t instance, const char *docid, const char *path)
{
    Result res;
    lcb_CMDSDGET gcmd = { 0 };
    LCB_CMD_SET_KEY(&gcmd, docid, strlen(docid));
    LCB_SDCMD_SET_PATH(&gcmd, path, strlen(path));
    EXPECT_EQ(LCB_SUCCESS, schedwait(instance, &res, &gcmd, lcb_sdget3));
    EXPECT_EQ(LCB_SUCCESS, res.rc);
    return res.value;
}

TEST_F(SubdocUnitTest, testSdGetExists)
{
    HandleWrap hw;
    lcb_t instance;
    CREATE_SUBDOC_CONNECTION(hw, instance);

    Result res;
    lcb_error_t rc;

    lcb_CMDSDGET sdgcmd = { 0 };
    LCB_CMD_SET_KEY(&sdgcmd, key.c_str(), key.size());

    LCB_SDCMD_SET_PATH(&sdgcmd, "dictkey", strlen("dictkey"));
    // get
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("\"dictval\"", res.value) << "Get dict value";
    // exists
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdexists3));
    ASSERT_EQ(LCB_SUCCESS, res.rc) << "Dict value exists";
    ASSERT_TRUE(res.value.empty());

    LCB_SDCMD_SET_PATH(&sdgcmd, "array", strlen("array"));
    // get
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("[1,2,3,4,[10,20,30,[100,200,300]]]", res.value) << "Get whole array";
    // exists
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdexists3));
    ASSERT_EQ(LCB_SUCCESS, res.rc) << "Array exists";
    ASSERT_TRUE(res.value.empty());

    LCB_SDCMD_SET_PATH(&sdgcmd, "array[0]", strlen("array[0]"));
    // get
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("1", res.value) << "Get array element";
    // exists
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdexists3));
    ASSERT_EQ(LCB_SUCCESS, res.rc) << "Array element exists";
    ASSERT_TRUE(res.value.empty());

    LCB_SDCMD_SET_PATH(&sdgcmd, "non-exist", strlen("non-exist"));
    // get
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUBDOC_PATH_ENOENT, res.rc) << "Get non-exist path";
    // exists
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdexists3));
    ASSERT_EQ(LCB_SUBDOC_PATH_ENOENT, res.rc);

    LCB_CMD_SET_KEY(&sdgcmd, "non-exist", strlen("non-exist"));
    // get
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_KEY_ENOENT, res.rc) << "Get non-exist document";
    // exists
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdexists3));
    ASSERT_EQ(LCB_KEY_ENOENT, res.rc);

    // Store non-JSON document
    LCB_CMD_SET_KEY(&sdgcmd, nonJsonKey.c_str(), nonJsonKey.size());

    // Get
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUBDOC_DOC_NOTJSON, res.rc) << "Get non-JSON document";
    // exists
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdexists3));
    ASSERT_EQ(LCB_SUBDOC_DOC_NOTJSON, res.rc);

    // Restore the key back to the document..
    LCB_CMD_SET_KEY(&sdgcmd, key.c_str(), key.size());

    // Invalid paths
    LCB_SDCMD_SET_PATH(&sdgcmd, "invalid..path", strlen("invalid..path"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUBDOC_PATH_EINVAL, res.rc);

    LCB_SDCMD_SET_PATH(&sdgcmd, "invalid[-2]", strlen("invalid[-2]"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUBDOC_PATH_EINVAL, res.rc);

    // Test negative paths
    LCB_SDCMD_SET_PATH(&sdgcmd, "array[-1][-1][-1]", strlen("array[-1][-1][-1]"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc) << lcb_strerror(NULL, res.rc);
    ASSERT_EQ("300", res.value);

    // Test nested arrays
    LCB_SDCMD_SET_PATH(&sdgcmd, "array[4][3][2]", strlen("array[4][3][2]"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("300", res.value);

    // Test path mismatch
    LCB_SDCMD_SET_PATH(&sdgcmd, "array.key", strlen("array.key"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &sdgcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUBDOC_PATH_MISMATCH, res.rc);
}

TEST_F(SubdocUnitTest, testSdStore)
{
    HandleWrap hw;
    lcb_t instance;
    lcb_error_t rc;
    CREATE_SUBDOC_CONNECTION(hw, instance);
    lcb_CMDSDSTORE cmd = { 0 };
    lcb_CMDSDGET gcmd = { 0 };

    LCB_CMD_SET_KEY(&cmd, key.c_str(), key.size());
    LCB_SDCMD_SET_PATH(&cmd, "newpath", strlen("newpath"));
    LCB_CMD_SET_VALUE(&cmd, "123", strlen("123"));

    Result res;

    // Insert
    cmd.mode = LCB_SUBDOC_DICT_ADD;
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_NE(0, res.cas);

    cmd.mode = LCB_SUBDOC_DICT_ADD;
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUBDOC_PATH_EEXISTS, res.rc);

    cmd.mode = LCB_SUBDOC_DICT_UPSERT;
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);

    // See if our value actually matches
    LCB_CMD_SET_KEY(&gcmd, key.c_str(), key.size());
    LCB_SDCMD_SET_PATH(&gcmd, "newpath", strlen("newpath"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &gcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("123", res.value);

    // Try with a bad CAS
    cmd.cas = res.cas + 1;
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_KEY_EEXISTS, res.rc);
    cmd.cas = 0; // Reset CAS

    // Try to add a compound value
    LCB_SDCMD_SET_PATH(&cmd, "dict", strlen("dict"));
    const char *v = "{\"key\":\"value\"}";
    LCB_CMD_SET_VALUE(&cmd, v, strlen(v));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    // Get it back
    LCB_CMD_SET_KEY(&gcmd, key.c_str(), key.size());
    LCB_SDCMD_SET_PATH(&gcmd, "dict.key", strlen("dict.key"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &gcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("\"value\"", res.value);

    // Try to insert a non-JSON value
    LCB_CMD_SET_VALUE(&cmd, "non-json", strlen("non-json"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUBDOC_VALUE_CANTINSERT, res.rc);

    const char *p = "parent.with.missing.children";

    // Intermediate paths
    LCB_SDCMD_SET_PATH(&cmd, p, strlen(p));
    LCB_CMD_SET_VALUE(&cmd, "null", strlen("null"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUBDOC_PATH_ENOENT, res.rc);

    // set MKINTERMEDIATES (MKDIR_P)
    cmd.cmdflags |= LCB_CMDSUBDOC_F_MKINTERMEDIATES;
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);

    cmd.cmdflags = 0;
    LCB_SDCMD_SET_PATH(&gcmd, p, strlen(p));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &gcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("null", res.value);

    // Test replace
    cmd.mode = LCB_SUBDOC_REPLACE;
    LCB_SDCMD_SET_PATH(&cmd, "dict", strlen("dict"));
    LCB_CMD_SET_VALUE(&cmd, "123", strlen("123"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);

    // Try replacing a non-existing path
    LCB_SDCMD_SET_PATH(&cmd, "non-exist", strlen("non-exist"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUBDOC_PATH_ENOENT, res.rc);

    // Try replacing root element. Invalid path for operation
    LCB_SDCMD_SET_PATH(&cmd, "", 0);
    ASSERT_EQ(LCB_EINVAL, schedwait(instance, &res, &cmd, lcb_sdstore3));

    // Try replacing array element
    LCB_SDCMD_SET_PATH(&cmd, "array[1]", strlen("array[1]"));
    LCB_CMD_SET_VALUE(&cmd, "true", strlen("true"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);

    LCB_SDCMD_SET_PATH(&gcmd, "array[1]", strlen("array[1]"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &gcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("true", res.value);
}

TEST_F(SubdocUnitTest, testUnique)
{
    HandleWrap hw;
    lcb_t instance;
    lcb_CMDSDSTORE cmd = { 0 };
    lcb_CMDSDGET gcmd = { 0 };
    Result res;

    CREATE_SUBDOC_CONNECTION(hw, instance);

    LCB_CMD_SET_KEY(&cmd, key.c_str(), key.size());
    LCB_CMD_SET_KEY(&gcmd, key.c_str(), key.size());

    // Test array operations: ADD_UNIQUE
    LCB_SDCMD_SET_PATH(&cmd, "a", strlen("a"));
    LCB_CMD_SET_VALUE(&cmd, "1", strlen("1"));
    cmd.mode = LCB_SUBDOC_ARRAY_ADD_UNIQUE;
    cmd.cmdflags |= LCB_CMDSUBDOC_F_MKINTERMEDIATES;
    // Push to a non-existent array (without _P)
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    cmd.cmdflags = 0;

    // Get the item back
    LCB_SDCMD_SET_PATH(&gcmd, "a[0]", strlen("a[0]"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &gcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("1", res.value);

    // Try adding the item again
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUBDOC_PATH_EEXISTS, res.rc);

    // Try adding a primitive
    LCB_CMD_SET_VALUE(&cmd, "{}", strlen("{}"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUBDOC_VALUE_CANTINSERT, res.rc);

    // Add the primitive using append
    cmd.mode = LCB_SUBDOC_ARRAY_ADD_LAST;
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);

    LCB_SDCMD_SET_PATH(&gcmd, "a[-1]", strlen("a[-1]"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &gcmd, lcb_sdget3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("{}", res.value);

    cmd.mode = LCB_SUBDOC_ARRAY_ADD_UNIQUE;
    LCB_CMD_SET_VALUE(&cmd, "null", strlen("null"));
    // Add unique to array with non-primitive
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUBDOC_PATH_MISMATCH, res.rc);
}

TEST_F(SubdocUnitTest, testCounter)
{
    HandleWrap hw;
    lcb_t instance;
    lcb_CMDSDCOUNTER cmd = { 0 };
    lcb_error_t rc;
    Result res;

    CREATE_SUBDOC_CONNECTION(hw, instance);

    LCB_CMD_SET_KEY(&cmd, key.c_str(), key.size());
    LCB_SDCMD_SET_PATH(&cmd, "counter", strlen("counter"));
    cmd.delta = 42;

    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdcounter3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("42", res.value);
    ASSERT_NE(0, res.cas);

    // Try it again
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdcounter3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("84", res.value);

    static const char *si64max = "9223372036854775807";

    // Use a large value
    lcb_CMDSDSTORE scmd = { 0 };
    scmd.mode = LCB_SUBDOC_DICT_UPSERT;
    LCB_CMD_SET_KEY(&scmd, key.c_str(), key.size());
    LCB_SDCMD_SET_PATH(&scmd, "counter", strlen("counter"));
    // INT64_MAX
    LCB_CMD_SET_VALUE(&scmd, si64max, strlen(si64max));

    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &scmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ(si64max, getPathValue(instance, key.c_str(), "counter"));

    // Try to increment by 1
    cmd.delta = 1;
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdcounter3));
    ASSERT_EQ(LCB_SUBDOC_DELTA_ERANGE, res.rc);

    // Try to use an already large number
    std::string biggerNum(si64max);
    biggerNum += "999999999999999999999999999999";
    LCB_CMD_SET_VALUE(&scmd, biggerNum.c_str(), biggerNum.size());
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &scmd, lcb_sdstore3));

    // Try the counter op again
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdcounter3));
    ASSERT_EQ(LCB_SUBDOC_NUM_ERANGE, res.rc);

    // Try the counter op with a non-JSON path
    LCB_SDCMD_SET_PATH(&cmd, "dictkey", strlen("dictkey"));
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdcounter3));
    ASSERT_EQ(LCB_SUBDOC_PATH_MISMATCH, res.rc);

    LCB_SDCMD_SET_PATH(&cmd, "counter", strlen("counter"));
    LCB_CMD_SET_VALUE(&scmd, "0", 1);
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &scmd, lcb_sdstore3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);

    // Try decrement
    cmd.delta = -42;
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdcounter3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("-42", res.value);
    // Try it again
    ASSERT_EQ(LCB_SUCCESS, schedwait(instance, &res, &cmd, lcb_sdcounter3));
    ASSERT_EQ(LCB_SUCCESS, res.rc);
    ASSERT_EQ("-84", res.value);
}

TEST_F(SubdocUnitTest, testMultiLookup)
{
    HandleWrap hw;
    lcb_t instance;
    CREATE_SUBDOC_CONNECTION(hw, instance);

    MultiResult mr;
    lcb_error_t rc;

    lcb_CMDSDMULTI mcmd = { 0 };
    mcmd.multimode = LCB_SDMULTI_MODE_LOOKUP;
    LCB_CMD_SET_KEY(&mcmd, key.c_str(), key.size());

    lcb_sched_enter(instance);
    lcb_SDMULTICTX *ctx = lcb_sdmultictx_new(instance, &mr, &mcmd, &rc);
    ASSERT_EQ(LCB_SUCCESS, rc);
    ASSERT_FALSE(ctx == NULL);

    lcb_CMDSDGET gcmd = { 0 };

    LCB_SDCMD_SET_PATH(&gcmd, "dictkey", strlen("dictkey"));
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_GET, (const lcb_CMDSDBASE*)&gcmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    LCB_SDCMD_SET_PATH(&gcmd, "array[0]", strlen("array[0]"));
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_EXISTS, (const lcb_CMDSDBASE*)&gcmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    // Sandwich a non-exist path between
    LCB_SDCMD_SET_PATH(&gcmd, "nonexist", strlen("nonexist"));
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_GET, (const lcb_CMDSDBASE*)&gcmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    LCB_SDCMD_SET_PATH(&gcmd, "array[1]", strlen("array[1]"));
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_GET, (const lcb_CMDSDBASE*)&gcmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    rc = lcb_sdmultictx_done(ctx);
    ASSERT_EQ(LCB_SUCCESS, rc);
    lcb_sched_leave(instance);
    lcb_wait(instance);

    ASSERT_EQ(LCB_SUBDOC_MULTI_FAILURE, mr.rc);
    ASSERT_EQ(4, mr.results.size());
    ASSERT_NE(0, mr.cas);

    ASSERT_EQ("\"dictval\"", mr.results[0].value);
    ASSERT_EQ(LCB_SUCCESS, mr.results[0].rc);

    ASSERT_TRUE(mr.results[1].value.empty());
    ASSERT_EQ(LCB_SUCCESS, mr.results[1].rc);

    ASSERT_TRUE(mr.results[2].value.empty());
    ASSERT_EQ(LCB_SUBDOC_PATH_ENOENT, mr.results[2].rc);

    ASSERT_EQ("2", mr.results[3].value);
    ASSERT_EQ(LCB_SUCCESS, mr.results[0].rc);

    // Test multi lookups with bad command types
    ctx = lcb_sdmultictx_new(instance, &mr, &mcmd, &rc);
    ASSERT_EQ(LCB_OPTIONS_CONFLICT,
        lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_REMOVE, (const lcb_CMDSDBASE*)&gcmd));
    lcb_sdmultictx_fail(ctx);

    // Test multi lookups with missing key
    std::string missing_key("missing-key");
    removeKey(instance, missing_key);

    mr.clear();
    LCB_CMD_SET_KEY(&mcmd, missing_key.c_str(), missing_key.size());
    lcb_sched_enter(instance);

    ctx = lcb_sdmultictx_new(instance, &mr, &mcmd, &rc);
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_GET, (const lcb_CMDSDBASE*)&gcmd);
    ASSERT_EQ(LCB_SUCCESS, rc);
    rc = lcb_sdmultictx_done(ctx);
    ASSERT_EQ(LCB_SUCCESS, rc);
    lcb_sched_leave(instance);
    lcb_wait(instance);
    ASSERT_EQ(LCB_KEY_ENOENT, mr.rc);
    ASSERT_TRUE(mr.results.empty());
}

TEST_F(SubdocUnitTest, testMultiMutations)
{
    HandleWrap hw;
    lcb_t instance;
    CREATE_SUBDOC_CONNECTION(hw, instance);

    lcb_CMDSDMULTI mcmd = { 0 };
    LCB_CMD_SET_KEY(&mcmd, key.c_str(), key.size());
    mcmd.multimode = LCB_SDMULTI_MODE_MUTATE;

    MultiResult mr;
    lcb_error_t rc;
    lcb_SDMULTICTX *ctx;

    lcb_sched_enter(instance);

    ctx = lcb_sdmultictx_new(instance, &mr, &mcmd, &rc);
    ASSERT_EQ(LCB_SUCCESS, rc);
    ASSERT_FALSE(ctx == NULL);

    lcb_CMDSDSTORE scmd = { 0 };
    LCB_SDCMD_SET_PATH(&scmd, "newPath", strlen("newPath"));
    LCB_CMD_SET_VALUE(&scmd, "true", strlen("true"));
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_DICT_UPSERT, (const lcb_CMDSDBASE*)&scmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    lcb_CMDSDCOUNTER ccmd = { 0 };
    LCB_SDCMD_SET_PATH(&ccmd, "counter", strlen("counter"));
    ccmd.delta = 42;
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_COUNTER, (const lcb_CMDSDBASE*)&ccmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    // Should be OK for now
    rc = lcb_sdmultictx_done(ctx);
    ASSERT_EQ(LCB_SUCCESS, rc);
    lcb_sched_leave(instance);
    lcb_wait(instance);
    ASSERT_EQ(LCB_SUCCESS, mr.rc);

    // Ensure the parameters were encoded correctly..
    ASSERT_EQ("true", getPathValue(instance, key.c_str(), "newPath"));
    ASSERT_EQ("42", getPathValue(instance, key.c_str(), "counter"));

    lcb_sched_enter(instance);
    mr.clear();
    // New context. Try with mismatched commands
    ctx = lcb_sdmultictx_new(instance, &mr, &mcmd, &rc);
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_GET, (const lcb_CMDSDBASE*)&scmd);
    ASSERT_EQ(LCB_OPTIONS_CONFLICT, rc);


    LCB_SDCMD_SET_PATH(&scmd, "newPath", strlen("newPath"));
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_REPLACE, (const lcb_CMDSDBASE*)&scmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    // Add something with an invalid path
    LCB_SDCMD_SET_PATH(&scmd, "nested.nonexist", strlen("nested.nonexist"));
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_REPLACE, (const lcb_CMDSDBASE*)&scmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    LCB_SDCMD_SET_PATH(&scmd, "bad..path", strlen("bad..path"));
    rc = lcb_sdmultictx_addcmd(ctx, LCB_SUBDOC_REPLACE, (const lcb_CMDSDBASE*)&scmd);
    ASSERT_EQ(LCB_SUCCESS, rc);

    rc = lcb_sdmultictx_done(ctx);
    ASSERT_EQ(LCB_SUCCESS, rc);

    lcb_sched_leave(instance);
    lcb_wait(instance);
    ASSERT_EQ(LCB_SUBDOC_PATH_ENOENT, mr.rc);
    ASSERT_EQ(1, mr.last_errix);

}
