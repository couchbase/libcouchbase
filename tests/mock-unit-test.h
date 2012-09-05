#ifndef TESTS_MOCK_UNIT_TESTS_H_
#define TESTS_MOCK_UNIT_TESTS_H_

#include "config.h"
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#include "server.h"
#include <string.h>

struct Item {
    void assign(const lcb_get_resp_t *resp) {
        key.assign((const char*)resp->v.v0.key, resp->v.v0.nkey);
        val.assign((const char*)resp->v.v0.bytes, resp->v.v0.nbytes);
        flags = resp->v.v0.flags;
        cas =  resp->v.v0.cas;
        datatype =  resp->v.v0.datatype;
    }

    Item() {
        flags = 0;
        cas = 0;
        datatype = 0;
    }

    std::string key;
    std::string val;
    lcb_uint32_t flags;
    lcb_cas_t cas;
    lcb_datatype_t datatype;
};


class MockUnitTest : public ::testing::Test
{
public:
    static int numNodes;

protected:
    static void SetUpTestCase();
    static void TearDownTestCase();

    virtual void createConnection(lcb_t &instance);
    static const void *mock;
    static const char *http;
};

void utilStoreKey(lcb_t instance,
              const std::string &key,
              const std::string &value);
void utilRemoveKey(lcb_t instance,
               const std::string &key);
void utilGetKey(lcb_t instance, const std::string &key, Item &item);


#endif
