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
#ifndef TESTS_TESTUTIL_H
#define TESTS_TESTUTIL_H 1

#include <libcouchbase/couchbase.h>
#include <string.h>

struct Item {
    void assign(const lcb_get_resp_t *resp, lcb_error_t e = LCB_SUCCESS) {
        key.assign((const char*)resp->v.v0.key, resp->v.v0.nkey);
        val.assign((const char*)resp->v.v0.bytes, resp->v.v0.nbytes);
        flags = resp->v.v0.flags;
        cas =  resp->v.v0.cas;
        datatype =  resp->v.v0.datatype;
        err = e;
    }

    /**
     * Extract the key and CAS from a response.
     */
    template <typename T>
    void assignKC(const T *resp, lcb_error_t e = LCB_SUCCESS) {
        key.assign((const char*)resp->v.v0.key, resp->v.v0.nkey);
        cas = resp->v.v0.cas;
        err = e;
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
    lcb_error_t err;
};

void storeKey(lcb_t instance, const std::string &key, const std::string &value);
void removeKey(lcb_t instance, const std::string &key);
void getKey(lcb_t instance, const std::string &key, Item &item);

#endif
