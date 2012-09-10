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
#ifndef TESTS_MOCK_ENVIRONMENT_H
#define TESTS_MOCK_ENVIRONMENT_H 1

#include "config.h"
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#include "serverparams.h"

class MockEnvironment : public ::testing::Environment
{
public:
    virtual void SetUp();
    virtual void TearDown();

    static void makeConnectParams(lcb_create_st &crst) {
        serverParams.makeConnectParams(crst);
    }

    static int numNodes;
    static bool isRealCluster;
    static const char *http;


protected:
    static void bootstrapRealCluster();
    static const struct test_server_info *mock;
    static ServerParams serverParams;
};

#endif
