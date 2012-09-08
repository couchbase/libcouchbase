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

#include "server.h"
#include "mock-unit-test.h"

const struct test_server_info *MockEnvironment::mock = NULL;
const char *MockEnvironment::http = NULL;
int MockEnvironment::numNodes;
ServerParams MockEnvironment::serverParams;
bool MockEnvironment::isRealCluster = false;

void MockEnvironment::bootstrapRealCluster()
{
    serverParams = ServerParams(mock->http, mock->bucket,
                                mock->username, mock->password);

    lcb_t tmphandle;
    lcb_error_t err;
    lcb_create_st options;
    serverParams.makeConnectParams(options);

    ASSERT_EQ(LCB_SUCCESS, lcb_create(&tmphandle, &options));
    ASSERT_EQ(LCB_SUCCESS, lcb_connect(tmphandle));
    lcb_wait(tmphandle);

    const char * const *servers = lcb_get_server_list(tmphandle);
    bool verbose = getenv("LCB_VERBOSE_TESTS") != 0;

    if (verbose) {
        std::cout << "Using the following servers: " << std::endl;
    }

    int ii;
    for (ii = 0; servers[ii] != NULL; ii++) {
        if (verbose) {
            std::cout << "[" << servers[ii] << "]" << std::endl;
        }
    }

    numNodes = ii;
    lcb_destroy(tmphandle);
}

void MockEnvironment::SetUp()
{
    mock = (struct test_server_info*)start_test_server(NULL);
    isRealCluster = is_using_real_cluster();
    ASSERT_NE((const void *)(NULL), mock);
    http = get_mock_http_server(mock);
    ASSERT_NE((const char *)(NULL), http);

    if (isRealCluster) {
        bootstrapRealCluster();
    } else {
        numNodes = 10;
    }
}

void MockEnvironment::TearDown()
{
    shutdown_mock_server(mock);
}
