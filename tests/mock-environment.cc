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
#include "mock-environment.h"

MockEnvironment *MockEnvironment::instance;

MockEnvironment *MockEnvironment::getInstance(void)
{
    if (instance == NULL) {
        instance = new MockEnvironment;
    }
    return instance;
}

void MockEnvironment::Reset()
{
    if (instance != NULL) {
        instance->TearDown();
        instance->SetUp();
    }
}

MockEnvironment::MockEnvironment() : mock(NULL), numNodes(10),
    realCluster(false),
    serverVersion(VERSION_UNKNOWN),
    http(NULL)
{
    // No extra init needed
}

void MockEnvironment::createConnection(lcb_t &instance)
{
    struct lcb_io_opt_st *io;

    if (lcb_create_io_ops(&io, NULL) != LCB_SUCCESS) {
        fprintf(stderr, "Failed to create IO instance\n");
        exit(1);
    }

    lcb_create_st options;
    makeConnectParams(options, io);

    ASSERT_EQ(LCB_SUCCESS, lcb_create(&instance, &options));
    (void)lcb_set_cookie(instance, io);
}

#define STAT_EP_VERSION "ep_version"

extern "C" {
    static void statsCallback(lcb_t, const void *cookie,
                              lcb_error_t err,
                              const lcb_server_stat_resp_t *resp)
    {
        MockEnvironment *me = (MockEnvironment *)cookie;
        ASSERT_EQ(LCB_SUCCESS, err);
        if (resp->v.v0.server_endpoint == NULL) {
            return;
        }

        if (!resp->v.v0.nkey) {
            return;
        }

        if (resp->v.v0.nkey != sizeof(STAT_EP_VERSION) - 1  ||
                memcmp(resp->v.v0.key, STAT_EP_VERSION,
                       sizeof(STAT_EP_VERSION) - 1) != 0) {
            return;
        }
        int version = ((const char *)resp->v.v0.bytes)[0] - '0';
        if (version == 1) {
            me->setServerVersion(MockEnvironment::VERSION_10);
        } else if (version == 2) {
            me->setServerVersion(MockEnvironment::VERSION_20);

        } else {
            std::cerr << "Unable to determine version from string '";
            std::cerr.write((const char *)resp->v.v0.bytes,
                            resp->v.v0.nbytes);
            std::cerr << "' assuming 1.x" << std::endl;

            me->setServerVersion(MockEnvironment::VERSION_10);
        }
    }
}

void MockEnvironment::bootstrapRealCluster()
{
    serverParams = ServerParams(mock->http, mock->bucket,
                                mock->username, mock->password);

    lcb_t tmphandle;
    lcb_error_t err;
    lcb_create_st options;
    serverParams.makeConnectParams(options, NULL);

    bool verbose = getenv("LCB_VERBOSE_TESTS") != 0;


    ASSERT_EQ(LCB_SUCCESS, lcb_create(&tmphandle, &options));
    ASSERT_EQ(LCB_SUCCESS, lcb_connect(tmphandle));
    lcb_wait(tmphandle);

    lcb_set_stat_callback(tmphandle, statsCallback);
    lcb_server_stats_cmd_t scmd, *pscmd;
    pscmd = &scmd;
    err = lcb_server_stats(tmphandle, this, 1, &pscmd);
    ASSERT_EQ(LCB_SUCCESS, err);
    lcb_wait(tmphandle);

    if (verbose) {
        std::cout << "Detected cluster version " << std::dec << serverVersion;
        std::cout << std::endl;
    }

    const char *const *servers = lcb_get_server_list(tmphandle);
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
    mock = (struct test_server_info *)start_test_server(NULL);
    realCluster = is_using_real_cluster();
    ASSERT_NE((const void *)(NULL), mock);
    http = get_mock_http_server(mock);
    ASSERT_NE((const char *)(NULL), http);

    if (realCluster) {
        bootstrapRealCluster();
    } else {
        serverParams = ServerParams(http, getenv("LCB_TEST_BUCKET"),
                                    "Administrator",
                                    "password");
        numNodes = 10;
    }
}

void MockEnvironment::TearDown()
{
    shutdown_mock_server(mock);
    mock = NULL;
}
