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
    enum ServerVersion {
        VERSION_UNKNOWN = 0,
        VERSION_10 = 1,
        VERSION_20 = 2
    };

    virtual void SetUp();
    virtual void TearDown();

    static MockEnvironment* getInstance(void);

    /**
     * Make a connect structure you may utilize to connect to
     * the backend we're running the tests towards.
     *
     * @param crst the create structure to fill in
     * @param io the io ops to use (pass NULL if you don't have a
     *           special io ops you want to use
     */
    void makeConnectParams(lcb_create_st &crst, lcb_io_opt_t io) {
        serverParams.makeConnectParams(crst, io);
    }

    /**
     * Get the number of nodes used in the backend
     */
    int getNumNodes(void) const {
        return numNodes;
    }

    /**
     * Are we currently using a real cluster as the backend, or
     * are we using the mock server.
     *
     * You should try your very best to avoid using this variable, and
     * rather extend the mock server to support the requested feature.
     */
    bool isRealCluster(void) const {
        return realCluster;
    }

    /**
     * Create a connection to the mock/real server.
     *
     * The instance will be initialized with the the connect parameters
     * to either the mock or a real server (just like makeConnectParams),
     * and call lcb_create. The io instance will be stored in the instance
     * cookie so you may grab it from there.
     *
     * You should call lcb_destroy on the instance when you're done
     * using it.
     *
     * @param instance the instane to create
     */
    void createConnection(lcb_t &instance);

    ServerVersion getServerVersion(void) const {
        return serverVersion;
    }

    void setServerVersion(ServerVersion ver)  {
        serverVersion = ver;
    }

protected:
    /**
     * Protected destructor to make it to a singleton
     */
    MockEnvironment();
    /**
     * Handle to the one and only instance of the mock environment
     */
    static MockEnvironment *instance;

    void bootstrapRealCluster();
    const struct test_server_info *mock;
    ServerParams serverParams;
    int numNodes;
    bool realCluster;
    ServerVersion serverVersion;
    const char *http;
};

#define LCB_TEST_REQUIRE_CLUSTER_VERSION(v) \
    if (!MockEnvironment::getInstance()->isRealCluster()) {             \
        std::cerr << "Skipping " << __FILE__ << ":" << std::dec << __LINE__; \
        std::cerr << " (need real cluster) " << std::endl; \
        return; \
    } \
    if (MockEnvironment:::getInstance()->getServerVersion() < v) {      \
        std::cerr << "Skipping " << __FILE__ << ":" << std::dec << __LINE__; \
        std::cerr << " (test needs higher cluster version)" << std::endl; \
        return; \
    }



#endif
