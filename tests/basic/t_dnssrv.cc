/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2026 Couchbase, Inc.
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

#include <cstring>
#include <string>

#if defined(HAVE_RES_NINIT) && defined(__linux__) && defined(__GLIBC__)
#include <netinet/in.h>
#include <resolv.h>

namespace
{
/* Off except around the lcb_create() below, so nothing else in this binary
 * reaches the interposed resolver. */
bool watching = false;
int queries = 0;
int observed_retrans = 0;
int observed_retry = 0;
std::string observed_name;
} // namespace

/**
 * The bound is only observable in the resolver state the library hands over,
 * because reaching the ceiling means waiting for it. Interposing the query is
 * what makes it a test rather than a stopwatch.
 */
extern "C" int res_nsearch(res_state statp, const char *dname, int, int, unsigned char *, int)
{
    if (watching) {
        queries++;
        observed_retrans = statp->retrans;
        observed_retry = statp->retry;
        observed_name = dname;
    }
    /* Every query is answered here, watched or not, so this binary never
     * reaches the network. Delegating to the real resolver would need its
     * address, and glibc exposes the lookup under __res_nsearch, so the
     * unprefixed name a dlsym() would ask for resolves to nothing before
     * 2.34. A negative return is "no such name", which process_dns_srv()
     * treats as "no SRV record" and falls back to the hostname it was
     * given. */
    return -1;
}

class DnsSrvTest : public ::testing::Test
{
};

/**
 * A connection string naming a single host with no port and no scheme suffix
 * asks for a DNS SRV lookup, and lcb_create() performs it before returning.
 * The resolver's own defaults let an unanswered query run to retrans * retry *
 * nameservers seconds, so the wait has to be bounded by something the caller
 * chose.
 */
TEST_F(DnsSrvTest, lookupIsBoundedByTheNodeTimeout)
{
    const std::string connstr = "couchbase://dnssrv-bound.example.com/default?config_node_timeout=4.0";
    lcb_CREATEOPTS *options = nullptr;
    lcb_createopts_create(&options, LCB_TYPE_BUCKET);
    lcb_createopts_connstr(options, connstr.c_str(), connstr.size());
    lcb_createopts_credentials(options, "Administrator", 13, "password", 8);

    lcb_INSTANCE *instance = nullptr;
    queries = 0;
    watching = true;
    lcb_STATUS rc = lcb_create(&instance, options);
    watching = false;
    lcb_createopts_destroy(options);

    ASSERT_EQ(LCB_SUCCESS, rc);
    ASSERT_EQ(1, queries) << "lcb_create did not perform the SRV lookup, so nothing was bounded";
    ASSERT_EQ("_couchbase._tcp.dnssrv-bound.example.com", observed_name);

    /* retrans is per nameserver per pass and retry counts the passes, so this
     * is the ceiling in seconds for one name in the search list. */
    ASSERT_GE(observed_retrans, 1);
    ASSERT_LE(observed_retrans, 4);
    ASSERT_EQ(1, observed_retry);

    lcb_destroy(instance);
}

/**
 * A SRV lookup asks one name to stand for the whole cluster, so it applies only
 * when the connection string names a single host. With more than one, nothing
 * is resolved and lcb_create() does not go near the network.
 */
TEST_F(DnsSrvTest, severalHostsAreNotLookedUp)
{
    const std::string connstr = "couchbase://one.example.com,two.example.com/default";
    lcb_CREATEOPTS *options = nullptr;
    lcb_createopts_create(&options, LCB_TYPE_BUCKET);
    lcb_createopts_connstr(options, connstr.c_str(), connstr.size());
    lcb_createopts_credentials(options, "Administrator", 13, "password", 8);

    lcb_INSTANCE *instance = nullptr;
    queries = 0;
    watching = true;
    lcb_STATUS rc = lcb_create(&instance, options);
    watching = false;
    lcb_createopts_destroy(options);

    ASSERT_EQ(LCB_SUCCESS, rc);
    ASSERT_EQ(0, queries);

    lcb_destroy(instance);
}
#endif
