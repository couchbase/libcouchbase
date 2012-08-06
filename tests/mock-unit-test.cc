/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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
#include "server.h"

void MockUnitTest::SetUpTestCase() {
    numNodes = 10;
    mock = start_mock_server(NULL);
    ASSERT_NE((const void*)(NULL), mock);
    http = get_mock_http_server(mock);
    ASSERT_NE((const char*)(NULL), http);
}

void MockUnitTest::TearDownTestCase() {
    shutdown_mock_server(mock);
}

extern "C" {
    static void error_callback(libcouchbase_t instance,
                               libcouchbase_error_t err,
                               const char *errinfo)
    {
        std::cerr << "Error " << libcouchbase_strerror(instance, err);
        if (errinfo) {
            std::cerr << errinfo;
        }

        ASSERT_TRUE(false);
    }
}

void MockUnitTest::createConnection(libcouchbase_t &instance) {
    struct libcouchbase_io_opt_st *io;

    io = get_test_io_opts();
    if (io == NULL) {
        fprintf(stderr, "Failed to create IO instance\n");
            exit(1);
    }
    instance = libcouchbase_create(http, "Administrator", "password",
                                       getenv("LIBCOUCHBASE_TEST_BUCKET"), io);

    ASSERT_NE((libcouchbase_t)NULL, instance);
    (void)libcouchbase_set_cookie(instance, io);
    (void)libcouchbase_set_error_callback(instance, error_callback);
    ASSERT_EQ(LIBCOUCHBASE_SUCCESS, libcouchbase_connect(instance));
    libcouchbase_wait(instance);
}


const void *MockUnitTest::mock;
const char *MockUnitTest::http;
int MockUnitTest::numNodes;

extern "C" {
    static void flags_storage_callback(libcouchbase_t,
                                       const void *,
                                       libcouchbase_storage_t operation,
                                       libcouchbase_error_t error,
                                       const void *key,
                                       libcouchbase_size_t nkey,
                                       libcouchbase_cas_t)
    {
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        ASSERT_EQ(5, nkey);
        ASSERT_EQ(0, memcmp(key, "flags", 5));
        ASSERT_EQ(LIBCOUCHBASE_SET, operation);
    }

    static void flags_get_callback(libcouchbase_t,
                                  const void *,
                                  libcouchbase_error_t error,
                                  const void *key, libcouchbase_size_t nkey,
                                  const void *bytes, libcouchbase_size_t nbytes,
                                  libcouchbase_uint32_t flags,
                                  libcouchbase_cas_t)
    {
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        ASSERT_EQ(5, nkey);
        ASSERT_EQ(0, memcmp(key, "flags", 5));
        ASSERT_EQ(1, nbytes);
        ASSERT_EQ(0, memcmp(bytes, "x", 1));
        ASSERT_EQ(0xdeadbeef, flags);
    }
}

TEST_F(MockUnitTest, testFlags)
{
    libcouchbase_t instance;
    createConnection(instance);
    (void)libcouchbase_set_get_callback(instance, flags_get_callback);
    (void)libcouchbase_set_storage_callback(instance, flags_storage_callback);

    const char *keys[1];
    libcouchbase_size_t nkeys[1];

    keys[0] = "flags";
    nkeys[0] = 5;

    assert(libcouchbase_store(instance, NULL, LIBCOUCHBASE_SET, keys[0], nkeys[0],
                              "x", 1, 0xdeadbeef, 0, 0) == LIBCOUCHBASE_SUCCESS);
    // Wait for it to be persisted
    libcouchbase_wait(instance);

    assert(libcouchbase_mget(instance, NULL, 1, (const void * const *)keys,
                             nkeys, NULL) == LIBCOUCHBASE_SUCCESS);

    // Wait for it to be received
    libcouchbase_wait(instance);

}



static libcouchbase_uint64_t arithm_val;

extern "C" {
    static void arithmetic_storage_callback(libcouchbase_t, const void *,
                                            libcouchbase_storage_t operation,
                                            libcouchbase_error_t error,
                                            const void *key, libcouchbase_size_t nkey,
                                            libcouchbase_cas_t)
    {
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        ASSERT_EQ(LIBCOUCHBASE_SET, operation);
        ASSERT_EQ(7, nkey);
        ASSERT_EQ(0, memcmp(key, "counter", 7));
    }

    static void arithmetic_incr_callback(libcouchbase_t, const void *,
                                         libcouchbase_error_t error,
                                         const void *key,
                                         libcouchbase_size_t nkey,
                                         libcouchbase_uint64_t value,
                                         libcouchbase_cas_t)
    {
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        ASSERT_EQ(7, nkey);
        ASSERT_EQ(0, memcmp(key, "counter", 7));
        ASSERT_EQ(arithm_val + 1, value);
        arithm_val = value;
    }

    static void arithmetic_decr_callback(libcouchbase_t, const void *,
                                         libcouchbase_error_t error,
                                         const void *key,
                                         libcouchbase_size_t nkey,
                                         libcouchbase_uint64_t value,
                                         libcouchbase_cas_t)
    {
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        ASSERT_EQ(7, nkey);
        ASSERT_EQ(0, memcmp(key, "counter", 7));
        ASSERT_EQ(arithm_val - 1, value);
        arithm_val = value;
    }

    static void arithmetic_create_callback(libcouchbase_t, const void *,
                                           libcouchbase_error_t error,
                                           const void *key,
                                           libcouchbase_size_t nkey,
                                           libcouchbase_uint64_t value,
                                           libcouchbase_cas_t)
    {
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        ASSERT_EQ(9, nkey);
        ASSERT_EQ(0, memcmp(key, "mycounter", 9));
        ASSERT_EQ(0xdeadbeef, value);
    }
}

TEST_F(MockUnitTest, populateArithmetic)
{
    libcouchbase_t instance;
    createConnection(instance);
    (void)libcouchbase_set_storage_callback(instance, arithmetic_storage_callback);
    libcouchbase_store(instance, this, LIBCOUCHBASE_SET, "counter", 7,
                       "0", 1, 0, 0, 0);
    libcouchbase_wait(instance);
    libcouchbase_destroy(instance);
}

TEST_F(MockUnitTest, testIncr)
{
    libcouchbase_t instance;
    createConnection(instance);
    (void)libcouchbase_set_arithmetic_callback(instance,
                                               arithmetic_incr_callback);

    for (int ii = 0; ii < 10; ++ii) {
        libcouchbase_arithmetic(instance, NULL, "counter", 7, 1, 0, 1, 0);
        libcouchbase_wait(instance);
    }

    libcouchbase_destroy(instance);
}

TEST_F(MockUnitTest, testDecr)
{
    libcouchbase_t instance;
    createConnection(instance);
    (void)libcouchbase_set_arithmetic_callback(instance,
                                               arithmetic_decr_callback);

    for (int ii = 0; ii < 10; ++ii) {
        libcouchbase_arithmetic(instance, NULL, "counter", 7, -1, 0, 1, 0);
        libcouchbase_wait(instance);
    }

    libcouchbase_destroy(instance);
}

TEST_F(MockUnitTest, testArithmeticCreate)
{
    libcouchbase_t instance;
    createConnection(instance);
    (void)libcouchbase_set_arithmetic_callback(instance,
                                               arithmetic_create_callback);

    libcouchbase_arithmetic(instance, NULL, "mycounter", 9, 0xff, 0, 1, 0xdeadbeef);
    libcouchbase_wait(instance);
    libcouchbase_destroy(instance);
}

extern "C" {
    static void syncmode_store_callback(libcouchbase_t instance,
                                        const void *cookie,
                                        libcouchbase_storage_t operation,
                                        libcouchbase_error_t error,
                                        const void *key,
                                        libcouchbase_size_t nkey,
                                        libcouchbase_cas_t cas)
    {
        int *status = (int *)cookie;
        *status = error;
        (void)instance;
        (void)operation;
        (void)key;
        (void)nkey;
        (void)cas;
    }
}

TEST_F(MockUnitTest, testSyncmodeDefault)
{

    libcouchbase_t instance;
    createConnection(instance);
    ASSERT_EQ(LIBCOUCHBASE_ASYNCHRONOUS,
              libcouchbase_behavior_get_syncmode(instance));
    libcouchbase_destroy(instance);
}

TEST_F(MockUnitTest, testSyncmodeBehaviorToggle)
{
    libcouchbase_t instance;
    createConnection(instance);
    libcouchbase_behavior_set_syncmode(instance, LIBCOUCHBASE_SYNCHRONOUS);
    ASSERT_EQ(LIBCOUCHBASE_SYNCHRONOUS,
              libcouchbase_behavior_get_syncmode(instance));
    libcouchbase_destroy(instance);
}

TEST_F(MockUnitTest, testSyncStore)
{
    libcouchbase_t instance;
    createConnection(instance);
    libcouchbase_behavior_set_syncmode(instance, LIBCOUCHBASE_SYNCHRONOUS);
    ASSERT_EQ(LIBCOUCHBASE_SYNCHRONOUS,
              libcouchbase_behavior_get_syncmode(instance));

    libcouchbase_set_storage_callback(instance, syncmode_store_callback);

    int cookie = 0xffff;
    libcouchbase_error_t ret = libcouchbase_store(instance, &cookie,
                                                  LIBCOUCHBASE_SET,
                                                  "key", 3, NULL, 0,
                                                  0, 0, 0);
    ASSERT_EQ(LIBCOUCHBASE_SUCCESS, ret);
    ASSERT_EQ((int)LIBCOUCHBASE_SUCCESS, cookie);
    cookie = 0xffff;
    ret = libcouchbase_store(instance, &cookie, LIBCOUCHBASE_ADD,
                             "key", 3, NULL, 0, 0, 0, 0);
    ASSERT_TRUE(ret == LIBCOUCHBASE_KEY_EEXISTS &&
                cookie == LIBCOUCHBASE_KEY_EEXISTS);
    libcouchbase_destroy(instance);
}

extern "C" {
    static void timings_callback(libcouchbase_t,
                                 const void *cookie,
                                 libcouchbase_timeunit_t timeunit,
                                 libcouchbase_uint32_t min,
                                 libcouchbase_uint32_t max,
                                 libcouchbase_uint32_t total,
                                 libcouchbase_uint32_t maxtotal)
    {
        FILE *fp = (FILE*)cookie;
        if (fp != NULL) {
            fprintf(fp, "[%3u - %3u]", min, max);

            switch (timeunit) {
            case LIBCOUCHBASE_TIMEUNIT_NSEC:
                fprintf(fp, "ns");
                break;
            case LIBCOUCHBASE_TIMEUNIT_USEC:
                fprintf(fp, "us");
                break;
            case LIBCOUCHBASE_TIMEUNIT_MSEC:
                fprintf(fp, "ms");
                break;
            case LIBCOUCHBASE_TIMEUNIT_SEC:
                fprintf(fp, "s");
                break;
            default:
                ;
            }

            int num = (int)((float)20.0 * (float)total / (float)maxtotal);

            fprintf(fp, " |");
            for (int ii = 0; ii < num; ++ii) {
                fprintf(fp, "#");
            }

            fprintf(fp, " - %u\n", total);
        }
    }
}

TEST_F(MockUnitTest, testTimings)
{
    FILE *fp = stdout;
    if (getenv("LIBCOUCHBASE_VERBOSE_TESTS") == NULL) {
        fp = NULL;
    }

    libcouchbase_t instance;
    createConnection(instance);
    libcouchbase_enable_timings(instance);
    libcouchbase_store(instance, NULL, LIBCOUCHBASE_SET, "counter", 7,
                       "0", 1, 0, 0, 0);
    libcouchbase_wait(instance);
    for (int ii = 0; ii < 100; ++ii) {
        libcouchbase_arithmetic(instance, NULL, "counter", 7, 1, 0, 1, 0);
        libcouchbase_wait(instance);
    }
    if (fp) {
        fprintf(fp, "              +---------+---------+\n");
    }
    libcouchbase_get_timings(instance, fp, timings_callback);
    if (fp) {
        fprintf(fp, "              +--------------------\n");
    }
    libcouchbase_disable_timings(instance);
    libcouchbase_destroy(instance);
}


extern "C" {
    static void timeout_error_callback(libcouchbase_t instance,
                                       libcouchbase_error_t err,
                                       const char *errinfo)
    {
        if (err == LIBCOUCHBASE_ETIMEDOUT) {
            return;
        }
        std::cerr << "Error " << libcouchbase_strerror(instance, err);
        if (errinfo) {
            std::cerr << errinfo;
        }
        std::cerr << std::endl;
        abort();
    }

    int timeout_seqno = 0;
    int timeout_stats_done = 0;

    static void timeout_storage_callback(libcouchbase_t,
                                         const void *cookie,
                                         libcouchbase_storage_t,
                                         libcouchbase_error_t error,
                                         const void *,
                                         libcouchbase_size_t,
                                         libcouchbase_cas_t)
    {
        libcouchbase_io_opt_t *io = (libcouchbase_io_opt_t *)cookie;

        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        timeout_seqno--;
        if (timeout_stats_done && timeout_seqno == 0) {
            io->stop_event_loop(io);
        }
    }

    static void timeout_stat_callback(libcouchbase_t instance,
                                      const void *cookie,
                                      const char *server_endpoint,
                                      libcouchbase_error_t error,
                                      const void *key,
                                      libcouchbase_size_t nkey,
                                      const void *bytes,
                                      libcouchbase_size_t nbytes)
    {
        libcouchbase_error_t err;
        libcouchbase_io_opt_t *io = (libcouchbase_io_opt_t *)cookie;
        char *statkey;
        libcouchbase_size_t nstatkey;

        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        if (server_endpoint != NULL) {
            nstatkey = strlen(server_endpoint) + nkey + 2;
            statkey = new char[nstatkey];
            snprintf(statkey, nstatkey, "%s-%s", server_endpoint, (const char *)key);
            err = libcouchbase_store(instance, io, LIBCOUCHBASE_SET,
                                     statkey, nstatkey,
                                     bytes, nbytes, 0, 0, 0);
            ASSERT_EQ(LIBCOUCHBASE_SUCCESS, err);
            timeout_seqno++;
            delete []statkey;
        } else {
            timeout_stats_done = 1;
        }
    }
}

TEST_F(MockUnitTest, testTimeout)
{
    // @todo we need to have a test that actually tests the timeout callback..
    libcouchbase_t instance;
    libcouchbase_io_opt_t *io;
    createConnection(instance);

    (void)libcouchbase_set_error_callback(instance, timeout_error_callback);
    (void)libcouchbase_set_stat_callback(instance, timeout_stat_callback);
    (void)libcouchbase_set_storage_callback(instance, timeout_storage_callback);

    io = (libcouchbase_io_opt_t *)libcouchbase_get_cookie(instance);
    ASSERT_EQ(LIBCOUCHBASE_SUCCESS,
              libcouchbase_server_stats(instance, io, NULL, 0));
    io->run_event_loop(io);
    libcouchbase_destroy(instance);
}

extern "C" {
    static char *verbosity_endpoint;

    static void verbosity_all_callback(libcouchbase_t instance,
                                       const void *cookie,
                                       const char *server_endpoint,
                                       libcouchbase_error_t error)
    {
        int *counter = (int*)cookie;
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        if (server_endpoint == NULL) {
            EXPECT_EQ(MockUnitTest::numNodes, *counter);
            libcouchbase_io_opt_t *io;
            io = (libcouchbase_io_opt_t *)libcouchbase_get_cookie(instance);
            io->stop_event_loop(io);
            return;
        } else if (verbosity_endpoint == NULL) {
            verbosity_endpoint = strdup(server_endpoint);
        }
        ++(*counter);
    }


    static void verbosity_single_callback(libcouchbase_t instance,
                                          const void *,
                                          const char *server_endpoint,
                                          libcouchbase_error_t error)
    {
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, error);
        if (server_endpoint == NULL) {
            libcouchbase_io_opt_t *io;
            io = (libcouchbase_io_opt_t *)libcouchbase_get_cookie(instance);
            io->stop_event_loop(io);
        } else {
            EXPECT_STREQ(verbosity_endpoint, server_endpoint);
        }
    }
}

TEST_F(MockUnitTest, testVerbosity)
{
    libcouchbase_t instance;
    createConnection(instance);
    (void)libcouchbase_set_verbosity_callback(instance, verbosity_all_callback);

    int counter = 0;
    EXPECT_EQ(LIBCOUCHBASE_SUCCESS,
              libcouchbase_set_verbosity(instance, &counter, NULL,
                                         LIBCOUCHBASE_VERBOSITY_DEBUG));

    libcouchbase_io_opt_t *io;
    io = (libcouchbase_io_opt_t *)libcouchbase_get_cookie(instance);
    io->run_event_loop(io);

    EXPECT_EQ(numNodes, counter);
    EXPECT_NE((char*)NULL, verbosity_endpoint);

    (void)libcouchbase_set_verbosity_callback(instance,
                                              verbosity_single_callback);

    EXPECT_EQ(LIBCOUCHBASE_SUCCESS,
              libcouchbase_set_verbosity(instance, &counter, verbosity_endpoint,
                                         LIBCOUCHBASE_VERBOSITY_DEBUG));
    io->run_event_loop(io);
    free((void*)verbosity_endpoint);

    libcouchbase_destroy(instance);
}

TEST_F(MockUnitTest, testIssue59)
{
    // libcouchbase_wait() blocks forever if there is nothing queued
    libcouchbase_t instance;
    createConnection(instance);
    libcouchbase_wait(instance);
    libcouchbase_wait(instance);
    libcouchbase_wait(instance);
    libcouchbase_wait(instance);
    libcouchbase_wait(instance);
    libcouchbase_wait(instance);
    libcouchbase_wait(instance);
    libcouchbase_wait(instance);
    libcouchbase_destroy(instance);
}

extern "C" {
    struct rvbuf {
        libcouchbase_error_t error;
        libcouchbase_cas_t cas1;
        libcouchbase_cas_t cas2;
    };

    static void df_store_callback1(libcouchbase_t instance,
                                   const void *cookie,
                                   libcouchbase_storage_t,
                                   libcouchbase_error_t error,
                                   const void *, libcouchbase_size_t,
                                   libcouchbase_cas_t)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        rv->error = error;
        libcouchbase_io_opt_t *io = (libcouchbase_io_opt_t *)libcouchbase_get_cookie(instance);
        io->stop_event_loop(io);
    }

    static void df_store_callback2(libcouchbase_t instance,
                                   const void *cookie,
                                   libcouchbase_storage_t,
                                   libcouchbase_error_t error,
                                   const void *, libcouchbase_size_t,
                                   libcouchbase_cas_t cas)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        rv->error = error;
        rv->cas2 = cas;
        libcouchbase_io_opt_t *io = (libcouchbase_io_opt_t *)libcouchbase_get_cookie(instance);
        io->stop_event_loop(io);
    }

    static void df_get_callback(libcouchbase_t instance,
                                const void *cookie,
                                libcouchbase_error_t error,
                                const void *key, libcouchbase_size_t nkey,
                                const void *, libcouchbase_size_t,
                                libcouchbase_uint32_t, libcouchbase_cas_t cas)
    {
        struct rvbuf *rv = (struct rvbuf *)cookie;
        const char *value = "{\"bar\"=>1, \"baz\"=>2}";
        libcouchbase_size_t nvalue = strlen(value);
        libcouchbase_error_t err;

        rv->error = error;
        rv->cas1 = cas;
        err = libcouchbase_store(instance, rv, LIBCOUCHBASE_SET, key, nkey, value, nvalue, 0, 0, cas);
        ASSERT_EQ(LIBCOUCHBASE_SUCCESS, err);
    }
}

TEST_F(MockUnitTest, testDoubleFreeError)
{
    libcouchbase_error_t err;
    struct rvbuf rv;
    const char *key = "test_compare_and_swap_async_", *value = "{\"bar\" => 1}";
    libcouchbase_size_t nkey = strlen(key), nvalue = strlen(value);
    libcouchbase_io_opt_t *io;
    libcouchbase_t instance;

    createConnection(instance);
    io = (libcouchbase_io_opt_t *)libcouchbase_get_cookie(instance);

    /* prefill the bucket */
    (void)libcouchbase_set_storage_callback(instance, df_store_callback1);
    err = libcouchbase_store(instance, &rv, LIBCOUCHBASE_SET, key, nkey, value, nvalue, 0, 0, 0);
    ASSERT_EQ(LIBCOUCHBASE_SUCCESS, err);
    io->run_event_loop(io);
    ASSERT_EQ(LIBCOUCHBASE_SUCCESS, rv.error);

    /* run exercise
     *
     * 1. get the valueue and its cas
     * 2. atomic set new valueue using old cas
     */
    (void)libcouchbase_set_storage_callback(instance, df_store_callback2);
    (void)libcouchbase_set_get_callback(instance, df_get_callback);
    err = libcouchbase_mget(instance, &rv, 1, (const void * const *)&key, &nkey, NULL);
    ASSERT_EQ(LIBCOUCHBASE_SUCCESS, err);
    rv.cas1 = rv.cas2 = 0;
    io->run_event_loop(io);
    ASSERT_EQ(LIBCOUCHBASE_SUCCESS, rv.error);
    ASSERT_GT(rv.cas1, 0);
    ASSERT_GT(rv.cas2, 0);
    ASSERT_NE(rv.cas1, rv.cas2);
}
