/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2020 Couchbase, Inc.
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
#include "iotests.h"
#include "internal.h"
#include "bucketconfig/clconfig.h"
#include <cstdarg>
#include <cstdio>
#include <map>
#include <vector>

class ErrmapUnitTest : public MockUnitTest
{
  protected:
    virtual void createErrmapConnection(HandleWrap &hw, lcb_INSTANCE **instance)
    {
        MockEnvironment::getInstance()->createConnection(hw, instance);
        ASSERT_EQ(LCB_SUCCESS, lcb_connect(*instance));
        lcb_wait(*instance, LCB_WAIT_DEFAULT);
        ASSERT_EQ(LCB_SUCCESS, lcb_get_bootstrap_status(*instance));
    }

    void checkRetryVerify(uint16_t errcode);

    void TearDown()
    {
        if (!MockEnvironment::getInstance()->isRealCluster()) {
            MockOpFailClearCommand clearCmd(MockEnvironment::getInstance()->getNumNodes());
            doMockTxn(clearCmd);
        }
        MockUnitTest::TearDown();
    }
};

struct ResultCookie {
    lcb_STATUS rc;
    bool called;

    void reset()
    {
        rc = LCB_SUCCESS;
        called = false;
    }
    ResultCookie() : rc(LCB_SUCCESS), called(false) {}
};

extern "C" {
static void opcb(lcb_INSTANCE *, int, const lcb_RESPSTORE *resp)
{
    ResultCookie *cookie;
    lcb_respstore_cookie(resp, (void **)&cookie);
    cookie->called = true;
    cookie->rc = lcb_respstore_status(resp);
}
}

TEST_F(ErrmapUnitTest, hasRecognizedErrors)
{
    SKIP_UNLESS_MOCK();
    HandleWrap hw;
    lcb_INSTANCE *instance;

    createErrmapConnection(hw, &instance);

    // Test the actual error map..
    using namespace lcb;
    const errmap::ErrorMap &em = *instance->settings->errmap;
    const errmap::Error &err = em.getError(PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    ASSERT_TRUE(err.isValid());
    ASSERT_TRUE(err.hasAttribute(errmap::CONSTRAINT_FAILURE));
}

TEST_F(ErrmapUnitTest, closesOnUnrecognizedError)
{
    // For now, EINTERNAL is an error code we don't know!
    SKIP_UNLESS_MOCK();
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createErrmapConnection(hw, &instance);

    const char *key = "key";
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, key, strlen(key));
    lcb_cmdstore_value(scmd, "val", 3);

    ResultCookie cookie;
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)opcb);
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(LCB_SUCCESS, cookie.rc);

    MockCommand cmd(MockCommand::OPFAIL);

    // Determine the server
    int srvix = instance->map_key(key);

    cmd.set("server", srvix);
    cmd.set("code", PROTOCOL_BINARY_RESPONSE_EINTERNAL); // Invalidate the connection!
    cmd.set("count", 1);
    doMockTxn(cmd);

    cookie.reset();
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);

    ASSERT_TRUE(cookie.called);
    ASSERT_NE(LCB_SUCCESS, cookie.rc);

    cookie.reset();
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_TRUE(cookie.called);

    // Note, we can't determine what the actual error here is. It would be nice
    // if we were able to reconnect and retry the other commands, but right now
    // detecting a failed connection is better than having no detection at all:
    //
    // ASSERT_EQ(LCB_SUCCESS, cookie.rc);
    lcb_cmdstore_destroy(scmd);
}

// Server::handle_unknown_error used to have an inverted guard around `newerr`.
// When an errmap entry is tagged `conn-state-invalidated` and no earlier
// branch (TEMPORARY/AUTH/ITEM_LOCKED) populates `newerr`, the code is supposed
// to default it to LCB_ERR_GENERIC before calling lcbio_ctx_senderr() so the
// per-command completion surfaces a non-success status. The original code
// defaulted `newerr` to LCB_ERR_GENERIC only when it was already non-success,
// which meant the common case (EINTERNAL, whose errmap entry carries
// `internal` + `conn-state-invalidated` and no other populating attribute)
// propagated LCB_SUCCESS through the dispatch path.
//
// This test exercises the conn-state-invalidated-only branch deterministically
// on every platform regardless of how the real errmap evolves. It replaces the
// connected instance's errmap with one that maps 0x7ff0 (a mock-accepted code)
// to *only* the conn-state-invalidated attribute, then drives the mock via
// OPFAIL to return that code. ErrorMap::parse() uses std::map::insert() which
// does not overwrite existing entries, so the test frees and recreates the
// errmap before parsing.
TEST_F(ErrmapUnitTest, connStateInvalidatedPropagatesNonSuccessStatus)
{
    SKIP_UNLESS_MOCK();
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createErrmapConnection(hw, &instance);

    // Prime the connection with a successful store so the mock has a real
    // socket to target and so we're sure negotiation is complete before we
    // start injecting failures.
    const char *key = "cs-inv-only";
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, key, strlen(key));
    lcb_cmdstore_value(scmd, "val", 3);

    ResultCookie cookie;
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)opcb);
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(LCB_SUCCESS, cookie.rc);

    // Replace the instance's errmap entirely with one that maps a synthetic
    // code that the mock accepts (0x7ff0) to conn-state-invalidated only.
    const uint16_t synthetic_code = 0x7ff0;
    const char *synthetic_errmap_json =
        "{"
        "  \"version\": 1,"
        "  \"revision\": 1,"
        "  \"errors\": {"
        "    \"7FF0\": {"
        "      \"name\": \"CS_INV_ONLY\","
        "      \"desc\": \"synthetic conn-state-invalidated\","
        "      \"attrs\": [\"conn-state-invalidated\"]"
        "    }"
        "  }"
        "}";
    lcb_errmap_free(instance->settings->errmap);
    instance->settings->errmap = lcb_errmap_new();
    std::string errmsg;
    ASSERT_TRUE(instance->settings->errmap->parse(synthetic_errmap_json, strlen(synthetic_errmap_json), errmsg))
        << errmsg;

    // Sanity: the injected code carries only conn-state-invalidated.
    const lcb::errmap::Error &injected = instance->settings->errmap->getError(synthetic_code);
    ASSERT_TRUE(injected.isValid());
    ASSERT_TRUE(injected.hasAttribute(lcb::errmap::CONN_STATE_INVALIDATED));
    ASSERT_FALSE(injected.hasAttribute(lcb::errmap::TEMPORARY));
    ASSERT_FALSE(injected.hasAttribute(lcb::errmap::AUTH));
    ASSERT_FALSE(injected.hasAttribute(lcb::errmap::ITEM_LOCKED));
    ASSERT_FALSE(injected.hasAttribute(lcb::errmap::SPECIAL_HANDLING));
    ASSERT_FALSE(injected.hasAttribute(lcb::errmap::AUTO_RETRY));

    // Arrange for the mock to fail the next operation on this server with
    // the synthetic code.
    int srvix = instance->map_key(key);
    MockCommand cmd(MockCommand::OPFAIL);
    cmd.set("server", srvix);
    cmd.set("code", synthetic_code);
    cmd.set("count", 1);
    doMockTxn(cmd);

    // Issue the store that must hit our synthetic error. With the pre-fix
    // code this assertion fails: cookie.rc comes back as LCB_SUCCESS because
    // newerr was never populated and LCB_SUCCESS was carried through err_override
    // all the way to the operation callback. After the fix newerr is defaulted
    // to LCB_ERR_GENERIC and the callback sees a non-success rc.
    cookie.reset();
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_TRUE(cookie.called);
    ASSERT_NE(LCB_SUCCESS, cookie.rc);

    lcb_cmdstore_destroy(scmd);
}

// CCBC-1686: a conn-state-invalidated server error drives socket_failed ->
// purge(REFRESH_ALWAYS) -> lcb_st::bootstrap(BS_REFRESH_THROTTLE|BS_REFRESH_INCRERR).
// The CCCP provider reacts by scheduling a GET_CLUSTER_CONFIG packet against
// the errored server (or opening a fresh config-node socket). If the
// application then calls lcb_destroy() before that refresh drains, the
// pending cookie races instance teardown. On Windows IOCP the race reliably
// produces an access violation (0xc0000005) during destruction; on other
// platforms it is a latent use-after-free that does not always crash.
//
// This test reproduces the same destroy-during-refresh sequence
// deterministically on every platform by driving the conn-state-invalidated
// branch via the synthetic errmap path, then calling HandleWrap::destroy()
// explicitly rather than leaving it to the scope guard. We assert that the
// destroy call returns within a bounded wall-clock window (a hang here
// would indicate the IO loop is waiting on CCCP work that was never
// cancelled) and that no further operation callbacks fire after destroy.
//
// Linux iotests run under ASAN in most CI configurations, which turns any
// residual use-after-free from the pre-fix code path into a hard failure.
TEST_F(ErrmapUnitTest, destroyDuringConnStateInvalidatedRefreshIsSafe)
{
    SKIP_UNLESS_MOCK();
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createErrmapConnection(hw, &instance);

    // Prime the connection with a successful store so the mock socket is
    // negotiated and we know where the key maps.
    const char *key = "cs-inv-destroy";
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, key, strlen(key));
    lcb_cmdstore_value(scmd, "v", 1);

    ResultCookie cookie;
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)opcb);
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(LCB_SUCCESS, cookie.rc);

    // Replace the errmap so 0x7ff0 carries only conn-state-invalidated. The
    // mock accepts codes in the 0x7ff0 range for OPFAIL injection. See the
    // commentary in connStateInvalidatedPropagatesNonSuccessStatus for why
    // we free-and-recreate the errmap here rather than merging.
    const uint16_t synthetic_code = 0x7ff0;
    const char *synthetic_errmap_json =
        "{"
        "  \"version\": 1,"
        "  \"revision\": 1,"
        "  \"errors\": {"
        "    \"7FF0\": {"
        "      \"name\": \"CS_INV_ONLY\","
        "      \"desc\": \"synthetic conn-state-invalidated\","
        "      \"attrs\": [\"conn-state-invalidated\"]"
        "    }"
        "  }"
        "}";
    lcb_errmap_free(instance->settings->errmap);
    instance->settings->errmap = lcb_errmap_new();
    std::string errmsg;
    ASSERT_TRUE(instance->settings->errmap->parse(synthetic_errmap_json, strlen(synthetic_errmap_json), errmsg))
        << errmsg;

    // Inject the synthetic code on the next operation so the KV response
    // arrives tagged conn-state-invalidated.
    int srvix = instance->map_key(key);
    MockCommand cmd(MockCommand::OPFAIL);
    cmd.set("server", srvix);
    cmd.set("code", synthetic_code);
    cmd.set("count", 1);
    doMockTxn(cmd);

    cookie.reset();
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_TRUE(cookie.called);
    ASSERT_NE(LCB_SUCCESS, cookie.rc);

    lcb_cmdstore_destroy(scmd);

    // At this point the CCCP provider has, very likely, a bootstrap refresh
    // in flight (queued GET_CLUSTER_CONFIG on the errored server, or an
    // outstanding ConnectEx/TCP-connect to a config node). We now destroy
    // the instance explicitly, while the refresh would still be pending if
    // not properly cancelled. This exercises the destroy-while-refresh
    // sequence that manifests as an SEH on Windows IOCP runners.
    //
    // Reset the cookie to a freshly-sentinelled state and stash its
    // previous rc so that any stray post-destroy callback invocation
    // would overwrite the sentinel and fail the assertion below. Reaching
    // the ASSERT lines at all proves lcb_destroy() returned (no hang on
    // draining cancelled provider work); a clean ASAN/valgrind run proves
    // no use-after-free was reachable from the cancelled cookie.
    cookie.reset();
    cookie.rc = LCB_ERR_SDK_INTERNAL;

    hw.destroy();

    ASSERT_FALSE(cookie.called) << "operation callback fired after lcb_destroy returned";
    ASSERT_EQ(LCB_ERR_SDK_INTERNAL, cookie.rc) << "cookie memory was written after lcb_destroy returned";
}

// CCBC-1687: asserts that the "skip non-clean server in CCCP refresh" guard
// actually fires on the exact path that crashes on Windows/TLS/IOCP
// (CV2870). The race is: a conn-state-invalidated KV error drives
// Server::socket_failed(), which must flip the pipeline's state to
// S_ERRDRAIN BEFORE purge(REFRESH_ALWAYS) -> instance->bootstrap() ->
// CccpProvider::refresh() -> schedule_next_request() runs. The guard in
// schedule_next_request() rejects any find_server() result whose state is
// not S_CLEAN and falls through to opening a fresh CCCP connection via
// memd_sockpool, avoiding the use-after-free on the dying pipeline's
// lcbio_CTX.
//
// The fix has two parts and both must be in place for the guard to fire:
//   1. src/mcserver/mcserver.cc: Server::socket_failed() pre-flips
//      Server::state = S_ERRDRAIN before calling purge(REFRESH_ALWAYS).
//      Without this, state is still S_CLEAN inside
//      CccpProvider::schedule_next_request() when it runs synchronously
//      out of instance->bootstrap(), and the guard passes through.
//   2. src/bucketconfig/bc_cccp.cc: the guard itself in
//      schedule_next_request() that rejects non-clean servers returned
//      by find_server() and falls through to memd_sockpool->get().
//
// The assertion is observational: we install a custom logger via
// lcb_cntl(LCB_CNTL_LOGGER) and verify that the sentinel DEBUG line
// "Skipping server struct ... for CCCP refresh" appears in the captured
// output. A future regression that either undoes the pre-flip or removes
// the guard trips this test on every platform, not just IOCP.
//
// Determinism across IO plugins: the guard only fires when
// CccpProvider::schedule_next_request() picks the dying pipeline's host
// as `next_host` AND find_server(*next_host) returns that still-errored
// Server. On a default 4-node mock, Hostlist::next() may return any of
// the four nodes depending on internal ix state, and on synchronous IO
// plugins (select) start_errored_ctx() -> finalize_errored_ctx() flips
// the pipeline's state back to S_CLEAN within the same tick, collapsing
// the guard window. To make the assertion reliable across IOCP, select,
// and any future plugin, we replace the CCCP provider's nodes list with
// a single-entry list containing only the dying server's host before
// driving the failing store. Hostlist::assign() (called from
// CccpProvider::configure_nodes) resets the iterator, so the first
// nodes->next() returned during the post-error refresh is guaranteed to
// be the dying host, find_server() resolves to the pipeline we just
// flipped to S_ERRDRAIN, and the guard's state != S_CLEAN check fires.
//
// Timing note: lcb_wait() returns the moment the KV operation callback
// fires, but the socket_failed -> purge -> bootstrap chain is scheduled
// from the async timer armed by lcbio_ctx_senderr() and therefore does
// not run until the next event-loop tick. After the failing store's
// lcb_wait() we pump the loop explicitly with lcb_tick_nowait() so the
// capture logger has a chance to receive the sentinel before we assert
// on it. Without this pump the assertion race-fails on platforms whose
// event loops exit the moment the pending count reaches zero.
//
// The crash itself only manifests on IOCP (because the UAF requires an
// async completion firing against a freed ctx, which synchronous-send
// plugins never produce). The guard is still a correctness invariant
// everywhere, so this test is portable across the plugins CV2870
// reproduced on. The deterministic destroy-during-refresh reproducer is
// ErrmapUnitTest.destroyDuringConnStateInvalidatedRefreshIsSafe above;
// this test is the observational companion that specifically checks the
// guard's code path was exercised on the failing store's error flow.
namespace
{
struct CaptureLogger {
    CaptureLogger() : base(nullptr) {}
    lcb_LOGGER *base;
    std::vector< std::string > messages;

    bool contains(const std::string &needle) const
    {
        for (const std::string &m : messages) {
            if (m.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};
} // namespace

extern "C" {
static void capture_logger_cb(const lcb_LOGGER *logger, uint64_t, const char *, lcb_LOG_SEVERITY, const char *, int,
                              const char *fmt, va_list ap)
{
    char buf[4096];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    CaptureLogger *cookie = nullptr;
    lcb_logger_cookie(logger, reinterpret_cast< void ** >(&cookie));
    if (cookie != nullptr) {
        cookie->messages.emplace_back(buf);
    }
}
}

TEST_F(ErrmapUnitTest, refreshAfterConnStateInvalidatedSkipsErroredPipeline)
{
    SKIP_UNLESS_MOCK();
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createErrmapConnection(hw, &instance);

    // Prime the connection so negotiation is complete before we start
    // swapping the errmap and installing the capture logger.
    const char *key = "cs-inv-refresh";
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, key, strlen(key));
    lcb_cmdstore_value(scmd, "v", 1);

    ResultCookie cookie;
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)opcb);
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_EQ(LCB_SUCCESS, cookie.rc);

    // Replace the errmap so 0x7ff0 carries only conn-state-invalidated.
    // See the commentary in connStateInvalidatedPropagatesNonSuccessStatus
    // for why we free-and-recreate the errmap here rather than merging.
    const uint16_t synthetic_code = 0x7ff0;
    const char *synthetic_errmap_json =
        "{"
        "  \"version\": 1,"
        "  \"revision\": 1,"
        "  \"errors\": {"
        "    \"7FF0\": {"
        "      \"name\": \"CS_INV_ONLY\","
        "      \"desc\": \"synthetic conn-state-invalidated\","
        "      \"attrs\": [\"conn-state-invalidated\"]"
        "    }"
        "  }"
        "}";
    lcb_errmap_free(instance->settings->errmap);
    instance->settings->errmap = lcb_errmap_new();
    std::string errmsg;
    ASSERT_TRUE(instance->settings->errmap->parse(synthetic_errmap_json, strlen(synthetic_errmap_json), errmsg))
        << errmsg;

    // Identify the pipeline that is about to enter S_ERRDRAIN and override
    // the CCCP provider's nodes list so the post-error refresh is forced
    // to select that pipeline's host. Without this override, Hostlist::next()
    // may return any of the 4 mock nodes on the refresh that runs out of
    // socket_failed(), and on synchronous-IO plugins the dying pipeline's
    // state is already back to S_CLEAN by the time the iteration reaches
    // it. See the comment block above this test for the full rationale.
    int srvix = instance->map_key(key);
    lcb::Server *dying = instance->get_server(srvix);
    ASSERT_NE(nullptr, dying);
    lcb::Hostlist single;
    single.add(dying->get_host());
    lcb::clconfig::Provider *cccp = instance->confmon->get_provider(lcb::clconfig::CLCONFIG_CCCP);
    ASSERT_NE(nullptr, cccp);
    cccp->configure_nodes(single);

    // Disable the Bootstrap::bootstrap() error-counter throttle for this
    // test. Server::purge(REFRESH_ALWAYS) triggers an immediate
    // bootstrap(BS_REFRESH_THROTTLE | BS_REFRESH_INCRERR) synchronously out
    // of socket_failed(). With the default error threshold of 100 and the
    // 10ms weird_things_delay, the first refresh after the KV error is
    // silently dropped if the primer's post-connect bootstrap set
    // last_refresh within the last 10ms -- which it does consistently on
    // fast local mocks. The throttle's return-without-calling-
    // schedule_next_request branch means the guard never runs at a moment
    // when the dying pipeline is still in S_ERRDRAIN; by the time a later
    // refresh fires, start_errored_ctx() -> finalize_errored_ctx() has
    // already reset state to S_CLEAN. Setting the threshold to 1 makes the
    // throttle's `errcounter < errthresh` check fall through after the
    // very first BS_REFRESH_INCRERR, so the synchronous refresh from
    // socket_failed() runs schedule_next_request() with the pipeline's
    // state still at S_ERRDRAIN. Only schedule_next_request() emits the
    // sentinel we assert on.
    std::size_t errthresh_override = 1;
    ASSERT_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_CONFERRTHRESH, &errthresh_override));

    // Install the capture logger now that negotiation is done. We do not
    // care about connect/bootstrap chatter; we only want to observe the
    // CCCP provider's behaviour during the post-error refresh. User
    // loggers receive every severity level regardless of the console
    // minlevel filter, so the DEBUG-level sentinel line will be delivered.
    CaptureLogger cap;
    ASSERT_EQ(LCB_SUCCESS, lcb_logger_create(&cap.base, &cap));
    ASSERT_EQ(LCB_SUCCESS, lcb_logger_callback(cap.base, capture_logger_cb));
    ASSERT_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_LOGGER, cap.base));

    // Arrange for the mock to fail the next operation on the target server
    // with the synthetic code.
    MockCommand cmd(MockCommand::OPFAIL);
    cmd.set("server", srvix);
    cmd.set("code", synthetic_code);
    cmd.set("count", 1);
    doMockTxn(cmd);

    // Issue the store that triggers the disconnect. The library path is:
    //   try_read -> Server::handle_unknown_error (ERRMAP_ACTION_DISCONN)
    //     -> operation callback dispatched synchronously (cookie fires)
    //     -> lcbio_ctx_senderr: async_signal(ctx->as_err)
    //   lcb_wait() returns here because pending count is zero.
    //
    //   Next event-loop tick (driven by lcb_tick_nowait below):
    //     on_error -> Server::socket_failed
    //       state = S_ERRDRAIN                        [pre-flip]
    //       purge(REFRESH_ALWAYS)
    //         -> instance->bootstrap(BS_REFRESH_THROTTLE|BS_REFRESH_INCRERR)
    //              -> CccpProvider::refresh
    //                   -> schedule_next_request
    //                        [guard sees state != S_CLEAN, logs
    //                         "Skipping server struct ..." and falls
    //                         through to memd_sockpool->get()]
    //       start_errored_ctx(S_ERRDRAIN)             [drain / finalize]
    cookie.reset();
    ASSERT_EQ(LCB_SUCCESS, lcb_store(instance, &cookie, scmd));
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_TRUE(cookie.called);
    ASSERT_NE(LCB_SUCCESS, cookie.rc);

    // Pump the event loop so the async on_error -> socket_failed ->
    // purge -> bootstrap chain runs while the capture logger is still
    // installed. We iterate up to a bounded number of ticks and break
    // as soon as the sentinel has been observed so the test stays
    // fast in the happy case. Both the select and iocp IO plugins
    // implement the tick entry, so this loop is portable across the
    // platforms CV2870 reproduced on.
    for (int ii = 0; ii < 50 && !cap.contains("Skipping server struct"); ++ii) {
        ASSERT_EQ(LCB_SUCCESS, lcb_tick_nowait(instance));
    }

    // The sentinel line only appears when the guard fires, which only
    // happens when (a) socket_failed pre-flips state before calling
    // purge, and (b) schedule_next_request rejects non-clean servers. If
    // either part of the fix regresses, this assertion fails and points
    // directly at the hazard that caused the CV2870 SEHs.
    EXPECT_TRUE(cap.contains("Skipping server struct"))
        << "CCCP refresh guard (CCBC-1687) did not fire during socket_failed -> "
           "purge -> bootstrap. Either Server::socket_failed no longer pre-flips "
           "state to S_ERRDRAIN, or CccpProvider::schedule_next_request no longer "
           "rejects non-clean servers. Captured log lines: "
        << cap.messages.size();

    lcb_cmdstore_destroy(scmd);

    // Tear the instance down before the capture logger so that any
    // destroy-time log messages cannot re-enter cap after it goes out of
    // scope. Then destroy the logger object itself.
    hw.destroy();
    lcb_logger_destroy(cap.base);
}

void ErrmapUnitTest::checkRetryVerify(uint16_t errcode)
{
    HandleWrap hw;
    lcb_INSTANCE *instance;
    createErrmapConnection(hw, &instance);
    lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)opcb);

    ResultCookie cookie;

    std::string key("hello");
    lcb_CMDSTORE *scmd;
    lcb_cmdstore_create(&scmd, LCB_STORE_UPSERT);
    lcb_cmdstore_key(scmd, key.c_str(), key.size());
    lcb_cmdstore_value(scmd, "val", 3);

    // Store the item once to ensure the server is actually connected
    // (we don't want opfail to be active during negotiation).
    lcb_store(instance, &cookie, scmd);
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    ASSERT_TRUE(cookie.called);
    ASSERT_EQ(LCB_SUCCESS, cookie.rc);

    // Figure out the server this key belongs to.
    int srvix = instance->map_key(key);

    MockCommand cmd(MockCommand::START_RETRY_VERIFY);
    cmd.set("idx", srvix);
    cmd.set("bucket", instance->get_bucketname());
    doMockTxn(cmd);

    // Set up opfail
    MockOpfailCommand failCmd(errcode, srvix, -1, instance->get_bucketname());
    doMockTxn(failCmd);

    // Run the command!
    cookie.reset();
    lcb_STATUS rc = lcb_store(instance, &cookie, scmd);
    ASSERT_EQ(LCB_SUCCESS, rc);
    lcb_wait(instance, LCB_WAIT_DEFAULT);

    ASSERT_TRUE(cookie.called);
    ASSERT_EQ(LCB_ERR_TEMPORARY_FAILURE, cookie.rc);

    // Check that we executed correctly:
    MockBucketCommand verifyCmd(MockCommand::CHECK_RETRY_VERIFY, srvix, instance->get_bucketname());
    verifyCmd.set("opcode", PROTOCOL_BINARY_CMD_SET);
    verifyCmd.set("errcode", errcode);
    /*
     * The mock's errmap verifier measures the actual gap between
     * successive lcb retries and raises VerificationException if any
     * gap differs from the spec by more than fuzz_ms. On Apple this
     * has been bumped twice now: first to 35 ms to absorb scheduler
     * noise on Jenkins Intel macOS (the original flake recorded a
     * 24 ms diff with the old 20 ms cap), and now further on Apple
     * Silicon Jenkins runners where cv-3125 reproduced a 41 ms diff
     * (a single gap of 51 ms against a 10 ms spec) inside an
     * otherwise well-behaved 28-retry sequence. The pattern is the
     * runner pausing the lcb event loop briefly, not lcb
     * misbehaving. CI Apple runners get a wider tolerance via
     * running_under_ci() because shared/loaded VMs are where the
     * long pauses actually appear; local Apple machines stay at
     * 60 ms (still well above the earlier 35 ms threshold).
     */
#ifdef __APPLE__
    verifyCmd.set("fuzz_ms", running_under_ci() ? 150 : 60);
#else
    verifyCmd.set("fuzz_ms", running_under_ci() ? 80 : 20);
#endif
    doMockTxn(verifyCmd);
    lcb_cmdstore_destroy(scmd);
}

static const uint16_t ERRCODE_CONSTANT = 0x7ff0;
static const uint16_t ERRCODE_LINEAR = 0x7ff1;
static const uint16_t ERRCODE_EXPONENTIAL = 0x7ff2;

TEST_F(ErrmapUnitTest, retrySpecConstant)
{
    SKIP_UNLESS_MOCK();
    checkRetryVerify(ERRCODE_CONSTANT);
}

TEST_F(ErrmapUnitTest, retrySpecLinear)
{
    SKIP_UNLESS_MOCK();
    checkRetryVerify(ERRCODE_LINEAR);
}

TEST_F(ErrmapUnitTest, retrySpecExponential)
{
    SKIP_UNLESS_MOCK();
    checkRetryVerify(ERRCODE_EXPONENTIAL);
}
