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

#include "socktest.h"

/* The stall is produced by interposing getaddrinfo(), which needs RTLD_NEXT. */
#if defined(__linux__) && defined(__GLIBC__)
#include <dlfcn.h>
#include <netdb.h>
#include <unistd.h>
#define LCB_TEST_CAN_STALL_RESOLVER 1
#endif

using namespace LCBTest;

class SockPoolConnectTest : public SockTest
{
};

#ifdef LCB_TEST_CAN_STALL_RESOLVER

namespace
{

/** Stops the loop once dispatched, bounding the pass driven from the stall. */
class LoopStopper : public Timer
{
  public:
    explicit LoopStopper(lcbio_TABLE *iot) : Timer(iot), iot_(iot) {}
    void expired() override
    {
        IOT_STOP(iot_);
    }

  private:
    lcbio_TABLE *iot_;
};

/** Armed for a single lookup by the test; NULL leaves getaddrinfo() alone. */
lcbio_TABLE *stall_iot = nullptr;
unsigned stall_us = 0;
bool stall_ran = false;

struct ConnResult {
    unsigned calls{0};
    lcb_STATUS last{LCB_SUCCESS};
};

class CalledBreakCondition : public BreakCondition
{
  public:
    explicit CalledBreakCondition(const ConnResult *res) : res_(res) {}

  protected:
    bool shouldBreakImpl() override
    {
        return res_->calls > 0;
    }

  private:
    const ConnResult *res_;
};

} // namespace

extern "C" {

/* Interposes over the C library for this test binary. A caller of
 * lcbio_connect() resolves through here; while the "resolver" is busy the same
 * event loop is turned, which is what the application's polling thread does in
 * the field. */
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    using gai_fn = int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
    static gai_fn real = nullptr;
    if (real == nullptr) {
        real = reinterpret_cast<gai_fn>(dlsym(RTLD_NEXT, "getaddrinfo"));
    }

    lcbio_TABLE *iot = stall_iot;
    if (iot != nullptr) {
        stall_iot = nullptr;
        stall_ran = true;
        /* Outlive the connect timeout, so the timer lcbio_connect() may have
         * armed is already due, then turn the loop over what is due. The
         * stopper is scheduled into the future so anything already overdue is
         * dispatched ahead of it. */
        usleep(stall_us);
        LoopStopper stopper(iot);
        stopper.schedule(5);
        IOT_START(iot);
    }
    return real(node, service, hints, res);
}

static void poolconnect_cb(lcbio_SOCKET *, void *arg, lcb_STATUS err, lcbio_OSERR)
{
    auto *res = reinterpret_cast<ConnResult *>(arg);
    res->calls++;
    res->last = err;
}
}

/**
 * A pool entry must be linked into PoolHost::ll_pending, and lcbio_connect()
 * must not have armed a timer, before the connect is started. Otherwise a turn
 * of the event loop taken while getaddrinfo() is resolving dispatches
 * Connstart::handler() into PoolConnInfo::on_connected(), which unlinks an
 * entry that was never linked and writes through its uninitialised list node.
 */
TEST_F(SockPoolConnectTest, testEntryUsableWhenLoopTurnsDuringResolve)
{
    lcb_host_t host = {"", "", 0};
    loop->populateHost(&host);

    ConnResult res;
    stall_us = 20000; /* 20ms, well past the 1ms connect timeout below */
    stall_ran = false;
    stall_iot = loop->iot;

    lcb::io::ConnectionRequest *req = loop->sockpool->get(host, LCB_MS2US(1), poolconnect_cb, &res);
    ASSERT_FALSE(req == NULL);

    /* Without this the run proves nothing: a passthrough resolve never turns
     * the loop, and the entry is never exposed. */
    ASSERT_TRUE(stall_ran);

    CalledBreakCondition bc(&res);
    loop->setBreakCondition(&bc);
    loop->start();

    /* Whether the connect beats the 1ms timeout is up to the host, but the
     * request must complete exactly once and the pool must still be intact. */
    ASSERT_EQ(1, res.calls);
}

#endif /* LCB_TEST_CAN_STALL_RESOLVER */
