#include "config.h"
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#include "mock-environment.h"
#include "internal.h"
#include "bucketconfig/clconfig.h"

class Confmon : public ::testing::Test
{
};

struct evstop_listener {
    clconfig_listener base;
    lcb_io_opt_t io;
    int called;
};

extern "C" {
static void listen_callback1(clconfig_info *info, clconfig_listener *lsn)
{
    evstop_listener *me = reinterpret_cast<evstop_listener*>(lsn);
    me->called = 1;
    me->io->v.v0.stop_event_loop(me->io);
}
}

TEST_F(Confmon, testBasic)
{
    HandleWrap hw;
    lcb_t instance;
    MockEnvironment::getInstance()->createConnection(hw, instance);


    lcb_confmon *mon = lcb_confmon_create(&instance->settings);
    lcb_confmon_set_nodes(mon, instance->usernodes, NULL);
    lcb_confmon_prepare(mon);

    EXPECT_EQ(NULL, lcb_confmon_get_config(mon));
    EXPECT_EQ(LCB_SUCCESS, lcb_confmon_start(mon));
    EXPECT_EQ(LCB_SUCCESS, lcb_confmon_start(mon));
    EXPECT_EQ(LCB_SUCCESS, lcb_confmon_stop(mon));
    EXPECT_EQ(LCB_SUCCESS, lcb_confmon_stop(mon));

    // Try to find a provider..
    clconfig_provider *provider = lcb_confmon_get_provider(mon, LCB_CLCONFIG_HTTP);
    ASSERT_NE(0, provider->enabled);

    struct evstop_listener listener;
    memset(&listener, 0, sizeof(listener));

    listener.base.callback = listen_callback1;
    listener.base.parent = mon;
    listener.io = hw.getIo();

    lcb_confmon_add_listener(mon, &listener.base);
    lcb_confmon_start(mon);
    hw.getIo()->v.v0.run_event_loop(hw.getIo());

    ASSERT_NE(0, listener.called);

    lcb_confmon_destroy(mon);
}
