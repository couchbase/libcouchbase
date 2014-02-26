#include "config.h"
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#include "mock-environment.h"
#include "internal.h"
#include "connmgr.h"

class Connmgr : public ::testing::Test
{
};

struct MyRequest : connmgr_request_st {
    lcb_connection_st myconn;
    lcb_iotable *io;
};

extern "C" {
static void io_error(lcbconn_t)
{
}
static void io_read(lcbconn_t)
{
}

static void mgr_callback(connmgr_request *reqbase)
{
    MyRequest *req = reinterpret_cast<MyRequest *>(reqbase);
    struct lcb_io_use_st use;
    lcbconn_use_easy(&use, req, io_read, io_error);
    lcbconn_transfer(reqbase->conn, &req->myconn, &use);
    IOT_STOP(req->io);
}
}


TEST_F(Connmgr, testBasic)
{
    HandleWrap hw;
    lcb_t instance;
    MockEnvironment *mock = MockEnvironment::getInstance();
    lcb_create_st crst;
    mock->createConnection(hw, instance);
    mock->makeConnectParams(crst, NULL);

    connmgr_t* mgr = connmgr_create(&instance->settings,
                                    instance->settings.io);
    mgr->idle_timeout = 10;
    mgr->max_idle = 1;
    mgr->max_total = 1;

    /** Get a basic connection to the mock's REST port */
    MyRequest req;
    memset(&req, 0, sizeof(req));

    req.io = instance->settings.io;
    req.callback = mgr_callback;
    strcpy(req.key, crst.v.v2.host);
    connmgr_get(mgr, &req, 2000000);
    IOT_START(mgr->io);

    ASSERT_EQ(LCBCONN_S_CONNECTED, req.myconn.state);
    /** Release the connection.. */
    connmgr_put(mgr, &req.myconn);

    ASSERT_EQ(1, req.he->n_total);
    ASSERT_EQ(0, req.he->n_leased);
    ASSERT_FALSE(LCB_CLIST_SIZE(&req.he->ll_idle) == 0);
    ASSERT_TRUE(LCB_CLIST_SIZE(&req.he->requests) == 0);
    connmgr_destroy(mgr);
}

TEST_F(Connmgr, testDiscard)
{

}
