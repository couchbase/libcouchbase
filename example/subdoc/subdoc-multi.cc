#define LCB_NO_DEPR_CXX_CTORS
#undef NDEBUG

#include <libcouchbase/couchbase.h>
#include <libcouchbase/api3.h>
#include <assert.h>
#include <string.h>

static void generic_callback(lcb_t, int type, const lcb_RESPBASE *rb)
{
    printf("Got callback for %s\n", lcb_strcbtype(type));

    if (rb->rc != LCB_SUCCESS && rb->rc != LCB_SUBDOC_MULTI_FAILURE) {
        printf("Failure: 0x%x\n", rb->rc);
        abort();
    }

    if (type == LCB_CALLBACK_GET) {
        const lcb_RESPGET *rg = (const lcb_RESPGET *)rb;
        printf("Result is: %.*s\n", (int)rg->nvalue, rg->value);
    }

    if (type == LCB_CALLBACK_SDMLOOKUP) {
        size_t iter = 0;
        int pos = 0;
        const lcb_RESPSDMLOOKUP *rml = (const lcb_RESPSDMLOOKUP*)rb;
        lcb_SDMULTI_ENTRY cur = { NULL };
        printf("Dumping multi results...\n");
        while ((lcb_sdmlookup_next(rml, &cur, &iter))) {
            printf("[%d]: 0x%x. %.*s\n",
                pos++, cur.status, (int)cur.nvalue, cur.value);
        }
    }
}

// cluster_run mode
#define DEFAULT_CONNSTR "couchbase://localhost:12000"

int main(int argc, char **argv) {
    lcb_create_st crst = { 0 };
    crst.version = 3;
    if (argc > 1) {
        crst.v.v3.connstr = argv[1];
    } else {
        crst.v.v3.connstr = DEFAULT_CONNSTR;
    }

    lcb_t instance;
    lcb_error_t rc = lcb_create(&instance, &crst);
    assert(rc == LCB_SUCCESS);

    rc = lcb_connect(instance);
    assert(rc == LCB_SUCCESS);
    lcb_wait(instance);
    rc = lcb_get_bootstrap_status(instance);
    assert(rc == LCB_SUCCESS);

    // Install generic callback
    lcb_install_callback3(instance, LCB_CALLBACK_DEFAULT, generic_callback);

    // Store an item
    lcb_CMDSTORE scmd = { 0 };
    scmd.operation = LCB_SET;
    LCB_CMD_SET_KEY(&scmd, "key", 3);
    const char *initval = "{\"hello\":\"world\"}";
    LCB_CMD_SET_VALUE(&scmd, initval, strlen(initval));
    lcb_sched_enter(instance);
    rc = lcb_store3(instance, NULL, &scmd);
    assert(rc == LCB_SUCCESS);

    lcb_CMDSDMULTI mcmd = { 0 };
    LCB_CMD_SET_KEY(&mcmd, "key", 3);
    mcmd.multimode = LCB_SDMULTI_MODE_MUTATE;
    lcb_SDMULTICTX *sctx = lcb_sdmultictx_new(instance, NULL, &mcmd, &rc);
    assert(sctx != NULL);

    // Add some mutations
    for (int ii = 0; ii < 5; ii++) {
        char pbuf[24];
        char vbuf[24];
        size_t np = sprintf(pbuf, "pth%d", ii);
        size_t nv = sprintf(vbuf, "\"Value_%d\"", ii);

        lcb_CMDSDSTORE sdstore = { 0 };
        LCB_SDCMD_SET_PATH(&sdstore, pbuf, np);
        LCB_CMD_SET_VALUE(&sdstore, vbuf, nv);
        rc = lcb_sdmultictx_addcmd(sctx, LCB_SUBDOC_DICT_UPSERT, (const lcb_CMDSDBASE*)&sdstore);
        assert(rc == LCB_SUCCESS);
    }
    rc = lcb_sdmultictx_done(sctx);
    assert(rc == LCB_SUCCESS);

    mcmd.multimode = LCB_SDMULTI_MODE_LOOKUP;
    sctx = lcb_sdmultictx_new(instance, NULL, &mcmd, &rc);
    assert(sctx != NULL);
    for (int ii = 0; ii < 5; ii++) {
        char pbuf[24];
        size_t np = sprintf(pbuf, "pth%d", ii);
        lcb_CMDSDGET sdget = { 0 };
        LCB_SDCMD_SET_PATH(&sdget, pbuf, np);
        rc = lcb_sdmultictx_addcmd(sctx, LCB_SUBDOC_GET, (const lcb_CMDSDBASE*)&sdget);
        assert(rc == LCB_SUCCESS);
    }

    lcb_CMDSDGET get2 = { 0 };
    LCB_SDCMD_SET_PATH(&get2, "dummy", 5);
    rc = lcb_sdmultictx_addcmd(sctx, LCB_SUBDOC_GET, (const lcb_CMDSDBASE*)&get2);
    assert(rc == LCB_SUCCESS);

    LCB_SDCMD_SET_PATH(&get2, "hello", 5);
    rc = lcb_sdmultictx_addcmd(sctx, LCB_SUBDOC_GET, (const lcb_CMDSDBASE*)&get2);
    assert(rc == LCB_SUCCESS);

    rc = lcb_sdmultictx_done(sctx);
    assert(rc == LCB_SUCCESS);

    lcb_CMDGET gcmd = { 0 };
    LCB_CMD_SET_KEY(&gcmd, "key", 3);
    rc = lcb_get3(instance, NULL, &gcmd);
    assert(rc == LCB_SUCCESS);

    lcb_sched_leave(instance);
    lcb_wait(instance);

    lcb_destroy(instance);
}
