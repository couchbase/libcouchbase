#define LCB_NO_DEPR_CXX_CTORS
#undef NDEBUG

#include <libcouchbase/couchbase.h>
#include <libcouchbase/api3.h>
#include <assert.h>
#include <string.h>

static void
op_callback(lcb_t, int cbtype, const lcb_RESPBASE *rb)
{
    fprintf(stderr, "Got callback for %s.. ", lcb_strcbtype(cbtype));
    if (rb->rc != LCB_SUCCESS) {
        fprintf(stderr, "Operation failed (%s)\n", lcb_strerror(NULL, rb->rc));
        return;
    }

    if (cbtype == LCB_CALLBACK_SDGET ||
            cbtype == LCB_CALLBACK_GET ||
            cbtype == LCB_CALLBACK_SDCOUNTER) {
        const lcb_RESPGET *rg = reinterpret_cast<const lcb_RESPGET*>(rb);
        fprintf(stderr, "Value %.*s\n", (int)rg->nvalue, rg->value);
    } else {
        fprintf(stderr, "OK\n");
    }
}

// cluster_run mode
#define DEFAULT_CONNSTR "couchbase://localhost:12000"
int main(int argc, char **argv)
{
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

    lcb_install_callback3(instance, LCB_CALLBACK_DEFAULT, op_callback);

    printf("Storing the initial item..\n");
    // Store an item
    lcb_CMDSTORE scmd = { 0 };
    scmd.operation = LCB_SET;
    LCB_CMD_SET_KEY(&scmd, "key", 3);
    const char *initval = "{\"hello\":\"world\"}";
    LCB_CMD_SET_VALUE(&scmd, initval, strlen(initval));
    lcb_sched_enter(instance);
    rc = lcb_store3(instance, NULL, &scmd);
    assert(rc == LCB_SUCCESS);

    printf("Getting the 'hello' path from the document\n");
    lcb_CMDSDGET sdgcmd = { 0 };
    LCB_CMD_SET_KEY(&sdgcmd, "key", 3);
    LCB_SDCMD_SET_PATH(&sdgcmd, "hello", 5);
    lcb_sched_enter(instance);
    rc = lcb_sdget3(instance, NULL, &sdgcmd);
    assert(rc == LCB_SUCCESS);
    lcb_sched_leave(instance);
    lcb_wait(instance);

    printf("Adding new 'goodbye' path to document\n");
    lcb_CMDSDSTORE sdscmd = { 0 };
    LCB_CMD_SET_KEY(&sdscmd, "key", 3);
    LCB_SDCMD_SET_PATH(&sdscmd, "goodbye", 7);
    LCB_CMD_SET_VALUE(&sdscmd, "\"world\"", 7);
    sdscmd.mode = LCB_SUBDOC_DICT_ADD;
    lcb_sched_enter(instance);
    rc = lcb_sdstore3(instance, NULL, &sdscmd);
    assert(rc == LCB_SUCCESS);
    lcb_sched_leave(instance);
    lcb_wait(instance);

    printf("Getting entire document..\n");
    // Perform the get after the store
    lcb_CMDGET gcmd = { 0 };
    LCB_CMD_SET_KEY(&gcmd, "key", 3);
    lcb_sched_enter(instance);
    rc = lcb_get3(instance, NULL, &gcmd);
    assert(rc == LCB_SUCCESS);
    lcb_sched_leave(instance);
    lcb_wait(instance);

    printf("Appending element to array (array might be missing)\n");
    // Add an array
    LCB_SDCMD_SET_PATH(&sdscmd, "array", 5);
    LCB_CMD_SET_VALUE(&sdscmd, "1", 1);
    // Create the parent array, since it does not exist
    sdscmd.cmdflags |= LCB_CMDSUBDOC_F_MKINTERMEDIATES;
    sdscmd.mode = LCB_SUBDOC_ARRAY_ADD_LAST;
    lcb_sched_enter(instance);
    rc = lcb_sdstore3(instance, NULL, &sdscmd);
    assert(rc == LCB_SUCCESS);
    lcb_sched_leave(instance);
    lcb_wait(instance);

    printf("Getting entire document...\n");
    lcb_sched_enter(instance);
    rc = lcb_get3(instance, NULL, &gcmd);
    assert(rc == LCB_SUCCESS);
    lcb_wait(instance);

    printf("Appending another element to array (array must exist)\n");
    sdscmd.cmdflags = 0;
    LCB_CMD_SET_VALUE(&sdscmd, "2", 1);
    lcb_sched_enter(instance);
    rc = lcb_sdstore3(instance, NULL, &sdscmd);
    lcb_sched_leave(instance);
    lcb_wait(instance);

    printf("Getting first array element...\n");
    LCB_SDCMD_SET_PATH(&sdgcmd, "array[0]", strlen("array[0]"));
    lcb_sched_enter(instance);
    rc = lcb_sdget3(instance, NULL, &sdgcmd);
    assert(rc == LCB_SUCCESS);
    lcb_sched_leave(instance);
    lcb_wait(instance);

    lcb_destroy(instance);
    return 0;
}
