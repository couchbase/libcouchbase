#define LCB_NO_DEPR_CXX_CTORS
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <libcouchbase/couchbase.h>
#include <libcouchbase/api3.h>
#include <string>

extern "C" {
static void opCallback(lcb_t, int type, const lcb_RESPBASE *rb) {
    int is_respget = 0;
    const char *msginfo = NULL;

    if (rb->rc != LCB_SUCCESS) {
        fprintf(stderr, "Operation failed (Type=%d. Code=0x%x [%s])\n",
            type, rb->rc, lcb_strerror(NULL, rb->rc));
        return;
    }

    if (type == LCB_CALLBACK_SDGET) {
        msginfo = "Got subdoc section";
        is_respget = 1;
    } else if (type == LCB_CALLBACK_SDCOUNTER) {
        msginfo = "Got new counter value";
        is_respget = 1;
    } else if (type == LCB_CALLBACK_GET) {
        msginfo = "Got entire document";
        is_respget = 1;
    }

    if (is_respget) {
        fprintf(stderr, "%s\n", msginfo);
        const lcb_RESPGET *rg = (const lcb_RESPGET*)rb;
        printf("%.*s\n", (int)rg->nvalue, rg->value);
    } else {
        fprintf(stderr, "Operation (%d) completed ok!\n", type);
    }
}
}

int main(int argc, const char **argv) {
    lcb_create_st cropts = { 0 };
    lcb_t instance;
    cropts.version = 3;
    cropts.v.v3.connstr = argc > 1 ? argv[1] : "couchbase://localhost:12000/default";
    lcb_error_t rc = lcb_create(&instance, &cropts);
    assert(rc == LCB_SUCCESS);
    rc = lcb_connect(instance);
    assert(rc == LCB_SUCCESS);
    lcb_wait(instance);
    rc = lcb_get_bootstrap_status(instance);
    assert(rc == LCB_SUCCESS);

    lcb_install_callback3(instance, LCB_CALLBACK_DEFAULT, opCallback);

    std::string value("{\"first\":\"field\"}");
    lcb_CMDSTORE doc_store_cmd = { 0 };
    LCB_CMD_SET_KEY(&doc_store_cmd, "doc", 3);
    LCB_CMD_SET_VALUE(&doc_store_cmd, value.c_str(), value.size());
    doc_store_cmd.operation = LCB_SET;
    lcb_sched_enter(instance);

    rc = lcb_store3(instance, NULL, &doc_store_cmd);
    assert(rc == LCB_SUCCESS);

    lcb_CMDSDGET cmd_sdget = { 0 };
    LCB_CMD_SET_KEY(&cmd_sdget, "doc", 3);
    LCB_SDCMD_SET_PATH(&cmd_sdget, "first", strlen("first"));
    rc = lcb_sdget3(instance, NULL, &cmd_sdget);

    lcb_CMDSDSTORE cmd_sdstore = { 0 };
    LCB_CMD_SET_KEY(&cmd_sdstore, "doc", 3);
    LCB_SDCMD_SET_PATH(&cmd_sdstore, "second", strlen("second"));
    LCB_CMD_SET_VALUE(&cmd_sdstore, "\"another\"", strlen("\"another\""));
    cmd_sdstore.mode = LCB_SUBDOC_DICT_ADD;

    rc = lcb_sdstore3(instance, NULL, &cmd_sdstore);
    assert(rc == LCB_SUCCESS);

    lcb_CMDSDEXISTS cmd_exists = { 0 };
    LCB_CMD_SET_KEY(&cmd_exists, "doc", 3);
    LCB_SDCMD_SET_PATH(&cmd_exists, "first", strlen("first"));
    rc = lcb_sdexists3(instance, NULL, &cmd_exists);
    assert(rc == LCB_SUCCESS);

    lcb_CMDSDCOUNTER cmd_counter = { 0 };
    LCB_CMD_SET_KEY(&cmd_counter, "doc", 3);
    LCB_SDCMD_SET_PATH(&cmd_counter, "path.to.counter", strlen("path.to.counter"));
    cmd_counter.delta = 42;
    cmd_counter.cmdflags |= LCB_CMDSUBDOC_F_MKINTERMEDIATES;
    rc = lcb_sdcounter3(instance, NULL, &cmd_counter);
    assert(rc == LCB_SUCCESS);

    cmd_counter.delta = -100;
    rc = lcb_sdcounter3(instance, NULL, &cmd_counter);
    assert(rc == LCB_SUCCESS);

    /* Create an array */
    memset(&cmd_sdstore, 0, sizeof cmd_sdstore);
    LCB_CMD_SET_KEY(&cmd_sdstore, "doc", 3);
    LCB_SDCMD_SET_PATH(&cmd_sdstore, "some.list", strlen("some.list"));
    LCB_CMD_SET_VALUE(&cmd_sdstore, "\"first_element\"", strlen("\"first_element\""));
    cmd_sdstore.cmdflags = LCB_CMDSUBDOC_F_MKINTERMEDIATES;
    cmd_sdstore.mode = LCB_SUBDOC_ARRAY_ADD_FIRST;
    rc = lcb_sdstore3(instance, NULL, &cmd_sdstore);
    assert(rc == LCB_SUCCESS);


    LCB_CMD_SET_VALUE(&cmd_sdstore, "\"second_element\"", strlen("\"second_element\""));
    cmd_sdstore.cmdflags = 0;
    cmd_sdstore.mode = LCB_SUBDOC_ARRAY_ADD_LAST;
    rc = lcb_sdstore3(instance, NULL, &cmd_sdstore);
    assert(rc == LCB_SUCCESS);


    lcb_CMDGET cmd_get_all = { 0 };
    LCB_CMD_SET_KEY(&cmd_get_all, "doc", 3);
    rc = lcb_get3(instance, NULL, &cmd_get_all);

    lcb_sched_leave(instance);
    lcb_wait(instance);

    lcb_destroy(instance);
    return 0;
}
