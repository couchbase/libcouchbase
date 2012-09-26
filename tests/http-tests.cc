/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"
#include "mock-unit-test.h"
#include "server.h"

#define DESIGN_DOC_NAME "lcb_design_doc"
#define VIEW_NAME "lcb-test-view"

class HttpUnitTest : public MockUnitTest
{
};

class HttpCmdContext
{
public:
    HttpCmdContext() { }
    bool received;
    lcb_http_status_t status;
    lcb_error_t err;
    std::string body;
};

static const char *view_common =
    "{ "
    " \"id\" : \"_design/" DESIGN_DOC_NAME "\","
    " \"language\" : \"javascript\","
    " \"views\" : { "
    " \"" VIEW_NAME "\" : {"
    "\"map\":"
    " \"function(doc) { "
    "if (doc.testid == 'lcb') { emit(doc.id) } "
    " } \" "
    " } "
    "}"
    "}";

#define SKIP_IF_MOCK()                                                  \
    if (!getenv(LCB_TEST_REALCLUSTER_ENV)) {                            \
        fprintf(stderr, "Skipping %s: Need real cluster\n", __func__);  \
        return;                                                         \
    }

static void dumpResponse(const lcb_http_resp_t *resp)
{
    if (resp->v.v0.headers) {
        const char *const *hdr;
        for (hdr = resp->v.v0.headers; *hdr; hdr++) {
            printf("Header: %s\n", *hdr);
        }
    }
    if (resp->v.v0.bytes) {
        printf("%*s\n", (int)resp->v.v0.nbytes, (const char *)resp->v.v0.bytes);
    }
    printf("%*s\n", (int)resp->v.v0.npath, resp->v.v0.path);

}

extern "C" {
    static void httpPutCallback(lcb_http_request_t request,
                                lcb_t instance,
                                const void *cookie,
                                lcb_error_t error,
                                const lcb_http_resp_t *resp)
    {
        HttpCmdContext *htctx;
        htctx = reinterpret_cast<HttpCmdContext *>((void *)cookie);
        htctx->err = error;
        htctx->status = resp->v.v0.status;
        htctx->received = true;

        if (error != LCB_SUCCESS) {
            dumpResponse(resp);
        }
    }
}

/**
 * @test HTTP (Put)
 *
 * @pre Create a valid view document and store it on the server
 * @post Store succeeds and the HTTP result code is 201
 */
TEST_F(HttpUnitTest, testPut)
{
    SKIP_IF_MOCK();

    lcb_t instance;
    createConnection(instance);

    const char *design_doc_path = "/_design/" DESIGN_DOC_NAME;
    lcb_http_cmd_st cmd;
    cmd = lcb_http_cmd_st(design_doc_path, strlen(design_doc_path),
                          view_common, strlen(view_common),
                          LCB_HTTP_METHOD_PUT, 0,
                          "application/json");

    lcb_error_t err;
    lcb_set_http_complete_callback(instance, httpPutCallback);

    lcb_http_request_t htreq;
    HttpCmdContext ctx;
    err = lcb_make_http_request(instance, &ctx, LCB_HTTP_TYPE_VIEW,
                                &cmd, &htreq);

    ASSERT_EQ(LCB_SUCCESS, err);
    lcb_wait(instance);

    ASSERT_EQ(true, ctx.received);
    ASSERT_EQ(LCB_SUCCESS, ctx.err);
    ASSERT_EQ(LCB_HTTP_STATUS_CREATED, ctx.status);

    lcb_destroy(instance);
}


extern "C" {
    static void httpGetCallback(lcb_http_request_t request,
                                lcb_t instance,
                                const void *cookie,
                                lcb_error_t error,
                                const lcb_http_resp_t *resp)
    {
        HttpCmdContext *htctx;
        htctx = reinterpret_cast<HttpCmdContext *>((void *)cookie);
        htctx->err = error;
        htctx->status = resp->v.v0.status;
        htctx->received = true;

        if (resp->v.v0.bytes) {
            htctx->body.assign((const char *)resp->v.v0.bytes,
                               resp->v.v0.nbytes);
        } else {
            dumpResponse(resp);
        }
    }
}

/**
 * @test HTTP (Get)
 * @pre Query a value view
 * @post HTTP Result is @c 200, and the view contents look like valid JSON
 * (i.e. the first non-whitespace char is a @c { and the last non-whitespace
 * char is a @c }
 */
TEST_F(HttpUnitTest, testGet)
{
    SKIP_IF_MOCK();

    lcb_t instance;
    createConnection(instance);
    const char *path = "_design/" DESIGN_DOC_NAME "/_view/" VIEW_NAME;
    lcb_http_cmd_st cmd = lcb_http_cmd_st(path, strlen(path), NULL, 0,
                                          LCB_HTTP_METHOD_GET, 0,
                                          "application/json");

    HttpCmdContext ctx;
    lcb_set_http_complete_callback(instance, httpGetCallback);
    lcb_error_t err;
    lcb_http_request_t htreq;

    err = lcb_make_http_request(instance, &ctx, LCB_HTTP_TYPE_VIEW,
                                &cmd, &htreq);

    ASSERT_EQ(LCB_SUCCESS, err);
    lcb_wait(instance);

    ASSERT_EQ(true, ctx.received);
    ASSERT_EQ(LCB_HTTP_STATUS_OK, ctx.status);
    ASSERT_GT(ctx.body.size(), 0);

    unsigned ii;
    const char *pcur;

    for (ii = 0, pcur = ctx.body.c_str();
            ii < ctx.body.size() && isspace(*pcur); ii++, pcur++) {
        /* no body */
    }

    /**
     * This is a view request. If all is in order, the content should be a
     * JSON object, first non-ws char is "{" and last non-ws char is "}"
     */
    ASSERT_NE(ctx.body.size(), ii);
    ASSERT_EQ(*pcur, '{');

    for (pcur = ctx.body.c_str() + ctx.body.size() - 1;
            ii >= 0 && isspace(*pcur); ii--, pcur--) {
        /* no body */
    }
    ASSERT_GE(ii, 0);
    ASSERT_EQ('}', *pcur);

    lcb_destroy(instance);
}

/**
 * @test HTTP (Bad POST params)
 * @pre Schedule an HTTP POST request, without passing a content body
 * @post Client returns @c EINVAL
 */
TEST_F(HttpUnitTest, testBadParams)
{
    SKIP_IF_MOCK();

    lcb_t instance;
    createConnection(instance);

    lcb_http_cmd_st cmd = lcb_http_cmd_st("/", 1, NULL, 0,
                                          LCB_HTTP_METHOD_POST, 0,
                                          "blah/blah");

    lcb_error_t err;
    lcb_http_request_t htreq;
    err = lcb_make_http_request(instance, NULL, LCB_HTTP_TYPE_VIEW,
                                &cmd, &htreq);
    ASSERT_EQ(LCB_EINVAL, err);
}
