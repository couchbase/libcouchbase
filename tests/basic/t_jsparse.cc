#include "config.h"
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#include "jsparse/parser.h"
#include "contrib/lcb-jsoncpp/lcb-jsoncpp.h"
#include "t_jsparse.h"

class JsonParseTest : public ::testing::Test {
};

using namespace lcb::jsparse;

struct Context {
    lcb_error_t rc;
    bool received_done;
    std::string meta;
    std::vector<std::string> rows;
    Context() {
        reset();
    }
    void reset() {
        rc = LCB_SUCCESS;
        received_done = false;
        meta.clear();
        rows.clear();
    }
};

static std::string iov2s(const lcb_IOV& iov) {
    return std::string(reinterpret_cast<const char*>(iov.iov_base), iov.iov_len);
}

extern "C" {
static void rowCallback(Parser *parser, const Row *row) {
    Context *ctx = reinterpret_cast<Context*>(parser->data);
    if (row->type == Row::ROW_ERROR) {
        ctx->rc = LCB_PROTOCOL_ERROR;
        ctx->received_done = true;
    } else if (row->type == Row::ROW_ROW) {
        ctx->rows.push_back(iov2s(row->row));
    } else if (row->type == Row::ROW_COMPLETE) {
        ctx->meta = iov2s(row->row);
        ctx->received_done = true;
    }
}
}

static bool validateJsonRows(const char *txt, size_t ntxt, Parser::Mode mode)
{
    Parser parser(mode);

    // Feed it once
    Context cx;
    parser.callback = rowCallback;
    parser.data = &cx;

    for (size_t ii = 0; ii < ntxt; ii++) {
        parser.feed(txt + ii, 1);
    }
    EXPECT_EQ(LCB_SUCCESS, cx.rc);

    lcb_IOV out;
    parser.get_postmortem(out);
    EXPECT_EQ(cx.meta, iov2s(out));
    Json::Value root;
    EXPECT_TRUE(Json::Reader().parse(cx.meta, root));
    return true;
}

static bool validateBadParse(const char *txt, size_t ntxt, Parser::Mode mode)
{
    Parser p(mode);
    Context cx;
    p.callback = rowCallback;
    p.data = &cx;
    p.feed(JSON_fts_bad, sizeof(JSON_fts_bad));
    EXPECT_EQ(LCB_PROTOCOL_ERROR, cx.rc);

    p.reset();
    cx.reset();

    p.callback = rowCallback;
    p.data = &cx;

    return true;
}

TEST_F(JsonParseTest, testFTS)
{
    ASSERT_TRUE(validateJsonRows(JSON_fts_good, sizeof(JSON_fts_good), Parser::MODE_FTS));
    ASSERT_TRUE(validateBadParse(JSON_fts_bad, sizeof(JSON_fts_bad), Parser::MODE_FTS));
    ASSERT_TRUE(validateBadParse(JSON_fts_bad2, sizeof(JSON_fts_bad2), Parser::MODE_FTS));
}

TEST_F(JsonParseTest, testN1QL) {
    ASSERT_TRUE(validateJsonRows(JSON_n1ql_nonempty, sizeof(JSON_n1ql_nonempty), Parser::MODE_N1QL));
    ASSERT_TRUE(validateJsonRows(JSON_n1ql_empty, sizeof(JSON_n1ql_empty), Parser::MODE_N1QL));
    ASSERT_TRUE(validateBadParse(JSON_n1ql_bad, sizeof(JSON_n1ql_bad), Parser::MODE_N1QL));
}
