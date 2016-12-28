#include <libcouchbase/couchbase.h>
#include <libcouchbase/views.h>
#include <libcouchbase/pktfwd.h>
#include <jsparse/parser.h>
#include <string>
#include "docreq.h"

namespace lcb {
namespace views {

struct ViewRequest;
struct VRDocRequest : docreq::DocRequest {
    ViewRequest *parent;
    lcb_IOV key;
    lcb_IOV value;
    lcb_IOV geo;
    std::string rowbuf;
};

struct ViewRequest {
    /** Current HTTP response to provide in callbacks */
    const lcb_RESPHTTP *cur_htresp;
    /** HTTP request object, in case we need to cancel prematurely */
    struct lcb_http_request_st *htreq;
    lcbjsp_PARSER *parser;
    const void *cookie;
    docreq::Queue *docq;
    lcb_VIEWQUERYCALLBACK callback;
    lcb_t instance;

    unsigned refcount;
    unsigned include_docs;
    unsigned no_parse_rows;
    lcb_error_t lasterr;
};

}
}
