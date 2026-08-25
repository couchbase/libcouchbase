#include <libcouchbase/couchbase.h>

#include "config.h"
#include "hostlist.h"
#include "connspec.h"

#ifndef _WIN32
#include <string>

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#if defined(__NAMESER) && __NAMESER < 19991006
#undef HAVE_RES_SEARCH
#endif /* __NAMESER < NNN */
#endif /* HAVE_ARPA_NAMESER_H */

#if defined(HAVE_ARPA_NAMESER_H) && defined(HAVE_RES_SEARCH)
#define CAN_SRV_LOOKUP
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>

#define LCB_NSRESSZ 4096

lcb_STATUS lcb::dnssrv_query(const char *name, lcb::Hostlist &hostlist, uint32_t timeout_us)
{
    ns_msg msg;

    int rv = 0, nresp, ii;
    lcb_U16 dns_rv;

    std::vector<unsigned char> pkt(LCB_NSRESSZ);

#ifdef HAVE_RES_NINIT
    /* The resolver waits `retrans` seconds on each nameserver on each of its
     * `retry` passes, so an unanswered query costs retrans * retry * nscount
     * before it gives up -- tens of seconds with the system defaults. This
     * lookup runs inside lcb_create(), which returns to the caller only when
     * it completes, so the wait is bounded by the budget the caller already
     * set for reaching one configuration node.
     *
     * Giving up early is not a failure: process_dns_srv() falls back to the
     * hostname it was given unless the scheme demanded SRV. The ceiling still
     * scales with the resolver's search list, which res_nsearch() walks one
     * name at a time. */
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) {
        return LCB_ERR_UNKNOWN_HOST;
    }
    unsigned nameservers = state.nscount > 0 ? static_cast<unsigned>(state.nscount) : 1u;
    state.retry = 1;
    state.retrans = static_cast<int>((timeout_us / 1000000u) / nameservers);
    if (state.retrans < 1) {
        state.retrans = 1;
    }
    nresp = res_nsearch(&state, name, ns_c_in, ns_t_srv, &pkt[0], pkt.size());
    res_nclose(&state);
#else
    (void)timeout_us;
    nresp = res_search(name, ns_c_in, ns_t_srv, &pkt[0], pkt.size());
#endif

    if (nresp < 0) {
        return LCB_ERR_UNKNOWN_HOST;
    }

    rv = ns_initparse(&pkt[0], nresp, &msg);
    if (rv != 0) {
        return LCB_ERR_PROTOCOL_ERROR;
    }

    dns_rv = ns_msg_getflag(msg, ns_f_rcode);
    if (dns_rv != ns_r_noerror) {
        return LCB_ERR_UNKNOWN_HOST;
    }

    if (!ns_msg_count(msg, ns_s_an)) {
        return LCB_ERR_UNKNOWN_HOST;
    }

    for (ii = 0; ii < ns_msg_count(msg, ns_s_an); ii++) {
        lcb_U16 srv_prio, srv_weight, srv_port;
        ns_rr rr;
        const lcb_U8 *rdata;
        size_t rdlen;

        if (ns_parserr(&msg, ns_s_an, ii, &rr) != 0) {
            continue;
        }

        if (ns_rr_type(rr) != ns_t_srv) {
            continue;
        }

        /* Get the rdata and length fields */
        rdata = ns_rr_rdata(rr);
        rdlen = ns_rr_rdlen(rr);

        if (rdlen < 6) {
            continue;
        }

#define do_get16(t)                                                                                                    \
    t = ns_get16(rdata);                                                                                               \
    rdata += 2;                                                                                                        \
    rdlen -= 2
        do_get16(srv_prio);
        do_get16(srv_weight);
        do_get16(srv_port);
#undef do_get_16

        (void)srv_prio;
        (void)srv_weight; /* Handle these in the future */
        std::vector<char> dname(NS_MAXDNAME + 1);
        ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata, &dname[0], NS_MAXDNAME);
        hostlist.add(&dname[0], srv_port);
    }
    return LCB_SUCCESS;
}
#endif /* HAVE_RES_SEARCH */

#elif defined(_MSC_VER)
#include <windns.h>
#define CAN_SRV_LOOKUP
/* Implement via DnsQuery() */
lcb_STATUS lcb::dnssrv_query(const char *addr, Hostlist &hs, uint32_t)
{
    DNS_STATUS status;
    PDNS_RECORDA root, cur;

    status = DnsQuery_A(addr, DNS_TYPE_SRV, DNS_QUERY_STANDARD, nullptr, (PDNS_RECORD *)&root, nullptr);
    if (status != 0) {
        return LCB_ERR_UNKNOWN_HOST;
    }

    for (cur = root; cur; cur = cur->pNext) {
        if(cur->wType == DNS_TYPE_SRV) {
            // Use the ASCII version of the DNS lookup structure
            const DNS_SRV_DATAA *srv = &cur->Data.SRV;
            hs.add(srv->pNameTarget, srv->wPort);
        }
    }
    DnsRecordListFree(root, DnsFreeRecordList);
    return LCB_SUCCESS;
}

#endif /* !WIN32 */

#ifndef CAN_SRV_LOOKUP
lcb_STATUS lcb::dnssrv_query(const char *, Hostlist &, uint32_t)
{
    return LCB_ERR_SDK_FEATURE_UNAVAILABLE;
}
#endif

#define SVCNAME_PLAIN "_couchbase._tcp."
#define SVCNAME_SSL "_couchbases._tcp."

lcb::Hostlist *lcb::dnssrv_getbslist(const char *addr, bool is_ssl, lcb_STATUS &errp, uint32_t timeout_us)
{
    std::string ss;
    auto *ret = new Hostlist();
    ss.append(is_ssl ? SVCNAME_SSL : SVCNAME_PLAIN);
    ss.append(addr);

    errp = dnssrv_query(ss.c_str(), *ret, timeout_us);
    if (errp != LCB_SUCCESS) {
        delete ret;
        return nullptr;
    }
    if (ret->empty()) {
        delete ret;
        errp = LCB_ERR_NAMESERVER;
        return nullptr;
    }
    return ret;
}
