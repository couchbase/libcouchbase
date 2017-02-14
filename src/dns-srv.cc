#include <libcouchbase/couchbase.h>

#include "config.h"
#include "hostlist.h"

#ifndef _WIN32
#include <string>

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#if __NAMESER < 19991006
#undef HAVE_RES_SEARCH
#endif /* __NAMESER < NNN */
#endif /* HAVE_ARPA_NAMESER_H */

#if defined(HAVE_ARPA_NAMESER_H) && defined(HAVE_RES_SEARCH)
#define CAN_SRV_LOOKUP
#include <cstdio>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>

LCB_INTERNAL_API
lcb_error_t
lcb_dnssrv_query(const char *name, hostlist_t hostlist)
{
    ns_msg msg;

    int rv = 0, nresp, ii;
    lcb_U16 dns_rv;

    std::vector<unsigned char> pkt(NS_PACKETSZ);
    nresp = res_search(name, ns_c_in, ns_t_srv, &pkt[0], NS_PACKETSZ);
    if (nresp < 0) {
        return LCB_UNKNOWN_HOST;
    }

    rv = ns_initparse(&pkt[0], nresp, &msg);
    if (rv != 0) {
        return LCB_PROTOCOL_ERROR;
    }

    dns_rv = ns_msg_getflag(msg, ns_f_rcode);
    if (dns_rv != ns_r_noerror) {
        return LCB_UNKNOWN_HOST;
    }

    if (!ns_msg_count(msg, ns_s_an)) {
        return LCB_UNKNOWN_HOST;
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

        #define do_get16(t) t = ns_get16(rdata); rdata += 2; rdlen -=2
        do_get16(srv_prio);
        do_get16(srv_weight);
        do_get16(srv_port);
        #undef do_get_16

        (void)srv_prio; (void)srv_weight; /* Handle these in the future */
        std::vector<char> dname(NS_MAXDNAME + 1);
        ns_name_uncompress(
            ns_msg_base(msg), ns_msg_end(msg),
            rdata, &dname[0], NS_MAXDNAME);
        hostlist->add(&dname[0], srv_port);
    }
    return LCB_SUCCESS;
}
#endif /* HAVE_RES_SEARCH */

#else
#include <windns.h>
#define CAN_SRV_LOOKUP
/* Implement via DnsQuery() */
LCB_INTERNAL_API
lcb_error_t
lcb_dnssrv_query(const char *addr, hostlist_t hs)
{
    DNS_STATUS status;
    PDNS_RECORDA root, cur;

    status = DnsQuery_A(
        addr, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, (PDNS_RECORD*)&root, NULL);
    if (status != 0) {
        return LCB_UNKNOWN_HOST;
    }

    for (cur = root; cur; cur = cur->pNext) {
        // Use the ASCII version of the DNS lookup structure
        const DNS_SRV_DATAA *srv = &cur->Data.SRV;
        hostlist_add_stringz(hs, srv->pNameTarget, srv->wPort);
    }
    DnsRecordListFree(root, DnsFreeRecordList);
    return LCB_SUCCESS;
}

#endif /* !WIN32 */


#ifndef CAN_SRV_LOOKUP
LCB_INTERNAL_API lcb_error_t lcb_dnssrv_query(const char *, hostlist_t) {
    return LCB_CLIENT_FEATURE_UNAVAILABLE;
}
#endif

#define SVCNAME_PLAIN "_couchbase._tcp."
#define SVCNAME_SSL "_couchbases._tcp."

LCB_INTERNAL_API
hostlist_st*
lcb_dnssrv_getbslist(const char *addr, int is_ssl, lcb_error_t *errp) {
    std::string ss;
    lcb::Hostlist *ret = new lcb::Hostlist();
    ss.append(is_ssl ? SVCNAME_SSL : SVCNAME_PLAIN);
    ss.append(addr);

    *errp = lcb_dnssrv_query(ss.c_str(), ret);
    if (*errp != LCB_SUCCESS) {
        delete ret;
        ret = NULL;
    }
    return static_cast<hostlist_st*>(ret);
}
