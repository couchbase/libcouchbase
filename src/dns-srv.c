#include <libcouchbase/couchbase.h>

#include "config.h"
#include "simplestring.h"
#include "hostlist.h"

#ifndef _WIN32

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#if __NAMESER < 19991006
#undef HAVE_RES_SEARCH
#endif /* __NAMESER < NNN */
#endif /* HAVE_ARPA_NAMESER_H */

#if defined(HAVE_ARPA_NAMESER_H) && defined(HAVE_RES_SEARCH)
#define CAN_SRV_LOOKUP

#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>

LCB_INTERNAL_API
lcb_error_t
lcb_dnssrv_query(const char *name, hostlist_t hostlist)
{
    lcb_string ss_resp;
    ns_msg msg;

    int rv = 0, nresp, ii;
    lcb_U16 dns_rv;
    char *dname_p;

#define DO_RETURN(err) \
    lcb_string_release(&ss_resp); \
    return err;

    lcb_string_init(&ss_resp);
    lcb_string_reserve(&ss_resp, NS_PACKETSZ + NS_MAXDNAME);

    dname_p = ss_resp.base + NS_PACKETSZ;

    nresp = res_search(name, ns_c_in, ns_t_srv, (lcb_U8*)ss_resp.base, NS_PACKETSZ);
    if (nresp < 0) {
        DO_RETURN(LCB_UNKNOWN_HOST);
    }

    rv = ns_initparse((lcb_U8*)ss_resp.base, nresp, &msg);
    if (rv != 0) {
        DO_RETURN(LCB_PROTOCOL_ERROR);
    }

    dns_rv = ns_msg_getflag(msg, ns_f_rcode);
    if (dns_rv != ns_r_noerror) {
        DO_RETURN(LCB_UNKNOWN_HOST);
    }

    if (!ns_msg_count(msg, ns_s_an)) {
        DO_RETURN(LCB_UNKNOWN_HOST);
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

        ns_name_uncompress(
            ns_msg_base(msg), ns_msg_end(msg),
            rdata, dname_p, NS_MAXDNAME);
        hostlist_add_stringz(hostlist, dname_p, srv_port);
    }
    DO_RETURN(LCB_SUCCESS);
#undef DO_RETURN
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
    PDNS_RECORD root, cur;

    status = DnsQuery_A(
        addr, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, &root, NULL);
    if (status != 0) {
        return LCB_UNKNOWN_HOST;
    }

    for (cur = root; cur; cur = cur->pNext) {
        const DNS_SRV_DATA *srv = &cur->Data.SRV;
        hostlist_add_stringz(hs, srv->pNameTarget, srv->wPort);
    }
    DnsRecordListFree(root, DnsFreeRecordList);
    return LCB_SUCCESS;
}

#endif /* !WIN32 */


#ifndef CAN_SRV_LOOKUP
LCB_INTERNAL_API lcb_error_t lcb_dnssrv_query(const char *addr, hostlist_t hs)
{
    (void)addr;(void)hs; return LCB_CLIENT_FEATURE_UNAVAILABLE;
}
#endif

#define SVCNAME_PLAIN "_couchbase._tcp."
#define SVCNAME_SSL "_couchbases._tcp."

LCB_INTERNAL_API
hostlist_t
lcb_dnssrv_getbslist(const char *addr, int is_ssl, lcb_error_t *errp)
{
    lcb_string ss;

    hostlist_t ret = hostlist_create();
    lcb_string_init(&ss);
    lcb_string_appendv(&ss, is_ssl ? SVCNAME_SSL : SVCNAME_PLAIN, (size_t)-1,
            addr, (size_t)-1, NULL);

    *errp = lcb_dnssrv_query(ss.base, ret);
    lcb_string_release(&ss);
    if (*errp != LCB_SUCCESS) {
        hostlist_destroy(ret);
        ret = NULL;
    }
    return ret;
}
