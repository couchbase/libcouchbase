#include "dsn.h"
#include "hostlist.h"
#include "strcodecs/strcodecs.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

#define SET_ERROR(msg) \
    *errmsg = msg; \
    err = LCB_EINVAL; \
    goto GT_DONE;


#define SCRATCHSIZE 4096
#define F_HASBUCKET (1<<0)
#define F_HASPASSWD (1<<1)
#define F_HASUSER (1<<2)

typedef struct {
    char *scratch; /* temporary buffer. Sufficient for strlen(dsn) * 3 bytes */
    char *decoded; /* offset into 'scratch' */
    const char *dsn; /* input string */
    const char *dsnend; /* end of input */
    const char **errmsg;
    lcb_DSNPARAMS *params;
} PARSECTX;

static lcb_error_t
parse_hosts(PARSECTX *ctx, const char *hosts_end)
{
    const char **errmsg = ctx->errmsg;
    lcb_error_t err = LCB_SUCCESS;
    const char *c;

    if (0 != lcb_urldecode(ctx->dsn, ctx->decoded, hosts_end - ctx->dsn)) {
        SET_ERROR("Couldn't decode from url encoding");
    }

    c = ctx->decoded;

    while (*c) {
        // get the current host
        const char *curend;
        const char *port_s;
        char *tmp;
        unsigned curlen, hostlen, portlen;
        lcb_DSNHOST *dh;
        int itmp, rv;
        char hpdummy[256];

        /* Seek ahead, chopping off any ',' */
        while (*c == ',') {
            if (*(++c) ==  '\0') {
                goto GT_DONE;
            }
        }

        /* Find the end */
        curend = strchr(c, ',');
        if (!curend) {
            curend = c + strlen(c);
        }
        curlen = curend - c;
        if (!curlen) {
            continue;
        }

        memcpy(ctx->scratch, c, curlen);
        c = curend;
        ctx->scratch[curlen] = '\0';

        /* weed out erroneous characters */
        if (strstr(ctx->scratch, "://")) {
            SET_ERROR("Detected '://' inside hostname");
        }

        port_s = strchr(ctx->scratch, ':');
        if (port_s == NULL) {
            hostlen = curlen;
            ctx->params->has_no_ports = 1;

        } else {
            ctx->params->has_custom_ports = 1;
            hostlen = port_s - ctx->scratch;
            portlen = (curlen - hostlen)-1;
            port_s++;
        }
        if (ctx->params->has_custom_ports && ctx->params->has_no_ports) {
            SET_ERROR("Cannot mix host:port and plain host specifiers");
        }

        dh = malloc(sizeof(*dh) + hostlen);
        dh->htport = 0;
        dh->ssl_htport = 0;
        dh->memdport = 0;
        dh->ssl_memdport = 0;

        memcpy(dh->hostname, ctx->scratch, hostlen);
        dh->hostname[hostlen] = '\0';
        lcb_list_append(&ctx->params->hosts, &dh->llnode);

        if (port_s == NULL) {
            continue;
        }
        if (portlen >= sizeof hpdummy) {
            SET_ERROR("Port specification too big");
        }
        memcpy(hpdummy, port_s, portlen);
        hpdummy[portlen] = '\0';


        /* we have a port. The format is port=proto */
        rv = sscanf(hpdummy, "%d=%s", &itmp, ctx->scratch);
        if (rv == 2) {
            for (tmp = ctx->scratch; *tmp; tmp++) {
                *tmp = toupper(*tmp);
            }
        } else if (rv == 1 &&
                (itmp == LCB_CONFIG_HTTP_PORT || itmp == LCB_CONFIG_MCD_PORT)) {
            continue;
        } else {
            SET_ERROR("Port must be specified with protocol (host:port=proto)");
        }

        tmp = ctx->scratch;
        if (!strcmp(tmp, "HTTP")) {
            dh->htport = itmp;
        } else if (!strcmp(tmp, "HTTPS")) {
            dh->ssl_htport = itmp;
        } else if (!strcmp(tmp, "MCD")) {
            dh->memdport = itmp;
        } else if (!strcmp(tmp, "MCDS")) {
            dh->ssl_memdport = itmp;
        } else {
            SET_ERROR("Unrecognized protocol specified. Recognized are "
                "HTTP, HTTPS, MCD, MCDS");
        }
    }
    GT_DONE:
    return err;
}

static lcb_error_t
parse_options(PARSECTX *ctx, const char *options, const char *dsnend)
{
    lcb_string tmpstr;
    char *scratch = ctx->scratch;
    char *tmp;
    const char **errmsg = ctx->errmsg;
    lcb_DSNPARAMS *out = ctx->params;
    lcb_error_t err = LCB_SUCCESS;

    lcb_string_init(&tmpstr);

    while (options != NULL && options < dsnend) {
        unsigned curlen;
        char *key, *value;
        const char *curend;

        if (*options == '&') {
            options++;
            continue;
        }

        curend = strchr(options, '&');
        if (!curend) {
            curend = dsnend;
        }

        curlen = curend - options;
        memcpy(scratch, options, curlen);
        scratch[curlen] = '\0';
        options = curend+1;

        key = scratch;
        value = strchr(key, '=');
        if (!value) {
            SET_ERROR("Option must be specified as a key=value pair");
        }

        *(value++) = '\0';
        if (!*value) {
            SET_ERROR("Value cannot be empty");
        }
        if (0 != lcb_urldecode(value, value, -1)) {
            SET_ERROR("Couldn't decode value");
        }
        if (!strcmp(key, "bootstrap_on")) {
            lcb_config_transport_t *arr = out->transports;
            if (!strcmp(value, "cccp")) {
                arr[0] = LCB_CONFIG_TRANSPORT_CCCP;
                arr[1] = LCB_CONFIG_TRANSPORT_LIST_END;
            } else if (!strcmp(value, "http")) {
                arr[0] = LCB_CONFIG_TRANSPORT_HTTP;
                arr[1] = LCB_CONFIG_TRANSPORT_LIST_END;
            } else if (!strcmp(value, "all")) {
                arr[0] = LCB_CONFIG_TRANSPORT_CCCP;
                arr[1] = LCB_CONFIG_TRANSPORT_HTTP;
                arr[2] = LCB_CONFIG_TRANSPORT_LIST_END;
            } else {
                SET_ERROR("Value for bootstrap_on must be 'cccp', 'http', or 'all'");
            }
        } else if (!strcmp(key, "username") || !strcmp(key, "user")) {
            if (! (out->flags & F_HASUSER)) {
                out->username = strdup(value);
            }
        } else if (!strcmp(key, "password") || !strcmp(key, "pass")) {
            if (! (out->flags & F_HASPASSWD)) {
                out->password = strdup(value);
            }
        } else if (!strcmp(key, "ssl")) {
            if (!strcmp(value, "off")) {
                out->sslopts = 0;
            } else if (!strcmp(value, "on")) {
                out->sslopts = LCB_SSL_ENABLED;
            } else if (!strcmp(value, "no_verify")) {
                out->sslopts = LCB_SSL_ENABLED|LCB_SSL_NOVERIFY;
            } else {
                SET_ERROR("Invalid value for 'ssl'. Choices are on, off, and no_verify");
            }
        } else if (!strcmp(key, "capath")) {
            out->capath = strdup(value);
        } else if (!strcmp(key, "console_log_level")) {
            if (sscanf(value, "%d", &out->loglevel) != 1) {
                SET_ERROR("console_log_level must be a numeric value");
            }
        } else {
            lcb_string_appendz(&tmpstr, key);
            lcb_string_appendz(&tmpstr, "=");
            lcb_string_appendz(&tmpstr, value);
            lcb_string_appendz(&tmpstr, "&");
        }
    }

    /* copy over the string */
    out->ctlopts = tmpstr.base;
    out->optslen = tmpstr.nused;
    tmpstr.base = NULL;
    tmpstr.nused = 0;

    /* seek ahead and set any '&' and '=' to '\0' */
    if (out->optslen) {
        tmp = out->ctlopts;
        while ((tmp = strpbrk(tmp, "&="))) {
            *tmp = '\0';
            tmp++;
        }
        /* chop off trailing '&' */
        out->optslen--;
    }

    GT_DONE:
    if (err != LCB_SUCCESS) {
        lcb_string_release(&tmpstr);
    }

    return err;
}

LIBCOUCHBASE_API
lcb_error_t
lcb_dsn_parse(const char *dsn_in, lcb_DSNPARAMS *out, const char **errmsg)
{
    PARSECTX ctx;
    lcb_error_t err = LCB_SUCCESS;
    const char *errmsg_s; /* stack based error message pointer */
    char *scratch_d = NULL; /* dynamically allocated scratch */
    char scratch_s[SCRATCHSIZE]; /* stack allocated scratch */
    const char *hlend; /* end of hosts list */
    const char *bucket = NULL; /* beginning of bucket (path) string */
    const char *options = NULL; /* beginning of options (query) string */
    const char *dsnend = NULL; /* end of DSN */
    unsigned dsnlen; /* length of dsn string */

    if (!errmsg) {
        errmsg = &errmsg_s;
    }

    ctx.errmsg = errmsg;
    ctx.dsn = dsn_in;
    ctx.params = out;

    lcb_list_init(&out->hosts);
    out->transports[0] = LCB_CONFIG_TRANSPORT_LIST_END;

    /* first find the scheme */
    if (strstr(ctx.dsn, LCB_DSN_SCHEME) != ctx.dsn) {
        SET_ERROR("String must begin with '"LCB_DSN_SCHEME"'");
    }

    ctx.dsn += (sizeof(LCB_DSN_SCHEME)-1);
    dsnlen = strlen(ctx.dsn);
    dsnend = ctx.dsn + dsnlen;

    if (dsnlen * 3 > SCRATCHSIZE) {
        scratch_d = malloc(dsnlen * 2);
        ctx.scratch = scratch_d;
    } else {
        ctx.scratch = scratch_s;
    }
    ctx.decoded = ctx.scratch + dsnlen * 2;

    /* if we have a path, the hosts end there */
    if ((hlend = strchr(ctx.dsn, '/'))) {
        bucket = hlend + 1;
        if ((options = strchr(bucket, '?'))) {
            options++;
        }
    }

    if (hlend == NULL) {
        bucket = NULL;
        if ((options = hlend = strchr(ctx.dsn, '?'))) {
            options++;
        }
    }

    if (hlend == NULL) {
        bucket = NULL;
        options = NULL;
        hlend = dsnend;
    }


    if (bucket != NULL) {
        unsigned blen;
        const char *b_end = options ? options-1 : dsnend;
        /* scan each of the options */
        blen = b_end - bucket;
        memcpy(ctx.scratch, bucket, blen);
        ctx.scratch[blen] = '\0';
        if (! (out->flags & F_HASBUCKET)) {
            out->bucket = strdup(ctx.scratch);
            if (0 != lcb_urldecode(out->bucket, out->bucket, -1)) {
                SET_ERROR("Couldn't decode bucket string");
            }
        }
    } else if (out->bucket == NULL) {
        out->bucket = strdup("default");
    }

    if ((err = parse_hosts(&ctx, hlend)) != LCB_SUCCESS) {
        goto GT_DONE;
    }

    if (LCB_LIST_IS_EMPTY(&out->hosts)) {
        const char localhost[] = "localhost";
        lcb_DSNHOST *host = calloc(1, sizeof(*host) + sizeof localhost);
        memcpy(host->hostname, localhost, sizeof localhost);
        lcb_list_append(&out->hosts, &host->llnode);
        out->has_no_ports = 1;
    }

    if (options != NULL) {
        if ((err = parse_options(&ctx, options, dsnend)) != LCB_SUCCESS) {
            goto GT_DONE;
        }
    }

    if (!out->username) {
        out->username = strdup(out->bucket);
    }
    GT_DONE:

    if (err != LCB_SUCCESS) {
        lcb_dsn_clean(out);
    }

    free(scratch_d);
    return err;
}

LIBCOUCHBASE_API
void
lcb_dsn_clean(lcb_DSNPARAMS *params)
{
    lcb_list_t *ll, *llnext;
    free(params->bucket);
    free(params->username);
    free(params->password);
    free(params->ctlopts);
    free(params->origdsn);

    LCB_LIST_SAFE_FOR(ll, llnext, &params->hosts) {
        lcb_DSNHOST *host = LCB_LIST_ITEM(ll, lcb_DSNHOST, llnode);
        lcb_list_delete(&host->llnode);
        free(host);
    }

    memset(params, 0, sizeof *params);
    lcb_list_init(&params->hosts);
}

LIBCOUCHBASE_API
int
lcb_dsn_next_option(const lcb_DSNPARAMS *params,
    const char **key, const char **value, int *ctx)
{
    if (!params->ctlopts) {
        return 0;
    }

    if (*ctx == -1) {
        return 0;
    }

    *key = params->ctlopts + *ctx;
    *ctx += strlen(*key) + 1;

    *value = params->ctlopts + *ctx;
    *ctx += strlen(*value);

    if ((unsigned)*ctx == params->optslen) {
        *ctx = -1;
    } else {
        *ctx += 1;
    }
    return 1;
}


#define MAYBEDUP(s) ((s) && (*s)) ? strdup(s) : NULL

static lcb_error_t
convert_hosts(lcb_string *outstr, const char *instr, int deflport)
{
    hostlist_t hlist;
    lcb_error_t err;
    unsigned ii;

    hlist = hostlist_create();
    if (!hlist) {
        return LCB_CLIENT_ENOMEM;
    }

    err = hostlist_add_stringz(hlist, instr, deflport);
    if (err != LCB_SUCCESS) {
        hostlist_destroy(hlist);
        return err;
    }

    for (ii = 0; ii < hlist->nentries; ii++) {
        const lcb_host_t *src = hlist->entries + ii;
        int port, rv;
        lcb_string_appendz(outstr, src->host);
        rv = sscanf(src->port, "%d", &port);
        if (rv && port != deflport) {
            const char *proto;
            char tmpbuf[256];
            if (deflport == LCB_CONFIG_MCD_PORT) {
                proto = "mcd";
            } else {
                proto = "http";
            }
            sprintf(tmpbuf, ":%d=%s", port, proto);
            lcb_string_appendz(outstr, tmpbuf);
        }
        lcb_string_appendz(outstr, ",");
    }

    hostlist_destroy(hlist);
    return LCB_SUCCESS;
}

#define TRYDUP(s) (s) ? strdup(s) : NULL
LIBCOUCHBASE_API
lcb_error_t
lcb_dsn_convert(lcb_DSNPARAMS *params, const struct lcb_create_st *cropts)
{
    const char *errmsg;
    lcb_string tmpstr;
    const struct lcb_create_st2 *cr2 = &cropts->v.v2;
    lcb_error_t err = LCB_SUCCESS;

    /* handle overrides */
    if (cr2->bucket && *cr2->bucket) {
        params->flags |= F_HASBUCKET;
        params->bucket = strdup(cr2->bucket);
    }

    if (cr2->user && *cr2->user) {
        params->flags |= F_HASUSER;
        params->username = strdup(cr2->user);
    }

    if (cr2->passwd && *cr2->passwd) {
        params->flags |= F_HASPASSWD;
        params->password = strdup(cr2->passwd);
    }

    if (cropts->version == 3) {
        return lcb_dsn_parse(cropts->v.v3.dsn, params, &errmsg);
    }

    if (cropts->version > 2 || cropts->version < 0) {
        return LCB_NOT_SUPPORTED;
    }

    lcb_string_init(&tmpstr);
    lcb_string_appendz(&tmpstr, "couchbase://");
    lcb_list_init(&params->hosts);

    params->transports[0] = LCB_CONFIG_TRANSPORT_LIST_END;
    if (cr2->host) {
        err = convert_hosts(&tmpstr, cr2->host, LCB_CONFIG_HTTP_PORT);
        if (err != LCB_SUCCESS) {
            goto GT_DONE;
        }
    }

    if (cropts->version == 2 && cr2->mchosts) {
        params->has_custom_ports = 1;
        err = convert_hosts(&tmpstr, cr2->mchosts, LCB_CONFIG_MCD_PORT);
        if (err != LCB_SUCCESS) {
            goto GT_DONE;
        }
    }

    lcb_string_appendz(&tmpstr, "?");

    err = lcb_dsn_parse(tmpstr.base, params, &errmsg);
    if (err == LCB_SUCCESS && cropts->version == 2 && cr2->transports) {
        /* copy over bootstrap list */
        unsigned ii, found_end = 0;
        for (ii = 0; ii < LCB_CONFIG_TRANSPORT_MAX; ii++) {
            params->transports[ii] = cr2->transports[ii];
            if (params->transports[ii] == LCB_CONFIG_TRANSPORT_LIST_END) {
                found_end = 1;
                break;
            }
        }
        if (!found_end) {
            params->transports[ii] = LCB_CONFIG_TRANSPORT_LIST_END;
        }
    }

    GT_DONE:
    if (err == LCB_SUCCESS) {
        params->origdsn = tmpstr.base;
    } else {
        lcb_string_release(&tmpstr);
    }
    return err;
}
