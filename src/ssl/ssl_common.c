/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014-2020 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * This file contains the common bucket of routines necessary for interfacing
 * with OpenSSL.
 */
#include "ssl_iot_common.h"
#include "settings.h"
#include "logging.h"
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
#define HAVE_CIPHERSUITES 1
#endif

#define LOGARGS(ssl, lvl) ((lcbio_SOCKET *)SSL_get_app_data(ssl))->settings, "SSL", lvl, __FILE__, __LINE__
static char *global_event = "dummy event for ssl";

static const char *capella_ca_cert = "-----BEGIN CERTIFICATE-----\n"
                                     "MIIDFTCCAf2gAwIBAgIRANLVkgOvtaXiQJi0V6qeNtswDQYJKoZIhvcNAQELBQAw\n"
                                     "JDESMBAGA1UECgwJQ291Y2hiYXNlMQ4wDAYDVQQLDAVDbG91ZDAeFw0xOTEyMDYy\n"
                                     "MjEyNTlaFw0yOTEyMDYyMzEyNTlaMCQxEjAQBgNVBAoMCUNvdWNoYmFzZTEOMAwG\n"
                                     "A1UECwwFQ2xvdWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfvOIi\n"
                                     "enG4Dp+hJu9asdxEMRmH70hDyMXv5ZjBhbo39a42QwR59y/rC/sahLLQuNwqif85\n"
                                     "Fod1DkqgO6Ng3vecSAwyYVkj5NKdycQu5tzsZkghlpSDAyI0xlIPSQjoORA/pCOU\n"
                                     "WOpymA9dOjC1bo6rDyw0yWP2nFAI/KA4Z806XeqLREuB7292UnSsgFs4/5lqeil6\n"
                                     "rL3ooAw/i0uxr/TQSaxi1l8t4iMt4/gU+W52+8Yol0JbXBTFX6itg62ppb/Eugmn\n"
                                     "mQRMgL67ccZs7cJ9/A0wlXencX2ohZQOR3mtknfol3FH4+glQFn27Q4xBCzVkY9j\n"
                                     "KQ20T1LgmGSngBInAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE\n"
                                     "FJQOBPvrkU2In1Sjoxt97Xy8+cKNMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0B\n"
                                     "AQsFAAOCAQEARgM6XwcXPLSpFdSf0w8PtpNGehmdWijPM3wHb7WZiS47iNen3oq8\n"
                                     "m2mm6V3Z57wbboPpfI+VEzbhiDcFfVnK1CXMC0tkF3fnOG1BDDvwt4jU95vBiNjY\n"
                                     "xdzlTP/Z+qr0cnVbGBSZ+fbXstSiRaaAVcqQyv3BRvBadKBkCyPwo+7svQnScQ5P\n"
                                     "Js7HEHKVms5tZTgKIw1fbmgR2XHleah1AcANB+MAPBCcTgqurqr5G7W2aPSBLLGA\n"
                                     "fRIiVzm7VFLc7kWbp7ENH39HVG6TZzKnfl9zJYeiklo5vQQhGSMhzBsO70z4RRzi\n"
                                     "DPFAN/4qZAgD5q3AFNIq2WWADFQGSwVJhg==\n"
                                     "-----END CERTIFICATE-----\n";

/******************************************************************************
 ******************************************************************************
 ** Boilerplate lcbio_TABLE Wrappers                                         **
 ******************************************************************************
 ******************************************************************************/
static void loop_run(lcb_io_opt_t io)
{
    lcbio_XSSL *xs = IOTSSL_FROM_IOPS(io);
    IOT_START(xs->orig);
}
static void loop_stop(lcb_io_opt_t io)
{
    lcbio_XSSL *xs = IOTSSL_FROM_IOPS(io);
    IOT_STOP(xs->orig);
}
static void *create_event(lcb_io_opt_t io)
{
    (void)io;
    return global_event;
}
static void destroy_event(lcb_io_opt_t io, void *event)
{
    (void)io;
    (void)event;
}
static void *create_timer(lcb_io_opt_t io)
{
    lcbio_XSSL *xs = IOTSSL_FROM_IOPS(io);
    return xs->orig->timer.create(IOT_ARG(xs->orig));
}
static int schedule_timer(lcb_io_opt_t io, void *timer, lcb_uint32_t us, void *arg, lcb_ioE_callback callback)
{
    lcbio_XSSL *xs = IOTSSL_FROM_IOPS(io);
    return xs->orig->timer.schedule(IOT_ARG(xs->orig), timer, us, arg, callback);
}
static void destroy_timer(lcb_io_opt_t io, void *timer)
{
    lcbio_XSSL *xs = IOTSSL_FROM_IOPS(io);
    xs->orig->timer.destroy(IOT_ARG(xs->orig), timer);
}
static void cancel_timer(lcb_io_opt_t io, void *timer)
{
    lcbio_XSSL *xs = IOTSSL_FROM_IOPS(io);
    xs->orig->timer.cancel(IOT_ARG(xs->orig), timer);
}
static int Eis_closed(lcb_io_opt_t io, lcb_socket_t sock, int flags)
{
    lcbio_XSSL *xs = IOTSSL_FROM_IOPS(io);
    return xs->orig->u_io.v0.io.is_closed(IOT_ARG(xs->orig), sock, flags);
}
static int Cis_closed(lcb_io_opt_t io, lcb_sockdata_t *sd, int flags)
{
    lcbio_XSSL *xs = IOTSSL_FROM_IOPS(io);
    return xs->orig->u_io.completion.is_closed(IOT_ARG(xs->orig), sd, flags);
}

/******************************************************************************
 ******************************************************************************
 ** Common Routines for lcbio_TABLE Emulation                                **
 ******************************************************************************
 ******************************************************************************/
void iotssl_init_common(lcbio_XSSL *xs, lcbio_TABLE *orig, SSL_CTX *sctx)
{
    lcbio_TABLE *base = &xs->base_;
    xs->iops_dummy_ = calloc(1, sizeof(*xs->iops_dummy_));
    xs->iops_dummy_->v.v0.cookie = xs;
    xs->orig = orig;
    base->model = xs->orig->model;
    base->p = xs->iops_dummy_;
    base->refcount = 1;
    base->loop.start = loop_run;
    base->loop.stop = loop_stop;
    base->timer.create = create_timer;
    base->timer.destroy = destroy_timer;
    base->timer.schedule = schedule_timer;
    base->timer.cancel = cancel_timer;

    if (orig->model == LCB_IOMODEL_EVENT) {
        base->u_io.v0.ev.create = create_event;
        base->u_io.v0.ev.destroy = destroy_event;
        base->u_io.v0.io.is_closed = Eis_closed;
    } else {
        base->u_io.completion.is_closed = Cis_closed;
    }

    lcbio_table_ref(xs->orig);

    xs->error = 0;
    xs->ssl = SSL_new(sctx);

    xs->rbio = BIO_new(BIO_s_mem());
    xs->wbio = BIO_new(BIO_s_mem());

    SSL_set_bio(xs->ssl, xs->rbio, xs->wbio);
    SSL_set_read_ahead(xs->ssl, 0);

    /* Indicate that we are a client */
    SSL_set_connect_state(xs->ssl);
}

void iotssl_destroy_common(lcbio_XSSL *xs)
{
    free(xs->iops_dummy_);
    SSL_free(xs->ssl);
    lcbio_table_unref(xs->orig);
}

#if LCB_CAN_OPTIMIZE_SSL_BIO
void iotssl_bm_reserve(BUF_MEM *bm)
{
    int oldlen;
    oldlen = bm->length;
    while (bm->max - bm->length < 4096) {
        /* there's also a BUF_MEM_grow_clean() but that actually clears the
         * used portion of the buffer */
        BUF_MEM_grow(bm, bm->max + 4096);
    }
    bm->length = oldlen;
}
#endif

void iotssl_log_errors(lcbio_XSSL *xs)
{
    unsigned long curerr;
    while ((curerr = ERR_get_error())) {
        if (SSL_get_app_data(xs->ssl) != NULL) {
            char errbuf[4096];
            ERR_error_string_n(curerr, errbuf, sizeof errbuf);
            lcb_log(LOGARGS(xs->ssl, LCB_LOG_ERROR), "%s", errbuf);
        }

        if (xs->errcode != LCB_SUCCESS) {
            continue; /* Already set */
        }

        if (ERR_GET_LIB(curerr) == ERR_LIB_SSL) {
            switch (ERR_GET_REASON(curerr)) {
                case SSL_R_CERTIFICATE_VERIFY_FAILED:
#ifdef SSL_R_MISSING_VERIFY_MESSAGE
                case SSL_R_MISSING_VERIFY_MESSAGE:
#endif
                    xs->errcode = LCB_ERR_SSL_CANTVERIFY;
                    break;

                case SSL_R_BAD_PROTOCOL_VERSION_NUMBER:
                case SSL_R_UNKNOWN_PROTOCOL:
                case SSL_R_WRONG_VERSION_NUMBER:
                case SSL_R_UNKNOWN_SSL_VERSION:
                case SSL_R_UNSUPPORTED_SSL_VERSION:
                    xs->errcode = LCB_ERR_PROTOCOL_ERROR;
                    break;
                default:
                    xs->errcode = LCB_ERR_SSL_ERROR;
            }
        }
    }
}

static void log_global_errors(lcb_settings *settings)
{
    unsigned long curerr;
    while ((curerr = ERR_get_error())) {
        char errbuf[4096];
        ERR_error_string_n(curerr, errbuf, sizeof errbuf);
        lcb_log(settings, "SSL", LCB_LOG_ERROR, __FILE__, __LINE__, "SSL Error: %ld, %s", curerr, errbuf);
    }
}

int iotssl_maybe_error(lcbio_XSSL *xs, int rv)
{
    lcb_assert(rv < 1);
    if (rv == -1) {
        int err = SSL_get_error(xs->ssl, rv);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* this is ok. */
            return 0;
        }
    }
    iotssl_log_errors(xs);
    return -1;
}

/******************************************************************************
 ******************************************************************************
 ** Higher Level SSL_CTX Wrappers                                            **
 ******************************************************************************
 ******************************************************************************/
static void log_callback(const SSL *ssl, int where, int ret)
{
    int should_log = 0;
    lcbio_SOCKET *sock = SSL_get_app_data(ssl);
    if (sock == NULL) {
        return;
    }
    /* Ignore low-level SSL stuff */

    if (where & SSL_CB_ALERT) {
        should_log = 1;
    }
    if (where == SSL_CB_HANDSHAKE_START || where == SSL_CB_HANDSHAKE_DONE) {
        should_log = 1;
    }
    if ((where & SSL_CB_EXIT) && ret == 0) {
        should_log = 1;
    }

    if (!should_log) {
        return;
    }

    lcb_log(LOGARGS(ssl, LCB_LOG_TRACE), "<%s:%s> sock=%p: ST(0x%x). %s. R(0x%x) %s (%s)",
            sock->info ? sock->info->ep_remote.host : "", sock->info ? sock->info->ep_remote.port : "", (void *)sock,
            where, SSL_state_string_long(ssl), ret, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));

    if (where == SSL_CB_HANDSHAKE_DONE) {
        lcb_log(LOGARGS(ssl, LCB_LOG_DEBUG), "sock=%p. Using SSL version %s. Cipher=%s", (void *)sock,
                SSL_get_version(ssl), SSL_get_cipher_name(ssl));
    }
}

#ifdef LCB_TLS_LOG_KEYS
static void log_keys_callback(const SSL *ssl, const char *line)
{
    const char *log_file_path = getenv("LCB_TLS_KEY_LOG_FILE");
    if (log_file_path) {
        FILE *log_file = fopen(log_file_path, "a+");
        if (log_file) {
            fprintf(log_file, "%s\n", line);
            fclose(log_file);
        }
    }
    (void)ssl;
}
#endif

#if 0
static void
msg_callback(int write_p, int version, int ctype, const void *buf, size_t n,
    SSL *ssl, void *arg)
{
    printf("Got message (%s). V=0x%x. T=%d. N=%lu\n",
        write_p ? ">" : "<", version, ctype, n);
    (void)ssl; (void)arg; (void)buf;
}
#endif

struct lcbio_SSLCTX {
    SSL_CTX *ctx;
};

#define LOGARGS_S(settings, lvl) settings, "SSL", lvl, __FILE__, __LINE__

static long decode_ssl_protocol(const char *protocol)
{
    long disallow = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    if (!protocol) {
        // The caller didn't care.. allow all from TLS 1
        return disallow;
    }
    if (strcasecmp(protocol, "tlsv1.1") == 0) {
        disallow |= SSL_OP_NO_TLSv1;
    } else if (strcasecmp(protocol, "tlsv1.2") == 0) {
        disallow |= SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1;
#ifdef HAVE_CIPHERSUITES
    } else if (strcasecmp(protocol, "tlsv1.3") == 0) {
        disallow |= SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1;
#endif
    }
    return disallow;
}

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
#define lcb_openssl_func_error_string(err) ERR_func_error_string(err)
#else
#define lcb_openssl_func_error_string(err) "unknown"
#endif
static lcb_STATUS add_certificate_authority(const lcb_settings *settings, SSL_CTX *ctx, const char *certificate_value,
                                            int certificate_length)
{
    lcb_STATUS rc = LCB_SUCCESS;
    ERR_clear_error();

    BIO *bio = BIO_new_mem_buf(certificate_value, certificate_length);
    if (bio) {
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        if (store) {
            for (int added = 0;; added = 1) {
                X509 *cert = PEM_read_bio_X509(bio, 0, 0, 0);
                if (!cert) {
                    unsigned long err = ERR_get_error();
                    if (added && ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
                        break;
                    }
                    lcb_log(LOGARGS_S(settings, LCB_LOG_ERROR),
                            "Unable to load default certificate: lib=%s, func=%s, reason=%s", ERR_lib_error_string(err),
                            lcb_openssl_func_error_string(err), ERR_reason_error_string(err));
                    rc = LCB_ERR_SSL_ERROR;
                    goto GT_CLEANUP;
                }

                int ok = X509_STORE_add_cert(store, cert);
                X509_free(cert);
                if (ok != 1) {
                    unsigned long err = ERR_get_error();
                    lcb_log(LOGARGS_S(settings, LCB_LOG_ERROR),
                            "Unable to add default certificate: lib=%s, func=%s, reason=%s", ERR_lib_error_string(err),
                            lcb_openssl_func_error_string(err), ERR_reason_error_string(err));
                    rc = LCB_ERR_SSL_ERROR;
                    goto GT_CLEANUP;
                }
            }
        }
    }
GT_CLEANUP:
    BIO_free(bio);
    return rc;
}

struct tls_key_secret {
    const char *password;
    size_t password_len;
};

static int keyfile_password_cb(char *buf, int size, int rwflag, void *userdata)
{
    (void)rwflag;

    struct tls_key_secret *secret = (struct tls_key_secret *)userdata;
    if (secret->password_len > (size_t)size) {
        return 0;
    }

    memcpy(buf, secret->password, secret->password_len);
    return secret->password_len;
}

lcbio_pSSLCTX lcbio_ssl_new(const char *tsfile, const char *cafile, const char *keyfile, const char *keypass,
                            size_t keypass_len, int noverify, lcb_STATUS *errp, lcb_settings *settings)
{
    lcb_STATUS err_s;
    lcbio_pSSLCTX ret;

    static const char *default_ssl_cipher_list =
        "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-"
        "CBC3-MD5:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:SEED-SHA:RC2-CBC-"
        "MD5:RC4-SHA:RC4-MD5:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5:EXP-EDH-RSA-DES-"
        "CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5:EXP-RC4-MD5:EXP-RC4-MD5";

    const char *cipher_list = getenv("LCB_SSL_CIPHER_LIST");
#ifdef HAVE_CIPHERSUITES
    const char *ciphersuites = getenv("LCB_SSL_CIPHERSUITES");
#endif
    const char *minimum_tls = getenv("LCB_SSL_MINIMUM_TLS");

    if (!cipher_list) {
        cipher_list = default_ssl_cipher_list;
    }

    if (!errp) {
        errp = &err_s;
    }

    ret = calloc(1, sizeof(*ret));
    if (!ret) {
        *errp = LCB_ERR_NO_MEMORY;
        goto GT_ERR;
    }
    ret->ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ret->ctx) {
        *errp = LCB_ERR_SSL_ERROR;
        goto GT_ERR;
    }

    if (SSL_CTX_set_cipher_list(ret->ctx, cipher_list) == 0 && strlen(cipher_list) > 0) {
        /*
         * The client requested a list of ciphers, but openssl don't support
         * any of them.
         */
        *errp = LCB_ERR_SSL_NO_CIPHERS;
        goto GT_ERR;
    }

#ifdef HAVE_CIPHERSUITES
    if (ciphersuites && SSL_CTX_set_ciphersuites(ret->ctx, ciphersuites) == 0 && strlen(ciphersuites) > 0) {
        *errp = LCB_ERR_SSL_INVALID_CIPHERSUITES;
        goto GT_ERR;
    }
#endif

    if (tsfile) {
        lcb_log(LOGARGS_S(settings, LCB_LOG_DEBUG), "Load verify locations from \"%s\"", tsfile ? tsfile : cafile);
        if (!SSL_CTX_load_verify_locations(ret->ctx, tsfile ? tsfile : cafile, NULL)) {
            *errp = LCB_ERR_SSL_ERROR;
            goto GT_ERR;
        }
    } else {
        lcb_log(LOGARGS_S(settings, LCB_LOG_DEBUG), "Use default CA for TLS verify");
        if (SSL_CTX_set_default_verify_paths(ret->ctx) != 1) {
            unsigned long err = ERR_get_error();
            lcb_log(LOGARGS_S(settings, LCB_LOG_WARN), "Unable to load system certificates: lib=%s, reason=%s",
                    ERR_lib_error_string(err), ERR_reason_error_string(err));
        }
        // add the capella Root CA if no other CA was specified.
        *errp = add_certificate_authority(settings, ret->ctx, capella_ca_cert, strlen(capella_ca_cert));
        if (*errp != LCB_SUCCESS) {
            goto GT_ERR;
        }
    }

    if (cafile && keyfile) {
        lcb_log(LOGARGS_S(settings, LCB_LOG_DEBUG), "Authenticate with key \"%s\"%s, cert \"%s\"", keyfile,
                keypass ? " (encrypted)" : "", cafile);
        if (!SSL_CTX_use_certificate_chain_file(ret->ctx, cafile)) {
            *errp = LCB_ERR_SSL_ERROR;
            goto GT_ERR;
        }
        struct tls_key_secret secret = {keypass, keypass_len};
        if (keypass) {
            SSL_CTX_set_default_passwd_cb(ret->ctx, keyfile_password_cb);
            SSL_CTX_set_default_passwd_cb_userdata(ret->ctx, (void *)&secret);
        }
        if (!SSL_CTX_use_PrivateKey_file(ret->ctx, keyfile, SSL_FILETYPE_PEM)) {
            lcb_log(LOGARGS_S(settings, LCB_LOG_ERROR), "Unable to load private key \"%s\"", keyfile);
            *errp = LCB_ERR_SSL_ERROR;
            goto GT_ERR;
        }
        if (!SSL_CTX_check_private_key(ret->ctx)) {
            lcb_log(LOGARGS_S(settings, LCB_LOG_ERROR), "Unable to verify private key \"%s\"", keyfile);
            *errp = LCB_ERR_SSL_ERROR;
            goto GT_ERR;
        }
    }

    if (noverify) {
        SSL_CTX_set_verify(ret->ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(ret->ctx, SSL_VERIFY_PEER, NULL);
    }

    SSL_CTX_set_info_callback(ret->ctx, log_callback);
#ifdef LCB_TLS_LOG_KEYS
    {
        const char *log_file_path = getenv("LCB_TLS_KEY_LOG_FILE");
        if (log_file_path) {
            SSL_CTX_set_keylog_callback(ret->ctx, log_keys_callback);
            lcb_log(
                LOGARGS_S(settings, LCB_LOG_FATAL),
                "LCB_TLS_LOG_KEYS was enabled during build, all TLS keys will be logged for network analysis to \"%s\" "
                "(https://wiki.wireshark.org/TLS). DO NOT USE THIS BUILD IN PRODUCTION",
                log_file_path);
        }
    }
#endif
#if 0
    SSL_CTX_set_msg_callback(ret->ctx, msg_callback);
#endif

    /* this will allow us to do SSL_write and use a different buffer if the
     * first one fails. This is helpful in the scenario where an initial
     * SSL_write() returns an SSL_ERROR_WANT_READ in the ssl_e.c plugin. In
     * such a scenario the correct behavior is to return EWOULDBLOCK. However
     * we have no guarantee that the next time we get a write request we would
     * be using the same buffer.
     */
    SSL_CTX_set_mode(ret->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_options(ret->ctx, decode_ssl_protocol(minimum_tls));
    return ret;

GT_ERR:
    log_global_errors(settings);
    if (ret) {
        if (ret->ctx) {
            SSL_CTX_free(ret->ctx);
        }
        free(ret);
    }
    return NULL;
}

struct proto_ctx_ssl {
    lcbio_PROTOCTX proto;
    SSL *ssl;
};

static void noop_dtor(lcbio_PROTOCTX *arg)
{
    if (!arg) {
        return;
    }
    struct proto_ctx_ssl *sproto = (struct proto_ctx_ssl *)arg;
    SSL_set_app_data(sproto->ssl, NULL);
    free(sproto);
}

lcb_STATUS lcbio_ssl_apply(lcbio_SOCKET *sock, lcbio_pSSLCTX sctx)
{
    lcbio_pTABLE old_iot = sock->io, new_iot;
    struct proto_ctx_ssl *sproto;

    if (old_iot->model == LCB_IOMODEL_EVENT) {
        new_iot = lcbio_Essl_new(old_iot, sock->u.fd, sctx->ctx);
    } else {
        new_iot = lcbio_Cssl_new(old_iot, sock->u.sd, sctx->ctx);
    }

    if (new_iot) {
        sproto = calloc(1, sizeof(*sproto));
        sproto->proto.id = LCBIO_PROTOCTX_SSL;
        sproto->proto.dtor = noop_dtor;
        lcbio_protoctx_add(sock, &sproto->proto);
        lcbio_table_unref(old_iot);
        sock->io = new_iot;
        /* just for logging */
        sproto->ssl = ((lcbio_XSSL *)new_iot)->ssl;
        SSL_set_app_data(((lcbio_XSSL *)new_iot)->ssl, sock);
        return LCB_SUCCESS;

    } else {
        return LCB_ERR_SSL_ERROR;
    }
}

int lcbio_ssl_check(lcbio_SOCKET *sock)
{
    return lcbio_protoctx_get(sock, LCBIO_PROTOCTX_SSL) != NULL;
}

lcb_STATUS lcbio_ssl_get_error(lcbio_SOCKET *sock)
{
    lcbio_XSSL *xs = (lcbio_XSSL *)sock->io;
    return xs->errcode;
}

void lcbio_ssl_free(lcbio_pSSLCTX ctx)
{
    SSL_CTX_free(ctx->ctx);
    free(ctx);
}

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
/**
 * According to https://www.openssl.org/docs/crypto/threads.html we need
 * to install two functions for locking support, a function that returns
 * a thread ID, and a function which performs locking/unlocking. However later
 * on in the link it says it will select a default implementation to return
 * the thread ID, and thus we only need supply the locking function.
 */
#if defined(_POSIX_THREADS)
#include <pthread.h>
typedef pthread_mutex_t ossl_LOCKTYPE;
static void ossl_lock_init(ossl_LOCKTYPE *l)
{
    pthread_mutex_init(l, NULL);
}
static void ossl_lock_acquire(ossl_LOCKTYPE *l)
{
    pthread_mutex_lock(l);
}
static void ossl_lock_release(ossl_LOCKTYPE *l)
{
    pthread_mutex_unlock(l);
}
#elif defined(_WIN32)
#include <windows.h>
typedef CRITICAL_SECTION ossl_LOCKTYPE;
static void ossl_lock_init(ossl_LOCKTYPE *l)
{
    InitializeCriticalSection(l);
}
static void ossl_lock_acquire(ossl_LOCKTYPE *l)
{
    EnterCriticalSection(l);
}
static void ossl_lock_release(ossl_LOCKTYPE *l)
{
    LeaveCriticalSection(l);
}
#else
typedef char ossl_LOCKTYPE;
#define ossl_lock_init(l)
#define ossl_lock_acquire(l)
#define ossl_lock_release(l)
#endif

static ossl_LOCKTYPE *ossl_locks;
static void ossl_lockfn(int mode, int lkid, const char *f, int line)
{
    ossl_LOCKTYPE *l = ossl_locks + lkid;

    if (mode & CRYPTO_LOCK) {
        ossl_lock_acquire(l);
    } else {
        ossl_lock_release(l);
    }

    (void)f;
    (void)line;
}

static void ossl_init_locks(void)
{
    unsigned ii, nlocks;
    if (CRYPTO_get_locking_callback() != NULL) {
        /* Someone already set the callback before us. Don't destroy it! */
        return;
    }
    nlocks = CRYPTO_num_locks();
    ossl_locks = malloc(sizeof(*ossl_locks) * nlocks);
    for (ii = 0; ii < nlocks; ii++) {
        ossl_lock_init(ossl_locks + ii);
    }
    /* TODO: locking API has been removed in OpenSSL 1.1 */
    CRYPTO_set_locking_callback(ossl_lockfn);
    (void)ossl_lockfn;
}
#endif

static volatile int ossl_initialized = 0;
void lcbio_ssl_global_init(void)
{
    if (ossl_initialized) {
        return;
    }
    ossl_initialized = 1;
    SSL_library_init();
    // As of version 1.1.0, OpenSSL automatically allocate all resources that it
    // needs, so explicit initialization is not necessary.
    // More info at OPENSSL_init_ssl(3)
#if OPENSSL_VERSION_NUMBER < 0x1010100fL
    SSL_library_init();
    SSL_load_error_strings();
    ossl_init_locks();
#endif
}

lcb_STATUS lcbio_sslify_if_needed(lcbio_SOCKET *sock, lcb_settings *settings)
{
    if (!(settings->sslopts & LCB_SSL_ENABLED)) {
        return LCB_SUCCESS; /*not needed*/
    }
    if (lcbio_ssl_check(sock)) {
        return LCB_SUCCESS; /*already ssl*/
    }
    return lcbio_ssl_apply(sock, settings->ssl_ctx);
}
