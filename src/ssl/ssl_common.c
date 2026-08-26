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

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error "libcouchbase requires OpenSSL >= 1.1.1; the build system should have caught this"
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

/**
 * Translates LCB_SSL_MINIMUM_TLS into the lowest protocol version the
 * connection may negotiate. The floor is TLS 1.2: RFC 8996 deprecated TLS
 * 1.0 and 1.1 in March 2021, NIST SP 800-52r2 requires 1.2 or above, and
 * every supported Couchbase Server release speaks 1.2.
 *
 * An unrecognised value keeps that floor rather than lowering it, and says
 * so; an operator who mistyped the variable would otherwise be left
 * believing they had changed something.
 */
static int decode_ssl_protocol(const char *protocol, const lcb_settings *settings)
{
    if (protocol == NULL) {
        return TLS1_2_VERSION;
    }
    if (strcasecmp(protocol, "tlsv1") == 0) {
        return TLS1_VERSION;
    }
    if (strcasecmp(protocol, "tlsv1.1") == 0) {
        return TLS1_1_VERSION;
    }
    if (strcasecmp(protocol, "tlsv1.2") == 0) {
        return TLS1_2_VERSION;
    }
    if (strcasecmp(protocol, "tlsv1.3") == 0) {
        return TLS1_3_VERSION;
    }
    lcb_log(LOGARGS_S(settings, LCB_LOG_WARN),
            "Unrecognized LCB_SSL_MINIMUM_TLS value \"%s\", keeping the minimum at TLS 1.2. "
            "Supported values are tlsv1, tlsv1.1, tlsv1.2 and tlsv1.3",
            protocol);
    return TLS1_2_VERSION;
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

    /* Cipher selection is delegated to OpenSSL's built-in defaults, which on
     * 1.1.1+ exclude RC4, DES/3DES, MD5, and EXPORT-grade suites by default.
     * A caller can still narrow or widen the list via LCB_SSL_CIPHER_LIST
     * (TLS <= 1.2) or LCB_SSL_CIPHERSUITES (TLS 1.3). */
    const char *cipher_list = getenv("LCB_SSL_CIPHER_LIST");
    const char *ciphersuites = getenv("LCB_SSL_CIPHERSUITES");
    const char *minimum_tls = getenv("LCB_SSL_MINIMUM_TLS");

    if (!errp) {
        errp = &err_s;
    }

    ret = calloc(1, sizeof(*ret));
    if (!ret) {
        *errp = LCB_ERR_NO_MEMORY;
        goto GT_ERR;
    }
    ret->ctx = SSL_CTX_new(TLS_client_method());
    if (!ret->ctx) {
        *errp = LCB_ERR_SSL_ERROR;
        goto GT_ERR;
    }

    if (cipher_list && strlen(cipher_list) > 0 && SSL_CTX_set_cipher_list(ret->ctx, cipher_list) == 0) {
        /* The user supplied a cipher list but OpenSSL supports none of them. */
        *errp = LCB_ERR_SSL_NO_CIPHERS;
        goto GT_ERR;
    }

    if (ciphersuites && strlen(ciphersuites) > 0 && SSL_CTX_set_ciphersuites(ret->ctx, ciphersuites) == 0) {
        *errp = LCB_ERR_SSL_INVALID_CIPHERSUITES;
        goto GT_ERR;
    }

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
    /* A version floor, rather than a mask of SSL_OP_NO_* bits: the mask has to
     * be extended every time a protocol version is added, and a floor does not.
     * Any floor at TLS 1.0 or above excludes SSLv2 and SSLv3 on its own. */
    if (!SSL_CTX_set_min_proto_version(ret->ctx, decode_ssl_protocol(minimum_tls, settings))) {
        *errp = LCB_ERR_SSL_ERROR;
        goto GT_ERR;
    }
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

int lcbio_ssl_min_proto_version(lcbio_pSSLCTX ctx)
{
    return (int)SSL_CTX_get_min_proto_version(ctx->ctx);
}

void lcbio_ssl_free(lcbio_pSSLCTX ctx)
{
    SSL_CTX_free(ctx->ctx);
    free(ctx);
}

void lcbio_ssl_global_init(void)
{
    /* OpenSSL >= 1.1.0 initialises itself lazily on first use and handles
     * threading internally (see OPENSSL_init_ssl(3)). Since this build
     * requires >= 1.1.1 there is nothing to do here, but the symbol is
     * retained so callers don't need to know that. */
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
