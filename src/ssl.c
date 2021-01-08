/*
 * MIT License
 *
 * Copyright (c) 2019 Jianhui Zhao <zhaojh329@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <unistd.h>
#include <errno.h>

#include "ssl.h"
#include "log.h"

#if UHTTPD_SSL_SUPPORT

void *uh_ssl_ctx_init(const char *cert, const char *key)
{
#if UHTTPD_HAVE_MBEDTLS
    struct mbedtls_ctx *ctx;

    ctx = calloc(1, sizeof(struct mbedtls_ctx));
    if (!ctx) {
        uh_log_err("calloc: %s\n", strerror(errno));
        return NULL;
    }

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&ctx->cache);
#endif
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

    if (mbedtls_x509_crt_parse_file(&ctx->cert, cert) != 0) {
        uh_log_err("Invalid SSL cert\n");
        goto err;
    }

    if (mbedtls_pk_parse_keyfile(&ctx->pkey, key, NULL) != 0) {
        uh_log_err("Invalid SSL key\n");
        goto err;
    }

    if (mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        uh_log_err("Failed to init SSL config\n");
        goto err;
    }

    mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, NULL, 0);
    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&ctx->conf, &ctx->cache,
                                   mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->cert.next, NULL);
    if (mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cert, &ctx->pkey) != 0) {
        uh_log_err("Private key does not match the certificate public key\n");
        goto err;
    }

#else
    SSL_CTX *ctx;

#if UHTTPD_HAVE_WOLFSSL
    wolfSSL_Init();
    ctx = SSL_CTX_new(TLSv1_2_server_method());
#elif OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_server_method());
#else
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_server_method());
#endif

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
        uh_log_err("Invalid SSL cert\n");
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        uh_log_err("Invalid SSL key\n");;
        goto err;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        uh_log_err("Private key does not match the certificate public key\n");
        goto err;
    }
#endif

    return ctx;

err:
#if UHTTPD_HAVE_MBEDTLS
    free(ctx);
#else
    SSL_CTX_free(ctx);
#endif
    return NULL;
}

void uh_ssl_ctx_free(void *ctx)
{
    if (!ctx)
        return;

#if UHTTPD_HAVE_MBEDTLS
    struct mbedtls_ctx *mctx = (struct mbedtls_ctx *)ctx;

    mbedtls_x509_crt_free(&mctx->cert);
    mbedtls_pk_free(&mctx->pkey);
    mbedtls_ssl_config_free(&mctx->conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&mctx->cache);
#endif
    mbedtls_ctr_drbg_free(&mctx->ctr_drbg);
    mbedtls_entropy_free(&mctx->entropy);
#else
    SSL_CTX_free(ctx);
#endif
}

void uh_ssl_free(void *ssl)
{
    if (!ssl)
        return;
#if UHTTPD_HAVE_MBEDTLS
    mbedtls_ssl_free(ssl);
#else
    SSL_shutdown(ssl);
    SSL_free(ssl);
#endif
}

#if UHTTPD_HAVE_MBEDTLS
static const char *mbedtls_err_string(int err)
{
    static char error_buf[200];
    mbedtls_strerror(err, error_buf, 200);
    return error_buf;
}

static int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
    int sock = (intptr_t)ctx;
    int n = write(sock, buf, len);
    if (n >= 0)
        return n;
    return ((errno == EAGAIN || errno == EINPROGRESS) ? MBEDTLS_ERR_SSL_WANT_WRITE : -1);
}

static int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
    int sock = (intptr_t)ctx;
    int n = read(sock, buf, len);
    if (n >= 0)
        return n;
    return ((errno == EAGAIN || errno == EINPROGRESS) ? MBEDTLS_ERR_SSL_WANT_READ : -1);
}
#endif

void *uh_ssl_new(void *ctx, int sock)
{
#if UHTTPD_HAVE_MBEDTLS
    struct mbedtls_ctx *mctx = (struct mbedtls_ctx *)ctx;
    mbedtls_ssl_context *ssl = calloc(1, sizeof(mbedtls_ssl_context));

    mbedtls_ssl_setup(ssl, &mctx->conf);
    mbedtls_ssl_set_bio(ssl, (void *)(intptr_t)sock, mbedtls_net_send, mbedtls_net_recv, NULL);
#else
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
#endif
    return ssl;
}

int uh_ssl_handshake(void *ssl)
{
#if UHTTPD_HAVE_MBEDTLS
    int ret = mbedtls_ssl_handshake(ssl);
    if (ret != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            return UH_SSL_ERROR_AGAIN;
        uh_log_err("SSL handshake failed: %s\n", mbedtls_err_string(ret));
        return UH_SSL_ERROR_UNKNOWN;
    }
#else
    int ret = SSL_accept(ssl);
    if (ret != 1) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return UH_SSL_ERROR_AGAIN;
        uh_log_err("SSL handshake failed: %s\n", ERR_reason_error_string(err));
        return UH_SSL_ERROR_UNKNOWN;
    }
#endif
    return UH_SSL_ERROR_NONE;
}

int uh_ssl_read(void *ssl, void *buf, size_t count)
{
#if UHTTPD_HAVE_MBEDTLS
    int ret = mbedtls_ssl_read(ssl, buf, count);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ)
            return UH_SSL_ERROR_AGAIN;
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            return 0;
        uh_log_err("mbedtls_ssl_read: %s\n", mbedtls_err_string(ret));
        return UH_SSL_ERROR_UNKNOWN;
    }
#else
    int ret = SSL_read(ssl, buf, count);
    if (ret < 0) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ)
            return UH_SSL_ERROR_AGAIN;
        uh_log_err("SSL_read: %s\n", ERR_reason_error_string(err));
        return UH_SSL_ERROR_UNKNOWN;
    }
#endif
    return ret;
}

int uh_ssl_write(void *ssl, void *buf, size_t count)
{
#if UHTTPD_HAVE_MBEDTLS
    int ret = mbedtls_ssl_write(ssl, buf, count);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            return UH_SSL_ERROR_AGAIN;
        uh_log_err("mbedtls_ssl_write: %s\n", mbedtls_err_string(ret));
        return UH_SSL_ERROR_UNKNOWN;
    }
#else
    int ret = SSL_write(ssl, buf, count);
    if (ret < 0) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE)
            return UH_SSL_ERROR_AGAIN;
        uh_log_err("SSL_write: %s\n", ERR_reason_error_string(err));
        return UH_SSL_ERROR_UNKNOWN;
    }
#endif
    return ret;
}

#endif
