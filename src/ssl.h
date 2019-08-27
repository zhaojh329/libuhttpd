/*
 * MIT License
 *
 * Copyright (c) 2019 Jianhui Zhao <jianhuizhao329@gmail.com>
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

#ifndef _UH_SSL_H
#define _UH_SSL_H

#include "config.h"
#include "log.h"

#if UHTTPD_SSL_SUPPORT

#if UHTTPD_HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#elif UHTTPD_HAVE_WOLFSSL
#define WC_NO_HARDEN
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#else
#include <mbedtls/debug.h>
#include <mbedtls/ecp.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#include <mbedtls/ssl_cache.h>
#endif

struct mbedtls_ctx {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif
};

#endif

#define UH_SSL_ERROR_NONE       0
#define UH_SSL_ERROR_AGAIN      -1
#define UH_SSL_ERROR_UNKNOWN    -2

void *uh_ssl_ctx_init(const char *cert, const char *key);
void uh_ssl_ctx_free(void *ctx);
void uh_ssl_free(void *ssl);

void *uh_ssl_new(void *ctx, int sock);
int uh_ssl_handshake(void *ssl);
int uh_ssl_read(void *ssl, void *buf, size_t count);
int uh_ssl_write(void *ssl, void *buf, size_t count);

#endif

#endif
