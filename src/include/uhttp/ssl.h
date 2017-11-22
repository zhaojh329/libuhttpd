#ifndef _UHTTP_SSL_H
#define _UHTTP_SSL_H

#include "internal.h"

#if (UHTTP_USE_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef SSL_SUCCESS
#define SSL_SUCCESS 1
#endif

#elif (UHTTP_USE_CYASSL)
#include <wolfssl/ssl.h>

#ifndef SSL_CTX
#define SSL_CTX WOLFSSL_CTX
#endif

#ifndef SSL_library_init
#define SSL_library_init wolfSSL_library_init
#endif

#ifndef SSL_load_error_strings
#define SSL_load_error_strings wolfSSL_library_init
#endif

#ifndef SSLv23_server_method
#define SSLv23_server_method wolfSSLv23_server_method
#endif

#ifndef SSL_CTX_new
#define SSL_CTX_new wolfSSL_CTX_new
#endif

#ifndef SSL_CTX_free
#define SSL_CTX_free(ssl) do {wolfSSL_CTX_free(ssl);wolfSSL_Cleanup();} while(0)
#endif

#ifndef SSL_CTX_use_certificate_file
#define SSL_CTX_use_certificate_file wolfSSL_CTX_use_certificate_file
#endif

#ifndef SSL_CTX_use_RSAPrivateKey_file
#define SSL_CTX_use_RSAPrivateKey_file wolfSSL_CTX_use_PrivateKey_file
#endif

#ifndef SSL_shutdown
#define SSL_shutdown wolfSSL_shutdown
#endif

#ifndef SSL_free
#define SSL_free wolfSSL_free
#endif

#ifndef SSL_accept
#define SSL_accept wolfSSL_accept
#endif

#ifndef SSL_new
#define SSL_new wolfSSL_new
#endif

#ifndef SSL_set_fd
#define SSL_set_fd wolfSSL_set_fd
#endif

#ifndef SSL_set_accept_state
#define SSL_set_accept_state wolfSSL_set_accept_state
#endif

#ifndef SSL_write
#define SSL_write wolfSSL_write
#endif

#ifndef SSL_read
#define SSL_read wolfSSL_read
#endif

#ifndef SSL_get_error
#define SSL_get_error wolfSSL_get_error
#endif

#ifndef ERR_reason_error_string
#define ERR_reason_error_string wolfSSL_ERR_reason_error_string
#endif

#ifndef ERR_peek_error
#define ERR_peek_error wolfSSL_ERR_peek_error
#endif

#endif

void uh_ssl_ctx_free(struct uh_server *srv);
void uh_ssl_free(struct uh_connection *con);
int uh_ssl_read(struct uh_connection *con, void *buf, int count);
int uh_ssl_write(struct uh_connection *con, void *buf, int count);
int uh_ssl_accept(struct uh_connection *con);
void uh_ssl_handshake(struct uh_connection *con);

#endif
