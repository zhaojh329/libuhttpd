#include "uhttp_ssl.h"
#include <unistd.h>
#include <sys/socket.h>

#if (UHTTP_USE_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>
#elif (UHTTP_USE_CYASSL)
#include <wolfssl/ssl.h>
#endif

int uh_ssl_init(struct uh_server *srv, const char *cert, const char *key)
{
#if (UHTTP_USE_OPENSSL)
	SSL_CTX *ctx = NULL;
#elif (UHTTP_USE_CYASSL)
	WOLFSSL_CTX *ctx = NULL;
#endif

#if (UHTTP_USE_OPENSSL)
	SSL_library_init();

	/* creates a new SSL_CTX object */
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		uh_log_err("Failed to create SSL context");
		return -1;
	}

	/* loads the first certificate stored in file into ctx */
	if (!SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM)) {
		uh_log_err("OpenSSL Error: loading certificate file failed");
		goto err;
	}
		
	/*
	 * adds the first private RSA key found in file to ctx.
	 *
	 * checks the consistency of a private key with the corresponding 
	 * certificate loaded into ctx. If more than one key/certificate 
	 * pair (RSA/DSA) is installed, the last item installed will be checked.
	 */
	if (!SSL_CTX_use_RSAPrivateKey_file(ctx, key, SSL_FILETYPE_PEM)) {
		uh_log_err("OpenSSL Error: loading key failed");
		goto err;
	}

#elif (UHTTP_USE_CYASSL)
	/* Initialize wolfSSL */
	wolfSSL_Init();

	/* Create the WOLFSSL_CTX */
	ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
	if (!ctx) {
		uh_log_err("Failed to create wolfSSL context");
		return -1;
	}

	/* Load server certificates into WOLFSSL_CTX */
	if (wolfSSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
		uh_log_err("wolfSSL Error: loading certificate file failed");
		goto err;
	}

	/* Load keys */
	if (wolfSSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != SSL_SUCCESS){
		uh_log_err("wolfSSL Error: loading key failed");
		goto err;
	}

#endif

#if (UHTTP_SSL_ENABLED)
	srv->ssl_ctx = ctx;
#endif
	return 0;
#if (UHTTP_SSL_ENABLED)
err:
#if (UHTTP_USE_OPENSSL)
	SSL_CTX_free(ctx);
#elif (UHTTP_USE_CYASSL)
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
#endif
#endif

	return -1;
}

void uh_ssl_ctx_free(struct uh_server *srv)
{
#if (UHTTP_SSL_ENABLED)
	if (!srv->ssl_ctx)
		return;
#endif

#if (UHTTP_USE_OPENSSL)
	SSL_CTX_free(srv->ssl_ctx);
#elif (UHTTP_USE_CYASSL)
	wolfSSL_CTX_free(srv->ssl_ctx);
#endif
}

void uh_ssl_free(struct uh_connection *con)
{
#if (UHTTP_SSL_ENABLED)
	if (!con->ssl)
		return;
#endif

#if (UHTTP_USE_OPENSSL)
	SSL_free(con->ssl);
#elif (UHTTP_USE_CYASSL)
	wolfSSL_free(con->ssl);
#endif
}

int uh_ssl_read(struct uh_connection *con, void *buf, int count)
{
#if (UHTTP_SSL_ENABLED)
	if (!con->ssl)
		return read(con->sock, buf, count);
#endif

#if (UHTTP_USE_OPENSSL)
	return SSL_read(con->ssl, buf, count);
#elif (UHTTP_USE_CYASSL)
	return wolfSSL_read(con->ssl, buf, count);
#endif

	return read(con->sock, buf, count);
}

int uh_ssl_write(struct uh_connection *con, void *buf, int count)
{
#if (UHTTP_SSL_ENABLED)
	if (!con->ssl)
		return write(con->sock, buf, count);
#endif
	
#if (UHTTP_USE_OPENSSL)
	return SSL_write(con->ssl, buf, count);
#elif (UHTTP_USE_CYASSL)
	return wolfSSL_write(con->ssl, buf, count);
#endif

	return write(con->sock, buf, count);
}

int uh_ssl_accept(struct uh_server *srv, struct uh_connection *con)
{
	int sock = -1;

	sock = accept4(srv->sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (sock < 0)
		return sock;
	
	con->sock = sock;

#if (UHTTP_SSL_ENABLED)
	if (!srv->ssl_ctx)
		return sock;
#endif

#if (UHTTP_USE_OPENSSL)	
	con->ssl = SSL_new(srv->ssl_ctx);
	if (!con->ssl)
		return -1;
	
	SSL_set_fd(con->ssl, sock);
	
	if (!SSL_accept(con->ssl)) {
		uh_log_err("SSL_accept Error: %s", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
#elif (UHTTP_USE_CYASSL)
	con->ssl = wolfSSL_new(srv->ssl_ctx);
	if (!con->ssl)
		return -1;

	wolfSSL_set_fd(con->ssl, sock);
#endif

	return sock;
}

