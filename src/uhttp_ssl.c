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

	/* registers the error strings for all libssl functions */
	SSL_load_error_strings();
	
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
	SSL_shutdown(con->ssl);
	SSL_free(con->ssl);
#elif (UHTTP_USE_CYASSL)
	wolfSSL_shutdown(con->ssl);
	wolfSSL_free(con->ssl);
#endif
}

#if (UHTTP_SSL_ENABLED)
static int uh_ssl_err(struct uh_connection *con, int ret, const char *fun)
{
	int err;
#if (UHTTP_USE_OPENSSL)
	
	err = SSL_get_error(con->ssl, ret);
	if (err == SSL_ERROR_ZERO_RETURN || ERR_peek_error()) {
		con->flags |= UH_CON_CLOSE;
		return 0;
	}

	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		return -1;

	if (err == SSL_ERROR_SYSCALL) {
		if (errno > 0)
			uh_log_err("%s", fun);
		con->flags |= UH_CON_CLOSE;
		return -1;
	}

	con->flags |= UH_CON_CLOSE;
	uh_log_err("%s() Error: %s", fun, ERR_reason_error_string(err));
	
#elif (UHTTP_USE_CYASSL)
	err = wolfSSL_get_error(con->ssl, ret);
	if (ret == 0 || err == SSL_ERROR_ZERO_RETURN || wolfSSL_ERR_peek_error()) {
		con->flags |= UH_CON_CLOSE;
		return 0;
	}

	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		return -1;

	if (err == SSL_ERROR_SYSCALL) {
		if (errno > 0)
			uh_log_err("%s", fun);
		con->flags |= UH_CON_CLOSE;
		return -1;
	}

	con->flags |= UH_CON_CLOSE;
	uh_log_err("%s() Error: %s", fun, wolfSSL_ERR_reason_error_string(err));
#endif
	return -1;
}
#endif

int uh_ssl_read(struct uh_connection *con, void *buf, int count)
{
	int ret = -1;
#if (UHTTP_SSL_ENABLED)
	if (!con->ssl)
		goto no_ssl;
#endif

#if (UHTTP_USE_OPENSSL)
	ret = SSL_read(con->ssl, buf, count);
	if (ret > 0)
		return ret;

	return uh_ssl_err(con, ret, "SSL_read");
	
#elif (UHTTP_USE_CYASSL)
	ret = wolfSSL_read(con->ssl, buf, count);
	if (ret > 0)
		return ret;

	return uh_ssl_err(con, ret, "wolfSSL_read");

#endif

#if (UHTTP_SSL_ENABLED)
no_ssl:
#endif
	ret = read(con->sock, buf, count);
	if (ret <= 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return ret;
		
		if (ret != 0) {
			con->flags |= UH_CON_CLOSE;
			uh_log_err("read");
		}
	}
	return ret;
}

int uh_ssl_write(struct uh_connection *con, void *buf, int count)
{
	int ret = -1;
#if (UHTTP_SSL_ENABLED)
	if (!con->ssl)
		goto no_ssl;
#endif
	
#if (UHTTP_USE_OPENSSL)
	ret = SSL_write(con->ssl, buf, count);
	if (ret > 0)
		return ret;

	return uh_ssl_err(con, ret, "SSL_write");
	
#elif (UHTTP_USE_CYASSL)
	ret = wolfSSL_write(con->ssl, buf, count);
	if (ret > 0)
		return ret;
	return uh_ssl_err(con, ret, "wolfSSL_write");
#endif

#if (UHTTP_SSL_ENABLED)
	no_ssl:
#endif
	ret = write(con->sock, buf, count);
	if (ret <= 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return ret;
		if (ret != 0) {
			con->flags |= UH_CON_CLOSE;
			uh_log_err("write");
		}
	}
	return ret;
}

int uh_ssl_accept(struct uh_connection *con)
{
	int sock = -1;
	struct uh_server *srv = con->srv; 

	sock = accept4(srv->sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (unlikely(sock < 0)) {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
			uh_log_err("accept4");
		return -1;
	}
	
	con->sock = sock;

#if (UHTTP_SSL_ENABLED)
	if (!srv->ssl_ctx)
		return sock;
#endif

#if (UHTTP_USE_OPENSSL)
	con->ssl = SSL_new(srv->ssl_ctx);
	if (!con->ssl)
		return -1;
	
	if (!SSL_set_fd(con->ssl, sock)) {
		uh_log_err("SSL_set_fd() failed");
		return -1;
	}

	SSL_set_accept_state(con->ssl);
	
#elif (UHTTP_USE_CYASSL)
	con->ssl = wolfSSL_new(srv->ssl_ctx);
	if (!con->ssl)
		return -1;

	if (wolfSSL_set_fd(con->ssl, sock) != SSL_SUCCESS) {
		uh_log_err("wolfSSL_set_fd() failed");
		return -1;
	}

	wolfSSL_set_accept_state(con->ssl);
#endif

	return sock;
}

void uh_ssl_handshake(struct uh_connection *con)
{
#if (UHTTP_SSL_ENABLED)
	int ret;
#if (UHTTP_USE_OPENSSL)
	ret = SSL_do_handshake(con->ssl);
	if (ret == 1) {
		con->flags |= UH_CON_SSL_HANDSHAKE_DONE;
		return;
	}

	uh_ssl_err(con, ret, "SSL_do_handshake");
	
#elif (UHTTP_USE_CYASSL)
	ret = wolfSSL_accept(con->ssl);
	if (ret == SSL_SUCCESS) {
		con->flags |= UH_CON_SSL_HANDSHAKE_DONE;
		return;
	}

	uh_ssl_err(con, ret, "wolfSSL_SSL_do_handshake");
#endif
#endif
}

