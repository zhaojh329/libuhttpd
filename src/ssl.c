#include "uhttp/ssl.h"
#include <unistd.h>
#include <sys/socket.h>

#if (UHTTP_SSL_ENABLED)
int uh_ssl_init(struct uh_server *srv, const char *cert, const char *key)
{
    SSL_CTX *ctx = NULL;

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
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
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
    if (SSL_CTX_use_RSAPrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        uh_log_err("OpenSSL Error: loading key failed");
        goto err;
    }

    srv->ssl_ctx = ctx;
    return 0;
    
err:
    SSL_CTX_free(ctx);
    return -1;
}
#endif

void uh_ssl_ctx_free(struct uh_server *srv)
{
#if (UHTTP_SSL_ENABLED)
    if (!srv->ssl_ctx)
        return;
    SSL_CTX_free(srv->ssl_ctx);
#endif
}

void uh_ssl_free(struct uh_connection *con)
{
#if (UHTTP_SSL_ENABLED)
    if (!con->ssl)
        return;
    SSL_shutdown(con->ssl);
    SSL_free(con->ssl);
#endif
}

#if (UHTTP_SSL_ENABLED)
static int uh_ssl_err(struct uh_connection *con, int ret, const char *fun)
{
    int err;
    err = SSL_get_error(con->ssl, ret);
    if (err == SSL_ERROR_ZERO_RETURN || ERR_peek_error()) {
        con->flags |= UH_CON_CLOSE;
        return 0;
    }
    
#if (UHTTP_USE_OPENSSL)
    if (ret == 0) {
        con->flags |= UH_CON_CLOSE;
        return 0;
    }
#endif

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
    
    return -1;
}
#endif

int uh_ssl_read(struct uh_connection *con, void *buf, int count)
{
    int ret = -1;
#if (UHTTP_SSL_ENABLED)
    if (!con->ssl)
        goto no_ssl;

    ret = SSL_read(con->ssl, buf, count);
    if (ret > 0)
        return ret;

    return uh_ssl_err(con, ret, "SSL_read");
no_ssl:
#endif
    ret = read(con->sock, buf, count);
    if (ret <= 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return ret;
        
        if (ret != 0)
            uh_log_err("read");
        else
            uh_log_debug("peer closed");

        con->flags |= UH_CON_CLOSE;
    }
    return ret;
}

int uh_ssl_write(struct uh_connection *con, void *buf, int count)
{
    int ret = -1;
#if (UHTTP_SSL_ENABLED)
    if (!con->ssl)
        goto no_ssl;

    ret = SSL_write(con->ssl, buf, count);
    if (ret > 0)
        return ret;

    return uh_ssl_err(con, ret, "SSL_write");
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

    con->ssl = SSL_new(srv->ssl_ctx);
    if (!con->ssl)
        return -1;
        
    if (!SSL_set_fd(con->ssl, sock)) {
        uh_log_err("SSL_set_fd() failed");
        return -1;
    }
    
    SSL_set_accept_state(con->ssl);
#endif
    
    return sock;
}

void uh_ssl_handshake(struct uh_connection *con)
{
#if (UHTTP_SSL_ENABLED)
    int ret = SSL_accept(con->ssl);
    if (ret == 1) {
        con->flags |= UH_CON_SSL_HANDSHAKE_DONE;
        return;
    }

    uh_ssl_err(con, ret, "SSL_accept");
#endif
}

