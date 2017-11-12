#ifndef _UHTTP_SSL_H
#define _UHTTP_SSL_H

#include "uhttp_internal.h"

void uh_ssl_ctx_free(struct uh_server *srv);
void uh_ssl_free(struct uh_connection *con);
int uh_ssl_read(struct uh_connection *con, void *buf, int count);
int uh_ssl_write(struct uh_connection *con, void *buf, int count);
int uh_ssl_accept(struct uh_connection *con);
void uh_ssl_handshake(struct uh_connection *con);

#endif
