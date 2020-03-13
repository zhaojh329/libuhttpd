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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "uhttpd.h"
#include "utils.h"
#include "ssl.h"
#include "log.h"

static void uh_server_free(struct uh_server *srv)
{
    struct uh_connection *conn = srv->conns;

    ev_io_stop(srv->loop, &srv->ior);

    if (srv->sock > 0)
        close(srv->sock);

    while (conn) {
        struct uh_connection *next = conn->next;
        conn->free(conn);
        conn = next;
    }

#if UHTTPD_SSL_SUPPORT
    uh_ssl_ctx_free(srv->ssl_ctx);
#endif
}

static void uh_accept_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_server *srv = container_of(w, struct uh_server, ior);
    struct uh_connection *conn;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int sock;

    sock = accept4(srv->sock, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK);
    if (sock < 0) {
        uh_log_err("accept: %s\n", strerror(errno));
        return;
    }

    uh_log_debug("New connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    conn = uh_new_connection(srv, sock, &addr);
    if (!conn)
        return;

    if (!srv->conns) {
        srv->conns = conn;
        return;
    }

    conn->next = srv->conns;
    srv->conns->prev = conn;
    srv->conns = conn;
}

struct uh_server *uh_server_new(struct ev_loop *loop, const char *host, int port)
{
    struct uh_server *srv;

    srv = malloc(sizeof(struct uh_server));
    if (!srv) {
        uh_log_err("malloc: %s\n", strerror(errno));
        return NULL;
    }

    if (uh_server_init(srv, loop, host, port) < 0) {
        free(srv);
        return NULL;
    }

    return srv;
}

#if UHTTPD_SSL_SUPPORT
static int uh_server_ssl_init(struct uh_server *srv, const char *cert, const char *key)
{
    srv->ssl_ctx = uh_ssl_ctx_init(cert, key);
    return srv->ssl_ctx ? 0 : -1;
}
#endif

int uh_server_init(struct uh_server *srv, struct ev_loop *loop, const char *host, int port)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port)
    };
    int sock = -1;
    int opt = 1;

    memset(srv, 0, sizeof(struct uh_server));

    if (host)
        addr.sin_addr.s_addr = inet_addr(host);

    sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        uh_log_err("socket: %s\n", strerror(errno));
        return -1;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        uh_log_err("bind: %s\n", strerror(errno));
        return -1;
    }

    listen(sock, SOMAXCONN);

    srv->loop = loop ? loop : EV_DEFAULT;
    srv->sock = sock;
    srv->free = uh_server_free;

#if UHTTPD_SSL_SUPPORT
    srv->ssl_init = uh_server_ssl_init;
#endif

    ev_io_init(&srv->ior, uh_accept_cb, sock, EV_READ);
    ev_io_start(srv->loop, &srv->ior);

    return 0;
}

