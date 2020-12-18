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
#include <arpa/inet.h>
#include <sys/socket.h>
#ifdef HAVE_DLOPEN
#include <dlfcn.h>
#endif

#include "uhttpd.h"
#include "utils.h"
#include "ssl.h"
#include "log.h"

void conn_free(struct uh_connection *conn);

static void uh_server_free(struct uh_server *srv)
{
    struct uh_connection *conn = srv->conns;
    struct uh_path_handler *h = srv->handlers;
#ifdef HAVE_DLOPEN
    struct uh_plugin *p = srv->plugins;
#endif

    ev_io_stop(srv->loop, &srv->ior);

    if (srv->sock > 0)
        close(srv->sock);

    while (conn) {
        struct uh_connection *next = conn->next;
        conn_free(conn);
        conn = next;
    }

    while (h) {
        struct uh_path_handler *temp = h;
        h = h->next;
        free(temp);
    }

#ifdef HAVE_DLOPEN
    while (p) {
        struct uh_plugin *temp = p;
        dlclose(p->dlh);
        p = p->next;
        free(temp);
    }
#endif

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

static int uh_load_plugin(struct uh_server *srv, const char *path)
{
#ifdef HAVE_DLOPEN
    struct uh_plugin_handler *h;
    struct uh_plugin *p;
    void *dlh;

    dlh = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!dlh) {
        uh_log_err("dlopen fail: %s\n", dlerror());
        return -1;
    }

    h = dlsym(dlh, "uh_plugin_handler");
    if (!h) {
        dlclose(dlh);
        uh_log_err("not found symbol 'uh_plugin_handler'\n");
        return -1;
    }

    if (!h->path || !h->path[0] || !h->handler) {
        dlclose(dlh);
        uh_log_err("invalid plugin\n");
        return -1;
    }

    p = calloc(1, sizeof(struct uh_plugin));
    if (!p) {
        uh_log_err("calloc: %s\n", strerror(errno));
        return -1;
    }

    p->h = h;
    p->dlh = dlh;

    if (!srv->plugins) {
        srv->plugins = p;
        return 0;
    }

    p->next = srv->plugins;
    srv->plugins = p;

    return 0;
#else
    uh_log_err("Not support plugin\n");
    return -1;
#endif
}

static int uh_add_path_handler(struct uh_server *srv, const char *path, uh_path_handler_prototype handler)
{
    struct uh_path_handler *h;

    h = calloc(1, sizeof(struct uh_path_handler) + strlen(path) + 1);
    if (!h) {
        uh_log_err("calloc: %s\n", strerror(errno));
        return -1;
    }

    h->handler = handler;
    strcpy(h->path, path);

    if (!srv->handlers) {
        srv->handlers = h;
        return 0;
    }

    h->next = srv->handlers;
    srv->handlers = h;

    return 0;
}

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

    srv->load_plugin = uh_load_plugin;

    srv->add_path_handler = uh_add_path_handler;

    ev_io_init(&srv->ior, uh_accept_cb, sock, EV_READ);
    ev_io_start(srv->loop, &srv->ior);

    return 0;
}

