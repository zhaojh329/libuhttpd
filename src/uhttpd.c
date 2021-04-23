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
#include <netdb.h>
#include <sys/socket.h>
#ifdef HAVE_DLOPEN
#include <dlfcn.h>
#endif

#include "uhttpd_internal.h"
#include "connection.h"
#include "utils.h"


static void uh_server_free(struct uh_server *srv)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
    struct uh_connection_internal *conn = srvi->conns;
    struct uh_path_handler *h = srvi->handlers;
    struct uh_listener *l = srvi->listeners;
#ifdef HAVE_DLOPEN
    struct uh_plugin *p = srvi->plugins;
#endif

    if (srvi->docroot)
        free(srvi->docroot);

    if (srvi->index_page)
        free(srvi->index_page);

    while (conn) {
        struct uh_connection_internal *next = conn->next;
        conn_free(conn);
        conn = next;
    }

    while (h) {
        struct uh_path_handler *temp = h;
        h = h->next;
        free(temp);
    }

    while (l) {
        struct uh_listener *temp = l;

        ev_io_stop(srvi->loop, &l->ior);

        if (l->sock > 0)
            close(l->sock);

        l = l->next;
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

#ifdef SSL_SUPPORT
    ssl_context_free(srvi->ssl_ctx);
#endif
}

static void uh_accept_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_listener *l = container_of(w, struct uh_listener, ior);
    struct uh_server_internal *srv = l->srv;
    struct uh_connection_internal *conn;
    union {
        struct sockaddr     sa;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } addr;
    socklen_t addr_len = sizeof(addr);
    char addr_str[INET6_ADDRSTRLEN];
    int port;
    int sock;

    sock = accept4(l->sock, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (sock < 0) {
        if (errno != EAGAIN)
            uh_log_err("accept: %s\n", strerror(errno));
        return;
    }

    if (uh_log_get_threshold() == LOG_DEBUG) {
        saddr2str(&addr.sa, addr_str, sizeof(addr_str), &port);
        uh_log_debug("New Connection from: %s %d\n", addr_str, port);
    }

    if (l->ssl) {
#ifdef SSL_SUPPORT
        if (!srv->ssl_ctx) {
            uh_log_err("SSL not initialized\n");
            close(sock);
            return;
        }
#else
        close(sock);
        uh_log_err("SSL not enabled when build\n");
        return;
#endif
    }

    conn = uh_new_connection(l, sock, &addr.sa);
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

struct uh_server *uh_server_new(struct ev_loop *loop)
{
    struct uh_server *srv;

    srv = malloc(sizeof(struct uh_server_internal));
    if (!srv) {
        uh_log_err("malloc: %s\n", strerror(errno));
        return NULL;
    }

    uh_server_init(srv, loop);

    return srv;
}

#ifdef SSL_SUPPORT
static int uh_server_ssl_init(struct uh_server *srv, const char *cert, const char *key)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    srvi->ssl_ctx = ssl_context_new(true);
    if (!srvi->ssl_ctx) {
        uh_log_err("ssl context init fail\n");
        return -1;
    }

    if (ssl_load_crt_file(srvi->ssl_ctx, cert)) {
        uh_log_err("load certificate file fail\n");
        return -1;
    }

    if (ssl_load_key_file(srvi->ssl_ctx, key)) {
        uh_log_err("load private key file fail\n");
        return -1;
    }

    return 0;
}
#endif

static int uh_load_plugin(struct uh_server *srv, const char *path)
{
#ifdef HAVE_DLOPEN
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
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

    if (!srvi->plugins) {
        srvi->plugins = p;
        return 0;
    }

    p->next = srvi->plugins;
    srvi->plugins = p;

    return 0;
#else
    uh_log_err("Not support plugin\n");
    return -1;
#endif
}

static int uh_add_path_handler(struct uh_server *srv, const char *path, uh_path_handler_prototype handler)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
    struct uh_path_handler *h;

    h = calloc(1, sizeof(struct uh_path_handler) + strlen(path) + 1);
    if (!h) {
        uh_log_err("calloc: %s\n", strerror(errno));
        return -1;
    }

    h->handler = handler;
    strcpy(h->path, path);

    if (!srvi->handlers) {
        srvi->handlers = h;
        return 0;
    }

    h->next = srvi->handlers;
    srvi->handlers = h;

    return 0;
}

static void uh_set_conn_abort_cb(struct uh_server *srv, uh_con_closed_cb_prototype cb)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    srvi->conn_closed_cb = cb;
}

static void uh_set_default_handler(struct uh_server *srv, uh_path_handler_prototype handler)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    srvi->default_handler = handler;
}

static int uh_set_docroot(struct uh_server *srv, const char *path)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    if (srvi->docroot)
        free(srvi->docroot);

    srvi->docroot = strdup(path);
    if (!srvi->docroot) {
        uh_log_err("strdup: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int uh_set_index_page(struct uh_server *srv, const char *name)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    if (srvi->index_page)
        free(srvi->index_page);

    srvi->index_page = strdup(name);
    if (!srvi->index_page) {
        uh_log_err("strdup: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static struct ev_loop *uh_get_loop(struct uh_server *srv)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    return srvi->loop;
}

static int parse_address(const char *addr, char **host, char **port)
{
    static char buf[256];
    char *s;
    int l;

    strcpy(buf, addr);

    *host = NULL;
    *port = buf;

    s = strrchr(buf, ':');
    if (!s)
        return -1;

    *host = buf;
    *port = s + 1;
    *s = 0;

    if (*host && **host == '[') {
        l = strlen(*host);
        if (l >= 2) {
            (*host)[l - 1] = 0;
            (*host)++;
        }
    }

    if ((*host)[0] == '\0')
        *host = "0";

    return 0;
}

static int uh_server_listen(struct uh_server *srv, const char *addr, bool ssl)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
    struct uh_listener *l;
    char *host, *port;
    struct addrinfo *addrs = NULL, *p = NULL;
    static struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
    };
    char addr_str[INET6_ADDRSTRLEN];
    int bound = 0;
    int on = 1;
    int status;
    int sock;

    if (parse_address(addr, &host, &port) < 0) {
        uh_log_err("invalid address\n");
        return -1;
    }

    status = getaddrinfo(host, port, &hints, &addrs);
    if (status != 0) {
        uh_log_err("getaddrinfo(): %s\n", gai_strerror(status));
        return -1;
    }

    /* try to bind a new socket to each found address */
    for (p = addrs; p; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, p->ai_protocol);
        if (sock < 0) {
            uh_log_err("socket: %s\n", strerror(errno));
            continue;
        }

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0) {
            uh_log_err("setsockopt: %s\n", strerror(errno));
            goto err;
        }

        /* required to get parallel v4 + v6 working */
        if (p->ai_family == AF_INET6 && setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(int)) < 0) {
            uh_log_err("setsockopt: %s\n", strerror(errno));
            goto err;
        }

        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(int));

        if (bind(sock, p->ai_addr, p->ai_addrlen) < 0) {
            uh_log_err("bind: %s\n", strerror(errno));
            goto err;
        }

        if (listen(sock, SOMAXCONN) < 0) {
            uh_log_err("bind: %s\n", strerror(errno));
            goto err;
        }

        l = calloc(1, sizeof(struct uh_listener));
        if (!l) {
            uh_log_err("calloc: %s\n", strerror(errno));
            goto err;
        }

        l->sock = sock;
        l->ssl = ssl;
        l->srv = srvi;

        ev_io_init(&l->ior, uh_accept_cb, sock, EV_READ);
        ev_io_start(srvi->loop, &l->ior);

        if (!srvi->listeners) {
            srvi->listeners = l;
        } else {
            l->next = srvi->listeners;
            srvi->listeners = l;
        }

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ina = (struct sockaddr_in *)p->ai_addr;
            inet_ntop(p->ai_family, &ina->sin_addr, addr_str, sizeof(addr_str));
            uh_log_debug("Listen on: %s:%d with ssl %s\n", addr_str, ntohs(ina->sin_port), ssl ? "on" : "off");
        } else {
            struct sockaddr_in6 *in6a = (struct sockaddr_in6 *)p->ai_addr;
            inet_ntop(p->ai_family, &in6a->sin6_addr, addr_str, sizeof(addr_str));
            uh_log_debug("Listen on: [%s]:%d with ssl %s\n", addr_str, ntohs(in6a->sin6_port), ssl ? "on" : "off");
        }

        bound++;

        continue;

err:
        if (sock > -1)
           close(sock);
    }

    freeaddrinfo(addrs);

    return bound;
}

void uh_server_init(struct uh_server *srv, struct ev_loop *loop)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    memset(srvi, 0, sizeof(struct uh_server_internal));

    srvi->loop = loop ? loop : EV_DEFAULT;

    srv->get_loop = uh_get_loop;
    srv->free = uh_server_free;

    srv->listen = uh_server_listen;

#ifdef SSL_SUPPORT
    srv->ssl_init = uh_server_ssl_init;
#endif

    srv->load_plugin = uh_load_plugin;

    srv->set_conn_closed_cb = uh_set_conn_abort_cb;
    srv->set_default_handler = uh_set_default_handler;
    srv->add_path_handler = uh_add_path_handler;

    srv->set_docroot = uh_set_docroot;
    srv->set_index_page = uh_set_index_page;
}
