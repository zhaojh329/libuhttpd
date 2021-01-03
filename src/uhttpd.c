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
#include <arpa/inet.h>
#include <sys/socket.h>
#ifdef HAVE_DLOPEN
#include <dlfcn.h>
#endif
#include <sys/sysinfo.h>

#include "uhttpd_internal.h"
#include "connection.h"
#include "utils.h"
#include "ssl.h"

static void uh_server_free(struct uh_server *srv)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
    struct uh_connection_internal *conn = srvi->conns;
    struct uh_path_handler *h = srvi->handlers;
#ifdef HAVE_DLOPEN
    struct uh_plugin *p = srvi->plugins;
#endif

    ev_io_stop(srvi->loop, &srvi->ior);

    if (srvi->sock > 0)
        close(srvi->sock);

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

#ifdef HAVE_DLOPEN
    while (p) {
        struct uh_plugin *temp = p;
        dlclose(p->dlh);
        p = p->next;
        free(temp);
    }
#endif

#if UHTTPD_SSL_SUPPORT
    uh_ssl_ctx_free(srvi->ssl_ctx);
#endif
}

static void uh_accept_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_server_internal *srv = container_of(w, struct uh_server_internal, ior);
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

    sock = accept4(srv->sock, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (sock < 0) {
        if (errno != EAGAIN)
            uh_log_err("accept: %s\n", strerror(errno));
        return;
    }

    if (uh_log_get_threshold() == LOG_DEBUG) {
        saddr2str(&addr.sa, addr_str, sizeof(addr_str), &port);
        uh_log_debug("New Connection from: %s %d\n", addr_str, port);
    }

    conn = uh_new_connection(srv, sock, &addr.sa);
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

static void uh_start_accept(struct uh_server_internal *srv)
{
    ev_io_init(&srv->ior, uh_accept_cb, srv->sock, EV_READ);
    ev_io_start(srv->loop, &srv->ior);
}

static void uh_stop_accept(struct uh_server_internal *srv)
{
    ev_io_stop(srv->loop, &srv->ior);
}

static void uh_worker_exit(struct ev_loop *loop, struct ev_child *w, int revents)
{
    struct worker *wk = container_of(w, struct worker, w);

    uh_log_info("worker %d exit\n", wk->i);

    free(wk);
}

static void uh_start_worker(struct uh_server *srv, int n)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
    pid_t pids[20];
    int i;

    if (n < 0)
        n = get_nprocs();

    if (n < 2)
        return;

    uh_stop_accept(srvi);

    for (i = 0; i < n; i++) {
        pids[i] = fork();
        switch (pids[i]) {
        case -1:
            uh_log_err("fork: %s\n", strerror(errno));
            return;
        case 0:
            ev_loop_fork(srvi->loop);
            uh_start_accept(srvi);

            uh_log_info("worker %d started\n", i);

            ev_run(srvi->loop, 0);
            return;
        }
    }

    while (i-- > 0) {
        struct worker *w = calloc(1, sizeof(struct worker));
        w->i = i;
        ev_child_init(&w->w, uh_worker_exit, pids[i], 0);
        ev_child_start(srvi->loop, &w->w);
    }
}

struct uh_server *uh_server_new(struct ev_loop *loop, const char *host, int port)
{
    struct uh_server *srv;

    srv = malloc(sizeof(struct uh_server_internal));
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
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
    srvi->ssl_ctx = uh_ssl_ctx_init(cert, key);
    return srvi->ssl_ctx ? 0 : -1;
}
#endif

static int uh_load_plugin(struct uh_server *srv, const char *path)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
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

int uh_server_init(struct uh_server *srv, struct ev_loop *loop, const char *host, int port)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
    union {
        struct sockaddr     sa;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } addr;
    char addr_str[INET6_ADDRSTRLEN];
    socklen_t addrlen;
    int sock = -1;
    int on = 1;

    if (!host || *host == '\0') {
        addr.sin.sin_family = AF_INET;
        addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (inet_pton(AF_INET, host, &addr.sin.sin_addr) == 1) {
        addr.sa.sa_family = AF_INET;
    } else if (inet_pton(AF_INET6, host, &addr.sin6.sin6_addr) == 1) {
        addr.sa.sa_family = AF_INET6;
    } else {
        static struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_flags = AI_PASSIVE
        };
        struct addrinfo *ais;
        int status;

        status = getaddrinfo(host, NULL, &hints, &ais);
        if (status != 0) {
            uh_log_err("getaddrinfo(): %s\n", gai_strerror(status));
            return -1;
        }

        memcpy(&addr, ais->ai_addr, ais->ai_addrlen);
        freeaddrinfo(ais);
    }

    if (addr.sa.sa_family == AF_INET) {
        addr.sin.sin_port = ntohs(port);
        addrlen = sizeof(addr.sin);
        inet_ntop(AF_INET, &addr.sin.sin_addr, addr_str, sizeof(addr_str));
    } else {
        addr.sin6.sin6_port = ntohs(port);
        addrlen = sizeof(addr.sin6);
        inet_ntop(AF_INET6, &addr.sin6.sin6_addr, addr_str, sizeof(addr_str));
    }

    sock = socket(addr.sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        uh_log_err("socket: %s\n", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0) {
        uh_log_err("setsockopt: %s\n", strerror(errno));
        goto err;
    }

    if (bind(sock, &addr.sa, addrlen) < 0) {
        close(sock);
        uh_log_err("bind: %s\n", strerror(errno));
        goto err;
    }

    listen(sock, SOMAXCONN);

    if (uh_log_get_threshold() == LOG_DEBUG) {
        saddr2str(&addr.sa, addr_str, sizeof(addr_str), &port);
        uh_log_debug("Listen on: %s %d\n", addr_str, port);
    }

    memset(srvi, 0, sizeof(struct uh_server_internal));

    srvi->loop = loop ? loop : EV_DEFAULT;
    srvi->sock = sock;
    srv->free = uh_server_free;
    srv->start_worker = uh_start_worker;

#if UHTTPD_SSL_SUPPORT
    srv->ssl_init = uh_server_ssl_init;
#endif

    srv->load_plugin = uh_load_plugin;

    srv->set_default_handler = uh_set_default_handler;
    srv->add_path_handler = uh_add_path_handler;

    srv->set_docroot = uh_set_docroot;
    srv->set_index_page = uh_set_index_page;

    uh_start_accept(srvi);

    return 0;

err:
    close(sock);
    return -1;
}
