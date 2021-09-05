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

static void uh_server_free_conns(struct list_head *head)
{
    struct uh_connection_internal *pos, *n;

    list_for_each_entry_safe(pos, n, head, list) {
        conn_free(pos);
    }
}

static void uh_server_free_handlers(struct list_head *head)
{
    struct uh_path_handler *pos, *n;

    list_for_each_entry_safe(pos, n, head, list) {
        list_del(&pos->list);
        free(pos);
    }
}

static void uh_server_free_plugins(struct list_head *head)
{
#ifdef HAVE_DLOPEN
    struct uh_plugin *pos, *n;

    list_for_each_entry_safe(pos, n, head, list) {
        list_del(&pos->list);
        dlclose(pos->dlh);
        free(pos);
    }
#endif
}

static void uh_server_free_listeners(struct list_head *head)
{
    struct uh_listener *pos, *n;

    list_for_each_entry_safe(pos, n, head, list) {
        ev_io_stop(pos->srv->loop, &pos->ior);

        list_del(&pos->list);

        if (pos->sock > 0)
            close(pos->sock);

        free(pos);
    }
}

static void uh_server_free(struct uh_server *srv)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    if (srvi->docroot)
        free(srvi->docroot);

    if (srvi->index_page)
        free(srvi->index_page);

    uh_server_free_conns(&srvi->conns);
    uh_server_free_handlers(&srvi->handlers);
    uh_server_free_plugins(&srvi->plugins);
    uh_server_free_listeners(&srvi->listeners);

#ifdef SSL_SUPPORT
    ssl_context_free(srvi->ssl_ctx);
#endif
}

static void uh_accept_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_listener *l = container_of(w, struct uh_listener, ior);
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
            log_err("accept: %s\n", strerror(errno));
        return;
    }

    log_debug("New Connection from %s %d\n", addr_str,
            (saddr2str(&addr.sa, addr_str, sizeof(addr_str), &port) ? port : 0));

    if (l->ssl) {
#ifdef SSL_SUPPORT
        if (!l->srv->ssl_ctx) {
            log_err("SSL not initialized\n");
            close(sock);
            return;
        }
#else
        close(sock);
        log_err("SSL not enabled when build\n");
        return;
#endif
    }

    uh_new_connection(l, sock, &addr.sa);
}

struct uh_server *uh_server_new(struct ev_loop *loop)
{
    struct uh_server *srv;

    srv = malloc(sizeof(struct uh_server_internal));
    if (!srv) {
        log_err("malloc: %s\n", strerror(errno));
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
        log_err("ssl context init fail\n");
        return -1;
    }

    if (ssl_load_crt_file(srvi->ssl_ctx, cert)) {
        log_err("load certificate file fail\n");
        return -1;
    }

    if (ssl_load_key_file(srvi->ssl_ctx, key)) {
        log_err("load private key file fail\n");
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
        log_err("dlopen fail: %s\n", dlerror());
        return -1;
    }

    h = dlsym(dlh, "uh_plugin_handler");
    if (!h) {
        dlclose(dlh);
        log_err("not found symbol 'uh_plugin_handler'\n");
        return -1;
    }

    if (!h->path || !h->path[0] || !h->handler) {
        dlclose(dlh);
        log_err("invalid plugin\n");
        return -1;
    }

    p = calloc(1, sizeof(struct uh_plugin));
    if (!p) {
        log_err("calloc: %s\n", strerror(errno));
        return -1;
    }

    p->h = h;
    p->dlh = dlh;
    p->path = h->path;
    p->len = strlen(h->path);

    if (h->path[0] == '^') {
        p->flags |= UH_PATH_MATCH_START;
        p->len--;
        p->path++;
    }

    if (p->path[p->len - 1] == '$') {
        p->flags |= UH_PATH_MATCH_END;
        p->len--;
    }

    list_add(&p->list, &srvi->plugins);

    return 0;
#else
    log_err("Not support plugin\n");
    return -1;
#endif
}

static int uh_add_path_handler(struct uh_server *srv, const char *path, uh_path_handler_prototype handler)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;
    int path_len = strlen(path);
    struct uh_path_handler *h;
    uint8_t flags = 0;

    if (path[0] == '^') {
        flags |= UH_PATH_MATCH_START;
        path_len--;
        path++;
    }

    if (path[path_len - 1] == '$') {
        flags |= UH_PATH_MATCH_END;
        path_len--;
    }

    h = calloc(1, sizeof(struct uh_path_handler) + strlen(path) + 1);
    if (!h) {
        log_err("calloc: %s\n", strerror(errno));
        return -1;
    }

    h->handler = handler;
    h->flags = flags;
    h->len = path_len;

    strncpy(h->path, path, path_len);

    list_add(&h->list, &srvi->handlers);

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
        log_err("strdup: %s\n", strerror(errno));
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
        log_err("strdup: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static struct ev_loop *uh_get_loop(struct uh_server *srv)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    return srvi->loop;
}

static void uh_set_loop(struct uh_server *srv, struct ev_loop *loop)
{
    struct uh_server_internal *srvi = (struct uh_server_internal *)srv;

    srvi->loop = loop;
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
        log_err("invalid address\n");
        return -1;
    }

    status = getaddrinfo(host, port, &hints, &addrs);
    if (status != 0) {
        log_err("getaddrinfo(): %s\n", gai_strerror(status));
        return -1;
    }

    /* try to bind a new socket to each found address */
    for (p = addrs; p; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, p->ai_protocol);
        if (sock < 0) {
            log_err("socket: %s\n", strerror(errno));
            continue;
        }

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0) {
            log_err("setsockopt: %s\n", strerror(errno));
            goto err;
        }

        /* required to get parallel v4 + v6 working */
        if (p->ai_family == AF_INET6 && setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(int)) < 0) {
            log_err("setsockopt: %s\n", strerror(errno));
            goto err;
        }

        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(int));

        if (bind(sock, p->ai_addr, p->ai_addrlen) < 0) {
            log_err("bind: %s\n", strerror(errno));
            goto err;
        }

        if (listen(sock, SOMAXCONN) < 0) {
            log_err("bind: %s\n", strerror(errno));
            goto err;
        }

        l = calloc(1, sizeof(struct uh_listener));
        if (!l) {
            log_err("calloc: %s\n", strerror(errno));
            goto err;
        }

        l->sock = sock;
        l->ssl = ssl;
        l->srv = srvi;

        ev_io_init(&l->ior, uh_accept_cb, sock, EV_READ);
        ev_io_start(srvi->loop, &l->ior);

        list_add(&l->list, &srvi->listeners);

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ina = (struct sockaddr_in *)p->ai_addr;
            inet_ntop(p->ai_family, &ina->sin_addr, addr_str, sizeof(addr_str));
            log_info("Listen on: %s:%d%s\n", addr_str, ntohs(ina->sin_port), ssl ? " with ssl" : "");
        } else {
            struct sockaddr_in6 *in6a = (struct sockaddr_in6 *)p->ai_addr;
            inet_ntop(p->ai_family, &in6a->sin6_addr, addr_str, sizeof(addr_str));
            log_info("Listen on: [%s]:%d%s\n", addr_str, ntohs(in6a->sin6_port), ssl ? " with ssl" : "");
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

    INIT_LIST_HEAD(&srvi->listeners);
    INIT_LIST_HEAD(&srvi->handlers);
    INIT_LIST_HEAD(&srvi->plugins);
    INIT_LIST_HEAD(&srvi->conns);

    srvi->loop = loop ? loop : EV_DEFAULT;

    srv->get_loop = uh_get_loop;
    srv->set_loop = uh_set_loop;
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
