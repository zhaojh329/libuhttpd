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

#ifndef LIBUHTTPD_UHTTPD_INTERNAL_H
#define LIBUHTTPD_UHTTPD_INTERNAL_H

#include <arpa/inet.h>

#include "uhttpd.h"
#include "list.h"

#ifdef SSL_SUPPORT
#include "ssl/ssl.h"
#endif

struct uh_server_internal;
struct uh_connection_internal;

struct uh_path_handler {
    uh_path_handler_prototype handler;
    struct list_head list;
    uint8_t flags;
    uint8_t len;
    char path[0];
};

struct uh_plugin {
    struct uh_plugin_handler *h;
    void *dlh;
    uint8_t flags;
    uint8_t len;
    const char *path;
    struct list_head list;
};

struct uh_listener {
    int sock;
    bool ssl;
    struct ev_io ior;
    struct list_head list;
    struct uh_server_internal *srv;
};

struct uh_server_internal {
    struct uh_server com;
    char *docroot;
    char *index_page;
    struct ev_loop *loop;
    void (*conn_closed_cb)(struct uh_connection *conn);
    void (*default_handler)(struct uh_connection *conn, int event);
#ifdef SSL_SUPPORT
    struct ssl_context *ssl_ctx;
#endif
    struct list_head listeners;
    struct list_head handlers;
    struct list_head plugins;
    struct list_head conns;
};

#endif
