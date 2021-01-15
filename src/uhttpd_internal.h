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

struct uh_connection_internal;

struct uh_server_internal {
    struct uh_server com;
    int sock;
    char *docroot;
    char *index_page;
    struct ev_loop *loop;
    struct ev_io ior;
    struct uh_connection_internal *conns;
    void (*conn_closed_cb)(struct uh_connection *conn);
    void (*default_handler)(struct uh_connection *conn, int event);
#if UHTTPD_SSL_SUPPORT
    void *ssl_ctx;
#endif
    struct uh_plugin *plugins;
    struct uh_path_handler *handlers;
};

struct worker {
    struct ev_child w;
    int i;
};

#endif