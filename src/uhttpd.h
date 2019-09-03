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

#ifndef _UHTTPD_H
#define _UHTTPD_H

#include <ev.h>

#include "connection.h"
#include "config.h"
#include "log.h"

struct uh_server {
    int sock;
    struct ev_loop *loop;
    struct ev_io ior;
    struct uh_connection *conns;
    void (*free)(struct uh_server *srv);
    void (*on_request)(struct uh_connection *conn);
#if UHTTPD_SSL_SUPPORT
    void *ssl_ctx;
    int (*ssl_init)(struct uh_server *srv, const char *cert, const char *key);
#endif
};

/*
 *  uh_server_new - creat an uh_server struct and init it
 *  @loop: If NULL will use EV_DEFAULT
 *  @host: If NULL will listen on "0.0.0.0"
 *  @port: port to listen on
 */
struct uh_server *uh_server_new(struct ev_loop *loop, const char *host, int port);

int uh_server_init(struct uh_server *srv, struct ev_loop *loop, const char *host, int port);

#endif

