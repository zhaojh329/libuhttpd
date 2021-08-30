/*
 * MIT License
 *
 * Copyright (c) 2021 Jianhui Zhao <zhaojh329@gmail.com>
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

#ifndef LIBUHTTPD_CGI_H
#define LIBUHTTPD_CGI_H

#include "connection.h"

#define CGI_TIMEOUT 60

struct uh_cgi {
    struct uh_connection *conn;
    struct buffer rb;
    struct buffer wb;
    struct ev_io ior;
    struct ev_io iow;
    struct ev_timer tmr;
    struct ev_child proc;
    bool header_end;
    bool skip_data;
    int status_code;
    char status_msg[256];
    struct buffer headers;
    uint64_t content_length;
};

void serve_cgi(struct uh_connection *conn, int event);
void cgi_free(struct uh_connection_internal *conn);

#endif
