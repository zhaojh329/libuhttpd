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

#ifndef LIBUHTTPD_CONNECTION_H
#define LIBUHTTPD_CONNECTION_H

#include <arpa/inet.h>

#include "buffer.h"
#include "uhttpd.h"

#define UHTTPD_CONNECTION_TIMEOUT   30.0
#define UHTTPD_MAX_HEADER_NUM       50

#define CONN_F_SEND_AND_CLOSE       (1 << 0)    /* Push remaining data and close  */
#define CONN_F_SSL_HANDSHAKE_DONE   (1 << 1)    /* SSL hanshake has completed */

struct uh_server_internal;

struct uh_request {
    size_t length;  /* The total length of the request which still remain in buffer */
    struct {
        ssize_t offset;
        size_t length;
    } url;

    int header_num;
    bool last_was_header_value;
    struct {
        struct {
            ssize_t offset;
            size_t length;
        } field;
        struct {
            ssize_t offset;
            size_t length;
        } value;
    } headers[UHTTPD_MAX_HEADER_NUM];

    struct {
        bool consumed;  /* Indicates whether the extract_body is called */
        ssize_t offset;
        size_t length;
    } body;
};

struct uh_connection_internal {
    struct uh_connection com;
    int sock;
#if UHTTPD_SSL_SUPPORT
    void *ssl;
#endif
    uint8_t flags;
    struct {
        int fd;
        uint64_t size;
    } file;
    struct ev_io ior;
    struct ev_io iow;
    struct buffer rb;
    struct buffer wb;
    ev_tstamp activity;
    struct ev_timer timer;
    struct uh_request req;
    struct uh_server_internal *srv;
    union {
        struct sockaddr     sa;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } addr; /* peer address */
    struct http_parser parser;
    struct http_parser_url url_parser;
    struct uh_connection_internal *prev;
    struct uh_connection_internal *next;
    void (*handler)(struct uh_connection *conn, int event);
};

struct uh_connection_internal *uh_new_connection(struct uh_server_internal *srv, int sock, struct sockaddr *addr);

void conn_free(struct uh_connection_internal *conn);

#endif
