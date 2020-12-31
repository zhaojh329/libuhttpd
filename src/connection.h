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

#include <ev.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "http_parser.h"
#include "buffer.h"
#include "config.h"

#define UHTTPD_CONNECTION_TIMEOUT   30.0
#define UHTTPD_MAX_HEADER_NUM       50

#define CONN_F_SEND_AND_CLOSE       (1 << 0)    /* Push remaining data and close  */
#define CONN_F_SSL_HANDSHAKE_DONE   (1 << 1)    /* SSL hanshake has completed */

struct uh_server;

struct uh_str {
    const char *p;
    size_t len;
};

struct uh_request {
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
        ssize_t offset;
        size_t length;
    } body;
};

struct uh_connection {
    int sock;
#if UHTTPD_SSL_SUPPORT
    void *ssl;
#endif
    uint8_t flags;
    struct {
        int fd;
        int size;
    } file;
    struct ev_io ior;
    struct ev_io iow;
    struct buffer rb;
    struct buffer wb;
    ev_tstamp activity;
    struct ev_timer timer;
    struct uh_request req;
    struct uh_server *srv;
    union {
        struct sockaddr     sa;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } addr; /* peer address */
    struct http_parser parser;
    struct http_parser_url url_parser;
    struct uh_connection *prev;
    struct uh_connection *next;
    void (*handler)(struct uh_connection *conn, int event);
    /*
    ** Indicates the end of request processing
    ** Must be called at last, if not call 'error', 'redirect' and 'serve_file'
    */
    void (*done)(struct uh_connection *conn);
    void (*send)(struct uh_connection *conn, const void *data, ssize_t len);
    void (*send_file)(struct uh_connection *conn, const char *path);
    void (*printf)(struct uh_connection *conn, const char *format, ...);
    void (*vprintf)(struct uh_connection *conn, const char *format, va_list arg);
    void (*send_status_line)(struct uh_connection *conn, int code, const char *extra_headers);
    void (*send_head)(struct uh_connection *conn, int code, int content_length, const char *extra_headers);
    void (*error)(struct uh_connection *conn, int code, const char *reason);
    void (*redirect)(struct uh_connection *conn, int code, const char *location, ...);
    void (*serve_file)(struct uh_connection *conn, const char *docroot, const char *index_page);
    void (*chunk_send)(struct uh_connection *conn, const void *data, ssize_t len);
    void (*chunk_printf)(struct uh_connection *conn, const char *format, ...);
    void (*chunk_vprintf)(struct uh_connection *conn, const char *format, va_list arg);
    void (*chunk_end)(struct uh_connection *conn);
    const struct sockaddr *(*get_addr)(struct uh_connection *conn);   /* peer address */
    enum http_method (*get_method)(struct uh_connection *conn);
    const char *(*get_method_str)(struct uh_connection *conn);
    struct uh_str (*get_path)(struct uh_connection *conn);
    struct uh_str (*get_query)(struct uh_connection *conn);
    struct uh_str (*get_header)(struct uh_connection *conn, const char *name);
    struct uh_str (*get_body)(struct uh_connection *conn);
    /* The remain body data will be discurd after this function called */
    struct uh_str (*extract_body)(struct uh_connection *conn);
};

struct uh_connection *uh_new_connection(struct uh_server *srv, int sock, struct sockaddr *addr);

#endif
