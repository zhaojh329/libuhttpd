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

#ifndef LIBUHTTPD_UHTTPD_H
#define LIBUHTTPD_UHTTPD_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ev.h>

#include "http_parser.h"
#include "config.h"
#include "utils.h"
#include "log.h"

struct uh_str {
    const char *p;
    size_t len;
};

enum {
    UH_EV_HEAD_COMPLETE,
    UH_EV_BODY,
    UH_EV_COMPLETE
};

struct uh_server;

struct uh_connection {
    struct uh_server *(*get_server)(struct uh_connection *conn);
    struct ev_loop *(*get_loop)(struct uh_connection *conn);
    /*
    ** Indicates the end of request processing
    ** Must be called at last, if not call 'error', 'redirect' and 'serve_file'
    */
    void (*done)(struct uh_connection *conn);
    void (*send)(struct uh_connection *conn, const void *data, ssize_t len);
    void (*send_file)(struct uh_connection *conn, const char *path, off_t offset, int64_t len);
    void (*printf)(struct uh_connection *conn, const char *format, ...) __attribute__((format(printf, 2, 3)));
    void (*vprintf)(struct uh_connection *conn, const char *format, va_list arg);
    void (*send_status_line)(struct uh_connection *conn, int code, const char *extra_headers);
    void (*send_head)(struct uh_connection *conn, int code, int64_t content_length, const char *extra_headers);
    void (*error)(struct uh_connection *conn, int code, const char *reason);
    void (*redirect)(struct uh_connection *conn, int code, const char *location, ...) __attribute__((format(printf, 3, 4)));
    void (*serve_file)(struct uh_connection *conn);
    void (*chunk_send)(struct uh_connection *conn, const void *data, ssize_t len);
    void (*chunk_printf)(struct uh_connection *conn, const char *format, ...) __attribute__((format(printf, 2, 3)));
    void (*chunk_vprintf)(struct uh_connection *conn, const char *format, va_list arg);
    void (*chunk_end)(struct uh_connection *conn);
    const struct sockaddr *(*get_addr)(struct uh_connection *conn); /* peer address */
    enum http_method (*get_method)(struct uh_connection *conn);
    const char *(*get_method_str)(struct uh_connection *conn);
    struct uh_str (*get_path)(struct uh_connection *conn);
    struct uh_str (*get_query)(struct uh_connection *conn);
    struct uh_str (*get_header)(struct uh_connection *conn, const char *name);
    void (*traverse_headers)(struct uh_connection *conn,
            bool (*cb)(const struct uh_str name, const struct uh_str value, void *arg), void *arg);
    uint64_t (*get_content_length)(struct uh_connection *conn);
    struct uh_str (*get_body)(struct uh_connection *conn);
    /* The remain body data will be discurd after this function called */
    struct uh_str (*extract_body)(struct uh_connection *conn);
    void (*close)(struct uh_connection *conn);  /* close low level TCP connection */
    void (*incref)(struct uh_connection *conn);
    void (*decref)(struct uh_connection *conn);
    void *userdata;
};

typedef void (*uh_con_closed_cb_prototype)(struct uh_connection *conn);
typedef void (*uh_path_handler_prototype)(struct uh_connection *conn, int event);

struct uh_server {
    struct ev_loop *(*get_loop)(struct uh_server *srv);
    void (*free)(struct uh_server *srv);
    /*
    ** listen an address, multiple call allowed
    ** returns the number of successful listen
    **
    ** :80 0:80 0.0.0.0:80 [::]:80
    ** localhost:80 [::1]:80
    */
    int (*listen)(struct uh_server *srv, const char *addr, bool ssl);
#ifdef SSL_SUPPORT
    int (*ssl_init)(struct uh_server *srv, const char *cert, const char *key);
#endif
    int (*load_plugin)(struct uh_server *srv, const char *path);
    void (*set_conn_closed_cb)(struct uh_server *srv, uh_con_closed_cb_prototype cb);
    void (*set_default_handler)(struct uh_server *srv, uh_path_handler_prototype handler);
    int (*add_path_handler)(struct uh_server *srv, const char *path, uh_path_handler_prototype handler);
    /*
    ** Similar with 'add_path_handler', but treats 'path' as wildcard
    **
    ** ^/cgi-bin/         matches the starting position within the path
    ** ^/cgi-bin/test$    matches the starting position and the ending position within the path
    ** test               matches any position within the path
    */
    int (*add_path_handler_w)(struct uh_server *srv, const char *path, uh_path_handler_prototype handler);
    int (*set_docroot)(struct uh_server *srv, const char *path);
    int (*set_index_page)(struct uh_server *srv, const char *name);
};

struct uh_plugin_handler {
    const char *path;
    uh_path_handler_prototype handler;
};

struct uh_plugin {
    struct uh_plugin_handler *h;
    void *dlh;
    struct uh_plugin *next;
};

enum {
    UH_PATH_WILDCARD    = (1 << 0),
    UH_PATH_MATCH_START = (1 << 1),
    UH_PATH_MATCH_END   = (1 << 2)
};

struct uh_path_handler {
    uh_path_handler_prototype handler;
    struct uh_path_handler *next;
    uint8_t flags;
    uint8_t len;
    char path[0];
};

/*
 *  uh_server_new - creat an uh_server struct and init it
 *  @loop: If NULL will use EV_DEFAULT
 */
struct uh_server *uh_server_new(struct ev_loop *loop);

void uh_server_init(struct uh_server *srv, struct ev_loop *loop);

#endif
