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

    const struct sockaddr *(*get_paddr)(struct uh_connection *conn); /* peer address */
    const struct sockaddr *(*get_saddr)(struct uh_connection *conn); /* server address */
    enum http_method (*get_method)(struct uh_connection *conn);
    const char *(*get_method_str)(struct uh_connection *conn);
    struct uh_str (*get_uri)(struct uh_connection *conn);
    struct uh_str (*get_path)(struct uh_connection *conn);
    struct uh_str (*get_query)(struct uh_connection *conn);
    struct uh_str (*get_header)(struct uh_connection *conn, const char *name);
    void (*traverse_headers)(struct uh_connection *conn,
            bool (*cb)(const struct uh_str name, const struct uh_str value, void *arg), void *arg);
    uint64_t (*get_content_length)(struct uh_connection *conn);
    struct uh_str (*get_body)(struct uh_connection *conn);
    /* The remain body data will be discurd after this function called */
    struct uh_str (*extract_body)(struct uh_connection *conn);

    /*
    ** This must be called first.
    ** Sends a response head to the client which consist of a status line and some headers.
    ** This method will sends a HTTP header 'Content-Length: num' if content_length is nonnegative,
    ** otherwise sends a HTTP header 'Transfer-Encoding: chunked' for chunked transfer.
    */
    void (*send_head)(struct uh_connection *conn, int code, int64_t content_length,
        const char *reason, ...) __attribute__((format(printf, 4, 5)));

    /* Sends a HTTP header */
    void (*send_header)(struct uh_connection *conn,
        const char *name, const char *value, ...) __attribute__((format(printf, 3, 4)));
    /*
    ** Sends a blank line (indicating the end of the HTTP headers in the response).
    ** This must be called before send body.
    */
    void (*end_headers)(struct uh_connection *conn);

    /*
    ** Sends a complete error reply to the client.
    ** The numeric code specifies the HTTP error code, with reason as an optional,
    ** short, human readable description of the error.
    */
    void (*send_error)(struct uh_connection *conn, int code, const char *reason, ...)
        __attribute__((format(printf, 3, 4)));

    /*
    ** Sends a complete redirect reply to the client.
    ** The numeric code specifies the redirect type:
    **   301: HTTP_STATUS_MOVED_PERMANENTLY
    **   302: HTTP_STATUS_FOUND
    **   307: HTTP_STATUS_TEMPORARY_REDIRECT
    **   308: HTTP_STATUS_PERMANENT_REDIRECT
    ** The location specifies the resource path.
    */
    void (*send_redirect)(struct uh_connection *conn, int code, const char *location, ...)
        __attribute__((format(printf, 3, 4)));

    /* Redirect HTTP requests to HTTPS if possible */
    bool (*https_redirect)(struct uh_connection *conn);

    /* If received the header 'Expect: 100-continue', then response 'HTTP/1.1 100 Continue' */
    void (*check_expect_100_continue)(struct uh_connection *conn);

    /*
    ** These three methods sends HTTP body to the client.
    ** These three methods can only be called after calls 'end_headers'.
    */
    void (*send)(struct uh_connection *conn, const void *data, size_t len);
    /* restriction: cannot send over 6553 bytes */
    void (*printf)(struct uh_connection *conn, const char *format, ...)
        __attribute__((format(printf, 2, 3)));
    /* restriction: cannot send over 6553 bytes */
    void (*vprintf)(struct uh_connection *conn, const char *format, va_list arg);

    /* Tells libuhttpd that we has replied all data to the client, no any more data to send */
    void (*end_response)(struct uh_connection *conn);

    /* handle file */
    void (*serve_file)(struct uh_connection *conn);

    /*
    ** Content-Disposition: attachment; filename="filename.jpg"
    **
    ** path: The physical path which to download in the server
    ** filename: Most browsers presenting a 'Save as' dialog, prefilled with the value of the filename parameters.
    */
    void (*download_file)(struct uh_connection *conn, const char *path, const char *filename);

    /* handle cgi */
    void (*serve_cgi)(struct uh_connection *conn, int event);

    bool (*closed)(struct uh_connection *conn);
    void (*close)(struct uh_connection *conn);  /* close low level TCP connection */
    void (*incref)(struct uh_connection *conn);
    void (*decref)(struct uh_connection *conn);

    void *userdata;
};

typedef void (*uh_con_closed_cb_prototype)(struct uh_connection *conn);
typedef void (*uh_path_handler_prototype)(struct uh_connection *conn, int event);

struct uh_server {
    struct ev_loop *(*get_loop)(struct uh_server *srv);
    /* Replace the existing loop. Can only be called before calling the listen */
    void (*set_loop)(struct uh_server *srv, struct ev_loop *loop);
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
    /*
    ** ^/cgi-bin/         matches the starting position within the path
    ** ^/cgi-bin/test$    matches the starting position and the ending position within the path
    ** /test               matches any position within the path
    */
    int (*add_path_handler)(struct uh_server *srv, const char *path, uh_path_handler_prototype handler);
    int (*set_docroot)(struct uh_server *srv, const char *path);
    int (*set_index_page)(struct uh_server *srv, const char *name);

    /* Redirect HTTP requests to HTTPS if possible */
    void (*https_redirect)(struct uh_server *srv, bool enable);

    void *userdata;
};

enum {
    UH_PATH_MATCH_START = (1 << 0),
    UH_PATH_MATCH_END   = (1 << 1)
};

struct uh_plugin_handler {
    const char *path;
    uh_path_handler_prototype handler;
};

/*
 *  uh_server_new - creat an uh_server struct and init it
 *  @loop: If NULL will use EV_DEFAULT
 */
struct uh_server *uh_server_new(struct ev_loop *loop);

void uh_server_init(struct uh_server *srv, struct ev_loop *loop);


static inline bool uh_str_equal(const struct uh_str *us, const char *s)
{
    size_t len = strlen(s);

    if (len != us->len)
        return false;

    return !memcmp(us->p, s, len);
}

/* ignoring case */
static inline bool uh_str_equal_case(const struct uh_str *us, const char *s)
{
    size_t len = strlen(s);

    if (len != us->len)
        return false;

    return !strncasecmp(us->p, s, len);
}

#include "handler.h"

#endif
