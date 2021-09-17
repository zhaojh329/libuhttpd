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
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/sendfile.h>

#include "uhttpd_internal.h"
#include "utils.h"
#include "file.h"
#include "cgi.h"

static void conn_send(struct uh_connection *conn, const void *data, size_t len)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (unlikely(conni->flags & CONN_F_CLOSED))
        return;

    buffer_put_data(&conni->wb, data, len);
    ev_io_start(conni->l->srv->loop, &conni->iow);
}

static void conn_send_chunk(struct uh_connection *conn, const void *data, size_t len)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct buffer *wb = &conni->wb;

    if (unlikely(conni->flags & CONN_F_CLOSED))
        return;

    buffer_put_printf(wb, "%zX\r\n", len);
    buffer_put_data(wb, data, len);
    buffer_put_data(wb, "\r\n", 2);
    ev_io_start(conni->l->srv->loop, &conni->iow);
}

static void conn_vprintf(struct uh_connection *conn, const char *format, va_list arg)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (unlikely(conni->flags & CONN_F_CLOSED))
        return;

    buffer_put_vprintf(&conni->wb, format, arg);
    ev_io_start(conni->l->srv->loop, &conni->iow);
}

static void conn_vprintf_chunk(struct uh_connection *conn, const char *format, va_list arg)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct buffer *wb = &conni->wb;
    size_t offset = 0;
    char *buf;
    int len;

    if (unlikely(conni->flags & CONN_F_CLOSED))
        return;

    offset = buffer_length(wb);
    buffer_put(wb, 4);

    len = buffer_put_vprintf(wb, format, arg);

    buf = buffer_data(wb) + offset;
    sprintf(buf, "%02X", len);
    memcpy(buf + 2, "\r\n", 2);
    buffer_put_data(wb, "\r\n", 2);

    ev_io_start(conni->l->srv->loop, &conni->iow);
}

static inline void conn_printf(struct uh_connection *conn, const char *format, ...)
{
    va_list arg;

    va_start(arg, format);
    conn_vprintf(conn, format, arg);
    va_end(arg);
}

static inline void conn_printf_chunk(struct uh_connection *conn, const char *format, ...)
{
    va_list arg;

    va_start(arg, format);
    conn_vprintf_chunk(conn, format, arg);
    va_end(arg);
}

static void conn_send_header_v(struct uh_connection *conn, const char *name, const char *value, va_list arg)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct buffer *wb = &conni->wb;

    buffer_put_printf(wb, "%s: ", name);
    buffer_put_vprintf(wb, value, arg);
    buffer_put_data(wb, "\r\n", 2);
    ev_io_start(conni->l->srv->loop, &conni->iow);
}

static inline void conn_send_header(struct uh_connection *conn, const char *name, const char *value, ...)
{
    va_list arg;

    va_start(arg, value);
    conn_send_header_v(conn, name, value, arg);
    va_end(arg);
}

static inline void conn_end_headers(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    buffer_put_data(&conni->wb, "\r\n", 2);
    ev_io_start(conni->l->srv->loop, &conni->iow);

    if (conni->resp.chunked) {
        conn->send = conn_send_chunk;
        conn->printf = conn_printf_chunk;
        conn->vprintf = conn_vprintf_chunk;
    } else {
        conn->send = conn_send;
        conn->printf = conn_printf;
        conn->vprintf = conn_vprintf;
    }
}

static void conn_send_head_v(struct uh_connection *conn, int code, int64_t content_length, const char *reason, va_list arg)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    const struct uh_str path = conn->get_path(conn);
    struct buffer *wb = &conni->wb;
    char addr_str[INET6_ADDRSTRLEN];
    int port;

    if (likely(!reason))
        reason = http_status_str(code);

    log_info("%s %d  %s %.*s - %d %s\n", addr_str, (saddr2str(&conni->paddr.sa, addr_str, sizeof(addr_str), &port) ? port : 0),
        http_method_str(conni->parser.method), (int)path.len, path.p, code, reason);

    buffer_put_printf(wb, "HTTP/1.1 %d ", code);
    buffer_put_vprintf(wb, reason, arg);
    buffer_put_printf(wb, "\r\nServer: Libuhttpd/%s\r\n", UHTTPD_VERSION_STRING);

    if (content_length < 0)
        buffer_put_printf(wb, "%s", "Transfer-Encoding: chunked\r\n");
    else
        buffer_put_printf(wb, "Content-Length: %" PRIu64 "\r\n", content_length);

    if (!http_should_keep_alive(&conni->parser))
        buffer_put_printf(wb, "%s", "Connection: close\r\n");

    conni->resp.chunked = content_length < 0;

    conn->send_header = conn_send_header;
    conn->end_headers = conn_end_headers;

    ev_io_start(conni->l->srv->loop, &conni->iow);
}

static inline void conn_send_head(struct uh_connection *conn, int code, int64_t content_length, const char *reason, ...)
{
    va_list arg;

    va_start(arg, reason);
    conn_send_head_v(conn, code, content_length, reason, arg);
    va_end(arg);
}

static void conn_end_response(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct ev_loop *loop = conni->l->srv->loop;

    if (unlikely(conni->flags & CONN_F_CLOSED))
        return;

    if (!http_should_keep_alive(&conni->parser))
        conni->flags |= CONN_F_SEND_AND_CLOSE;

    if (conni->flags & CONN_F_SEND_AND_CLOSE)
        ev_io_stop(loop, &conni->ior);

    /* end chunk */
    if (conni->resp.chunked)
        conn->send(conn, NULL, 0);

    ev_io_start(loop, &conni->iow);

    ev_timer_stop(loop, &conni->timer);

    conni->handler = NULL;

    conn->send_header = NULL;
    conn->end_headers = NULL;
    conn->send = NULL;
    conn->printf = NULL;
    conn->vprintf = NULL;
}

static void conn_send_error(struct uh_connection *conn, int code, const char *reason, ...)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    va_list arg;

    if (unlikely(conni->flags & CONN_F_SEND_AND_CLOSE))
        return;

    va_start(arg, reason);
    conn_send_head_v(conn, code, 0, reason, arg);
    va_end(arg);

    conn_send_header(conn, "Content-Type", "text/plain");

    if (http_should_keep_alive(&conni->parser))
        conn_send_header(conn, "Connection", "close");

    conni->flags |= CONN_F_SEND_AND_CLOSE;

    conn_end_headers(conn);
    conn_end_response(conn);
}

static void conn_send_redirect(struct uh_connection *conn, int code, const char *location, ...)
{
    va_list arg;

    conn_send_head(conn, code, 0, NULL);

    va_start(arg, location);
    conn_send_header_v(conn, "Location", location, arg);
    va_end(arg);

    conn_end_headers(conn);
    conn_end_response(conn);
}

static bool conn_https_redirect(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct uh_str host = conn->get_header(conn, "host");
    struct uh_str url = conn->get_uri(conn);
    struct sockaddr_in6 sin6;
    struct uh_listener *l;
    int tls_port = -1;
    int host_len = 0;
    const char *p;

    if (conni->l->ssl)
        return false;

    list_for_each_entry(l, &conni->l->srv->listeners, list) {
        socklen_t sl = sizeof(struct sockaddr_in6);

        if (!l->ssl)
            continue;

        getsockname(l->sock, (struct sockaddr *)&sin6, &sl);

        if (sin6.sin6_family != conni->saddr.sa.sa_family)
            continue;

        if (tls_port != -1 && ntohs(sin6.sin6_port) != 443)
			continue;

		tls_port = ntohs(sin6.sin6_port);
    }

    if (tls_port == -1)
        return false;

    if (host.len == 0)
        return false;

    host_len = 0;
    p = host.p;

    while (p < host.p + host.len) {
        if (*p++ == ']') {
            host_len = p - host.p - 1;
            break;
        }
    }

    if (host_len == 0) {
        p = host.p;
        while (p < host.p + host.len) {
            if (*p++ == ':') {
                host_len = p - host.p - 1;
                break;
            }
        }
    }

    if (host_len == 0)
        host_len = host.len;

    if (tls_port == 443)
        conn->send_redirect(conn, HTTP_STATUS_TEMPORARY_REDIRECT,
            "https://%.*s%.*s", host_len, host.p, (int)url.len, url.p);
    else
        conn->send_redirect(conn, HTTP_STATUS_TEMPORARY_REDIRECT,
            "https://%.*s:%d%.*s", host_len, host.p, tls_port, (int)url.len, url.p);

    return true;
}

static void conn_check_expect_100_continue(struct uh_connection *conn)
{
    struct uh_str expect = conn->get_header(conn, "Expect");

    if (uh_str_equal_case(&expect, "100-continue")) {
        conn->send_head(conn, HTTP_STATUS_CONTINUE, 0, NULL);
        conn->end_headers(conn);
    }
}

static inline const struct sockaddr *conn_get_paddr(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return &conni->paddr.sa;
}

static inline const struct sockaddr *conn_get_saddr(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return &conni->saddr.sa;
}

static inline enum http_method conn_get_method(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return conni->parser.method;
}

static inline const char *conn_get_method_str(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return http_method_str(conni->parser.method);
}

/* offset of the request field */
#define ROF(c, a) (a - (const char *)c->rb.data)

/* data of the request field */
#define O2D(c, o) ((const char *)c->rb.data + o)

static struct uh_str conn_get_uri(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct uh_request *req = &conni->req;
    struct uh_str uri;

    uri.p = O2D(conni, req->url.offset);
    uri.len = req->url.length;

    return uri;
}

static struct uh_str conn_get_path(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct http_parser_url *u = &conni->url_parser;
    struct uh_request *req = &conni->req;
    struct uh_str path;

    path.p = O2D(conni, u->field_data[UF_PATH].off) + req->url.offset;
    path.len = u->field_data[UF_PATH].len;

    return path;
}

static struct uh_str conn_get_query(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct http_parser_url *u = &conni->url_parser;
    struct uh_request *req = &conni->req;
    struct uh_str query = {};

    if (!(u->field_set & (1 << UF_QUERY)))
        return query;

    query.p = O2D(conni, u->field_data[UF_QUERY].off) + req->url.offset;
    query.len = u->field_data[UF_QUERY].len;

    return query;
}

static struct uh_str conn_get_header(struct uh_connection *conn, const char *name)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct uh_request *req = &conni->req;
    int name_len = strlen(name);
    struct uh_str value = {};
    int i;

    for (i = 0; i < UHTTPD_MAX_HEADER_NUM; i++) {
        if (req->headers[i].field.offset == 0)
            return value;

        if (req->headers[i].field.length != name_len)
            continue;

        if (!strncasecmp(O2D(conni, req->headers[i].field.offset), name, name_len)) {
            value.p = O2D(conni, req->headers[i].value.offset);
            value.len = req->headers[i].value.length;
        }
    }

    return value;
}

static void conn_traverse_headers(struct uh_connection *conn,
        bool (*cb)(const struct uh_str name, const struct uh_str value, void *arg), void *arg)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct uh_request *req = &conni->req;
    struct uh_str name, value;
    int i;

    for (i = 0; i < UHTTPD_MAX_HEADER_NUM; i++) {
        if (req->headers[i].field.offset == 0)
            return;

        name.p = O2D(conni, req->headers[i].field.offset);
        name.len = req->headers[i].field.length;

        value.p = O2D(conni, req->headers[i].value.offset);
        value.len = req->headers[i].value.length;

        if (!cb(name, value, arg))
            return;
    }
}

static uint64_t conn_get_content_length(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return conni->parser.content_length;
}

static struct uh_str conn_get_body(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct uh_request *req = &conni->req;
    struct uh_str body;

    body.p = O2D(conni, req->body.offset);
    body.len = req->body.length;

    return body;
}

static struct uh_str conn_extract_body(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct uh_str body = conn_get_body(conn);

    conni->req.body.consumed = true;

    return body;
}

static void conn_close(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    http_parser_pause(&conni->parser, true);

    conni->flags |= CONN_F_CLOSED;
}

static int on_message_begin_cb(struct http_parser *parser)
{
    struct uh_connection_internal *conn = (struct uh_connection_internal *)parser->data;
    struct uh_request *req = &conn->req;

    memset(req, 0, sizeof(struct uh_request));
    memset(&conn->resp, 0, sizeof(struct uh_response));

    req->last_was_header_value = true;

    http_parser_url_init(&conn->url_parser);

    ev_timer_start(conn->l->srv->loop, &conn->timer);

    return 0;
}

static int on_url_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection_internal *conn = (struct uh_connection_internal *)parser->data;
    struct uh_request *req = &conn->req;

    if (req->url.offset == 0)
        req->url.offset = ROF(conn, at);
    req->url.length += length;

    return 0;
}

static int on_header_field_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection_internal *conn = (struct uh_connection_internal *)parser->data;
    struct uh_request *req = &conn->req;

    if (req->last_was_header_value) {
        req->last_was_header_value = false;
        req->header_num++;

        if (req->header_num == UHTTPD_MAX_HEADER_NUM) {
            log_err("Header too more\n");
            return 1;
        }

        req->headers[req->header_num - 1].field.offset = ROF(conn, at);
    }

    req->headers[req->header_num - 1].field.length += length;

    return 0;
}

static int on_header_value_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection_internal *conn = (struct uh_connection_internal *)parser->data;
    struct uh_request *req = &conn->req;

    if (!req->last_was_header_value) {
        req->last_was_header_value = true;
        req->headers[req->header_num - 1].value.offset = ROF(conn, at);
    }

    req->headers[req->header_num - 1].value.length += length;

    return 0;
}

static bool match_path(struct uh_str *path, const char *needle, int needlelen, uint8_t flags)
{
    int match = 0;

    if (path->len < needlelen)
        return false;

    if (flags & UH_PATH_MATCH_START) {
        if (strncmp(path->p, needle, needlelen))
            return false;
        match++;
    }

    if (flags & UH_PATH_MATCH_END) {
        if (strncmp(path->p + (path->len - needlelen), needle, needlelen))
            return false;
        match++;
    }

    if (!match && !memmem(path->p, path->len, needle, needlelen))
        return false;

    return true;
}

static void *find_path_handler(struct uh_connection_internal *conn, struct list_head *head, struct uh_str *path)
{
    struct uh_path_handler *h;

    list_for_each_entry(h, head, list) {
        if (match_path(path, h->path, h->len, h->flags))
            return h->handler;
    }

    return NULL;
}

static void *find_plugin_handler(struct uh_connection_internal *conn, struct list_head *head, struct uh_str *path)
{
    struct uh_plugin *p;

    list_for_each_entry(p, head, list) {
        if (match_path(path, p->path, p->len, p->flags))
            return p->h->handler;
    }

    return NULL;
}

static int on_headers_complete(struct http_parser *parser)
{
    struct uh_connection_internal *conn = (struct uh_connection_internal *)parser->data;
    struct uh_server_internal *srv = conn->l->srv;
    struct http_parser_url *u = &conn->url_parser;
    struct uh_request *req = &conn->req;
    uh_path_handler_prototype handler;
    struct uh_str path;

    canonpath((char *)O2D(conn, req->url.offset), &req->url.length);

    http_parser_parse_url(O2D(conn, req->url.offset), req->url.length, false, u);

    path.p = O2D(conn, u->field_data[UF_PATH].off) + req->url.offset;
    path.len = u->field_data[UF_PATH].len;

    handler = find_path_handler(conn, &srv->handlers, &path);
    if (!handler)
        handler = find_plugin_handler(conn, &srv->plugins, &path);

    if (!handler)
        handler = srv->default_handler;

    if (!handler) {
        conn_send_error(&conn->com, HTTP_STATUS_NOT_FOUND, NULL);
        return -1;
    }

    conn->handler = handler;
    handler(&conn->com, UH_EV_HEAD_COMPLETE);

    if (conn->flags & CONN_F_SEND_AND_CLOSE)
        return -1;

    return 0;
}

static int on_body_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection_internal *conn = (struct uh_connection_internal *)parser->data;
    struct uh_request *req = &conn->req;

    if (req->body.offset == 0)
        req->body.offset = ROF(conn, at);
    req->body.length += length;

    conn->handler(&conn->com, UH_EV_BODY);

    if (conn->flags & CONN_F_SEND_AND_CLOSE)
        return -1;

    if (req->body.consumed) {
        req->body.consumed = false;
        buffer_discard(&conn->rb, req->body.length);
        req->length -= req->body.length;
        req->body.length = 0;
    }

    return 0;
}

static int on_message_complete_cb(struct http_parser *parser)
{
    struct uh_connection_internal *conn = (struct uh_connection_internal *)parser->data;
    struct uh_server_internal *srv = conn->l->srv;

    ev_timer_stop(srv->loop, &conn->timer);

    if (!conn->l->srv->https_redirect || !conn_https_redirect(&conn->com))
        conn->handler(&conn->com, UH_EV_COMPLETE);

    http_parser_pause(parser, true);

    return 0;
}

static struct http_parser_settings settings = {
    .on_message_begin = on_message_begin_cb,
    .on_url = on_url_cb,
    .on_header_field = on_header_field_cb,
    .on_header_value = on_header_value_cb,
    .on_headers_complete = on_headers_complete,
    .on_body = on_body_cb,
    .on_message_complete = on_message_complete_cb
};

static void conn_incref(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (!conni)
        return;

    __sync_add_and_fetch(&conni->refcount, 1);
}

static void conn_decref(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (!conni)
        return;

    if (__sync_sub_and_fetch(&conni->refcount, 1))
        return;

    log_debug("Free connection: %p\n", conn);

    free(conn);
}

void conn_free(struct uh_connection_internal *conn)
{
    struct ev_loop *loop = conn->l->srv->loop;
    char addr_str[INET6_ADDRSTRLEN];
    int port;

    conn->flags |= CONN_F_CLOSED;

    ev_timer_stop(loop, &conn->timer);
    ev_io_stop(loop, &conn->ior);
    ev_io_stop(loop, &conn->iow);

    buffer_free(&conn->rb);
    buffer_free(&conn->wb);

    if (conn->file.fd > 0)
        close(conn->file.fd);

    list_del(&conn->list);

#ifdef SSL_SUPPORT
    ssl_session_free(conn->ssl);
#endif

  if (conn->l->srv->conn_closed_cb)
        conn->l->srv->conn_closed_cb(&conn->com);

    if (conn->sock > 0)
        close(conn->sock);

    cgi_free(conn);

    log_debug("Connection(%s %d) closed\n", addr_str,
            (saddr2str(&conn->paddr.sa, addr_str, sizeof(addr_str), &port) ? port : 0));

    conn_decref((struct uh_connection *)conn);
}

static void conn_http_parse(struct uh_connection_internal *conn)
{
    struct http_parser *parser = &conn->parser;
    struct uh_request *req = &conn->req;
    struct buffer *rb = &conn->rb;
    uint8_t *data = buffer_data(rb) + req->length;
    size_t length = buffer_length(rb) - req->length;
    size_t nparsed;

    if (parser->http_errno == HPE_PAUSED)
        return;

    nparsed = http_parser_execute(parser, &settings, (const char *)data, length);
    if (conn->flags & CONN_F_CLOSED) {
        conn_free(conn);
        return;
    }

    switch (parser->http_errno) {
    case HPE_PAUSED:
    case HPE_OK:
        if (parser->upgrade) {
            conn_send_error(&conn->com, HTTP_STATUS_NOT_IMPLEMENTED, NULL);
            return;
        }

        req->length += nparsed;

        /* paused in on_message_complete */
        if (parser->http_errno == HPE_PAUSED) {
            buffer_pull(rb, NULL, req->length);
            req->length = 0;
        }
        return;

    default:
        conn_send_error(&conn->com, HTTP_STATUS_BAD_REQUEST, http_errno_description(parser->http_errno));
        return;
    }
}

#ifdef SSL_SUPPORT
static void on_ssl_verify_error(int error, const char *str, void *arg)
{
    log_warn("SSL certificate error(%d): %s\n", error, str);
}

/* -1 error, 0 pending, 1 ok */
static int ssl_negotiated(struct uh_connection_internal *conn)
{
    char err_buf[128];
    int ret;

    ret = ssl_connect(conn->ssl, true, on_ssl_verify_error, NULL);
    if (ret == SSL_PENDING)
        return 0;

    if (ret == SSL_ERROR) {
        log_err("ssl connect error: %s\n", ssl_last_error_string(err_buf, sizeof(err_buf)));
        return -1;
    }

    conn->flags &= CONN_F_SSL_HANDSHAKE_DONE;

    return 1;
}

static int conn_ssl_read(int fd, void *buf, size_t count, void *arg)
{
    struct uh_connection_internal *conn = arg;
    static char err_buf[128];
    int ret;

    ret = ssl_read(conn->ssl, buf, count);
    if (ret == SSL_ERROR) {
        log_err("ssl_read: %s\n", ssl_last_error_string(err_buf, sizeof(err_buf)));
        return P_FD_ERR;
    }

    if (ret == SSL_PENDING)
        return P_FD_PENDING;

    return ret;
}
#endif

static void conn_write_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_connection_internal *conn = container_of(w, struct uh_connection_internal, iow);
    int ret;

    if (conn->ssl) {
#ifdef SSL_SUPPORT
        static char err_buf[128];
        struct buffer *b = &conn->wb;

        if (!likely((conn->flags & CONN_F_SSL_HANDSHAKE_DONE))) {
            ret = ssl_negotiated(conn);
            if (ret < 0)
                goto err;
            if (ret == 0)
                return;
        }

        ret = ssl_write(conn->ssl, buffer_data(b), buffer_length(b));
        if (ret == SSL_ERROR) {
            log_err("ssl_write: %s\n", ssl_last_error_string(err_buf, sizeof(err_buf)));
            goto err;
        }

        if (ret == SSL_PENDING)
            return;

        buffer_pull(b, NULL, ret);
#endif
    } else {
        ret = buffer_pull_to_fd(&conn->wb, w->fd, -1);
        if (ret < 0) {
            log_err("write error: %s\n", strerror(errno));
            goto err;
        }
    }

    if (buffer_length(&conn->wb) == 0) {
        if (conn->file.fd > 0) {
#ifdef SSL_SUPPORT
            if (conn->ssl) {
                bool eof;
                if (buffer_put_fd(&conn->wb, conn->file.fd, 8192, &eof) < 0 || eof) {
                    close(conn->file.fd);
                    conn->file.fd = -1;
                }
                return;
            } else {
#endif
                ret = sendfile(w->fd, conn->file.fd, NULL, conn->file.size);
                if (ret < 0) {
                    if (errno != EAGAIN) {
                        log_err("write error: %s\n", strerror(errno));
                        goto err;
                    }
                    return;
                }

                if (ret < conn->file.size) {
                    conn->file.size -= ret;
                    return;
                }

                close(conn->file.fd);
                conn->file.fd = -1;
#ifdef SSL_SUPPORT
            }
#endif
        }

        if (conn->flags & CONN_F_SEND_AND_CLOSE) {
            goto err;
        } else {
            char addr_str[INET6_ADDRSTRLEN];
            int port;

            ev_io_stop(loop, w);

            /* already called conn_end_response, then enable parsing */
            if (!conn->handler && !conn->cgi) {
                log_debug("%s %d response end\n", addr_str,
                    (saddr2str(&conn->paddr.sa, addr_str, sizeof(addr_str), &port) ? port : 0));

                http_parser_pause(&conn->parser, false);

                if (buffer_length(&conn->rb) > 0)
                    conn_http_parse(conn);
            }
        }
    }

    return;

err:
    conn_free(conn);
}

static void conn_read_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_connection_internal *conn = container_of(w, struct uh_connection_internal, ior);
    struct buffer *rb = &conn->rb;
    bool eof;
    int ret;

    if (conn->flags & CONN_F_SEND_AND_CLOSE) {
        ev_io_stop(loop, w);
        return;
    }

    conn->activity = ev_now(loop);

    if (conn->ssl) {
#ifdef SSL_SUPPORT
        if (!likely((conn->flags & CONN_F_SSL_HANDSHAKE_DONE))) {
            ret = ssl_negotiated(conn);
            if (ret < 0)
                goto err;
            if (ret == 0)
                return;
        }

        ret = buffer_put_fd_ex(&conn->rb, w->fd, -1, &eof, conn_ssl_read, conn);
        if (ret < 0)
            goto err;
#endif
    } else {
        ret = buffer_put_fd(rb, w->fd, -1, &eof);
        if (ret < 0) {
            log_err("read error: %s\n", strerror(errno));
            goto err;
        }
    }

    if (eof)
        goto err;

    conn_http_parse(conn);

    return;

err:
    conn_free(conn);
}

static void keepalive_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    struct uh_connection_internal *conn = container_of(w, struct uh_connection_internal, timer);
    ev_tstamp after = conn->activity + UHTTPD_CONNECTION_TIMEOUT - ev_now(loop);

    if (conn->flags & CONN_F_SEND_AND_CLOSE) {
        ev_timer_stop(loop, w);
        return;
    }

    if (after > 0) {
        ev_timer_set(w, after, 0.0);
        ev_timer_start(loop, w);
        return;
    }

    conn_send_error(&conn->com, HTTP_STATUS_REQUEST_TIMEOUT, NULL);
}

static struct uh_server *conn_get_server(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return &conni->l->srv->com;
}

static struct ev_loop *conn_get_loop(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return conni->l->srv->loop;
}

static void conn_init_cb(struct uh_connection *conn)
{
    conn->get_server = conn_get_server;
    conn->get_loop = conn_get_loop;

    conn->get_paddr = conn_get_paddr;
    conn->get_saddr = conn_get_saddr;
    conn->get_method = conn_get_method;
    conn->get_method_str = conn_get_method_str;
    conn->get_uri = conn_get_uri;
    conn->get_path = conn_get_path;
    conn->get_query = conn_get_query;
    conn->get_header = conn_get_header;
    conn->traverse_headers = conn_traverse_headers;
    conn->get_content_length = conn_get_content_length;
    conn->get_body = conn_get_body;
    conn->extract_body = conn_extract_body;

    conn->send_head = conn_send_head;

    conn->send_error = conn_send_error;
    conn->send_redirect = conn_send_redirect;
    conn->https_redirect = conn_https_redirect;

    conn->check_expect_100_continue = conn_check_expect_100_continue;

    conn->end_response = conn_end_response;

    conn->serve_file = serve_file;
    conn->download_file = download_file;
    conn->serve_cgi = serve_cgi;

    conn->close = conn_close;

    conn->incref = conn_incref;
    conn->decref = conn_decref;
}

void uh_new_connection(struct uh_listener *l, int sock, struct sockaddr *addr)
{
    socklen_t sl = sizeof(struct sockaddr_in6);
    struct uh_server_internal *srv = l->srv;
    struct uh_connection_internal *conn;

    conn = calloc(1, sizeof(struct uh_connection_internal));
    if (!conn) {
        log_err("malloc: %s\n", strerror(errno));
        return;
    }

    conn->l = l;
    conn->sock = sock;
    conn->activity = ev_now(srv->loop);

    if (addr->sa_family == AF_INET)
        memcpy(&conn->paddr, addr, sizeof(struct sockaddr_in));
    else
        memcpy(&conn->paddr, addr, sizeof(struct sockaddr_in6));

    getsockname(sock, &conn->saddr.sa, &sl);

    ev_io_init(&conn->iow, conn_write_cb, sock, EV_WRITE);

    ev_io_init(&conn->ior, conn_read_cb, sock, EV_READ);
    ev_io_start(srv->loop, &conn->ior);

    ev_timer_init(&conn->timer, keepalive_cb, UHTTPD_CONNECTION_TIMEOUT, 0.0);
    ev_timer_start(srv->loop, &conn->timer);

#ifdef SSL_SUPPORT
    if (l->ssl)
        conn->ssl = ssl_session_new(srv->ssl_ctx, sock);
#endif

    http_parser_init(&conn->parser, HTTP_REQUEST);

    conn->parser.data = conn;

    conn_init_cb(&conn->com);

    conn_incref((struct uh_connection *)conn);

    list_add(&conn->list, &srv->conns);

    log_debug("Alloc connection: %p\n", conn);
}
