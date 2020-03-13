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
#include <assert.h>

#include "connection.h"
#include "uhttpd.h"
#include "utils.h"
#include "ssl.h"



static void conn_send(struct uh_connection *conn, const void *data, ssize_t len)
{
    buffer_put_data(&conn->wb, data, len);
    ev_io_start(conn->srv->loop, &conn->iow);
}

static void conn_printf(struct uh_connection *conn, const char *format, ...)
{
    struct buffer *wb = &conn->wb;
    va_list arg;

    va_start(arg, format);
    buffer_put_vprintf(wb, format, arg);
    va_end(arg);

    ev_io_start(conn->srv->loop, &conn->iow);
}

static void conn_vprintf(struct uh_connection *conn, const char *format, va_list arg)
{
    buffer_put_vprintf(&conn->wb, format, arg);
    ev_io_start(conn->srv->loop, &conn->iow);
}

static void conn_chunk_send(struct uh_connection *conn, const void *data, ssize_t len)
{
    conn_printf(conn, "%X\r\n", len);
    conn_send(conn, data, len);
    conn_printf(conn, "\r\n", len);
}

static void conn_chunk_vprintf(struct uh_connection *conn, const char *format, va_list arg)
{
    char buf[256];
    va_list arg2;
    int len;

    va_copy(arg2, arg);
    len = vsnprintf(buf, sizeof(buf), format, arg2);
    va_end(arg2);

    conn_printf(conn, "%X\r\n", len);
    if (len < sizeof(buf))
        conn_send(conn, buf, len);
    else
        conn_vprintf(conn, format, arg);
    conn_printf(conn, "\r\n", len);
}

static void conn_chunk_printf(struct uh_connection *conn, const char *format, ...)
{
    va_list arg;

    va_start(arg, format);
    conn_chunk_vprintf(conn, format, arg);
    va_end(arg);
}

static inline void conn_chunk_end(struct uh_connection *conn)
{
    conn_chunk_send(conn, NULL, 0);
}

static void conn_send_status_line(struct uh_connection *conn, int code, const char *extra_headers)
{
    conn_printf(conn, "HTTP/1.1 %d %s\r\nServer: Libuhttpd/%s\r\n", code, http_status_str(code), UHTTPD_VERSION_STRING);
    if (extra_headers)
        conn_send(conn, extra_headers, strlen(extra_headers));
}

static void conn_send_head(struct uh_connection *conn, int code, int content_length, const char *extra_headers)
{
    conn_send_status_line(conn, code, extra_headers);
    if (content_length < 0)
        conn_printf(conn, "%s", "Transfer-Encoding: chunked\r\n");
    else
        conn_printf(conn, "Content-Length: %d\r\n", content_length);
    conn_send(conn, "\r\n", 2);
}

static void conn_error(struct uh_connection *conn, int code, const char *reason)
{
    if (!reason)
        reason = http_status_str(code);
    conn_send_head(conn, code, strlen(reason), "Content-Type: text/plain\r\nConnection: close\r\n");
    conn_send(conn, reason, strlen(reason));

    conn->flags |= CONN_F_SEND_AND_CLOSE;
}

static void conn_redirect(struct uh_connection *conn, int code, const char *location, ...)
{
    struct buffer *wb = &conn->wb;
    va_list arg;

    assert((code == 301 || code == 302) && location);

    conn_send_status_line(conn, code, NULL);

    conn_printf(conn, "Location: ");
    va_start(arg, location);
    buffer_put_vprintf(wb, location, arg);
    va_end(arg);
    conn_send(conn, "\r\n", 2);

    conn_printf(conn, "Content-Length: 0\r\n");
    conn_send(conn, "\r\n", 2);
}

/* offset of the request field */
#define ROF(c, a) (a - (const char *)c->rb.data)

/* data of the request field */
#define O2D(c, o) ((const char *)c->rb.data + o)

static const char *conn_get_url(struct uh_connection *conn)
{
    struct uh_request *req = &conn->req;

    if (!req->url)
        req->url = strndup(O2D(conn, req->url_info.offset), req->url_info.len);
    return req->url;
}

static const char *conn_get_header(struct uh_connection *conn, const char *name)
{
    struct uh_request *req = &conn->req;
    int i, j;

    for (i = 0; i < UHTTPD_MAX_HEADER_NUM; i++) {
        if (!req->headers[i].name)
            break;
        if (!strcmp(req->headers[i].name, name))
            return req->headers[i].value;
    }

    if (i == UHTTPD_MAX_HEADER_NUM)
        return "";

    for (j = 0; j < UHTTPD_MAX_HEADER_NUM; j++) {
        if (req->headers_info[j].name_offset > 0) {
            const char *p = O2D(conn, req->headers_info[j].name_offset);
            if (!strncmp(p, name, req->headers_info[j].name_len)) {
                req->headers[i].name = strndup(p, req->headers_info[j].name_len);
                req->headers[i].value = strndup(O2D(conn, req->headers_info[j].value_offset), req->headers_info[j].value_len);
                req->headers_info[j].name_len = 0;
                return req->headers[i].value;
            }
        }
    }

    return "";
}

static const char *conn_get_body(struct uh_connection *conn, int *len)
{
    struct uh_request *req = &conn->req;
    const char *at = O2D(conn, req->body.offset);

    *len = req->body.len;

    return at;
}

static int on_url_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;

    req->url_info.offset = ROF(conn, at);
    req->url_info.len = length;

    return 0;
}

static int on_header_field_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;
    int n = req->header_num;

    if (n == UHTTPD_MAX_HEADER_NUM) {
        uh_log_err("Header too more\n");
        return 0;
    }

    req->headers_info[n].name_offset = ROF(conn, at);
    req->headers_info[n].name_len = length;

    return 0;
}

static int on_header_value_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;
    int n = req->header_num;

    req->headers_info[n].value_offset = ROF(conn, at);
    req->headers_info[n].value_len = length;

    req->header_num++;

    return 0;
}

static int on_body_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;

    req->body.offset = ROF(conn, at);
    req->body.len = length;

    return 0;
}

static int on_message_complete_cb(struct http_parser *parser)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;
    int i;

    if (conn->srv->on_request)
        conn->srv->on_request(conn);
    else
        conn_error(conn, 404, NULL);

    buffer_pull(&conn->rb, NULL, buffer_length(&conn->rb));

    if (req->url)
        free(req->url);

    for (i = 0; i < UHTTPD_MAX_HEADER_NUM; i++) {
        if (req->headers[i].name)
            free(req->headers[i].name);
        if (req->headers[i].value)
            free(req->headers[i].value);
    }

    memset(req, 0, sizeof(struct uh_request));

    return 0;
}

static struct http_parser_settings settings = {
    .on_url = on_url_cb,
    .on_header_field = on_header_field_cb,
    .on_header_value = on_header_value_cb,
    .on_body = on_body_cb,
    .on_message_complete = on_message_complete_cb
};

static void conn_free(struct uh_connection *conn)
{
    struct ev_loop *loop = conn->srv->loop;
    struct sockaddr_in *addr = &conn->addr;

    ev_timer_stop(loop, &conn->timer);
    ev_io_stop(loop, &conn->ior);
    ev_io_stop(loop, &conn->iow);

    buffer_free(&conn->rb);
    buffer_free(&conn->wb);

    if (conn->prev)
        conn->prev->next = conn->next;
    else
        conn->srv->conns = conn->next;

    if (conn->next)
        conn->next->prev = conn->prev;

#if UHTTPD_SSL_SUPPORT
    uh_ssl_free(conn->ssl);
#endif

    if (conn->sock > 0)
        close(conn->sock);

    uh_log_debug("Connection(%s:%d) closed\n", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

    free(conn);
}

#if UHTTPD_SSL_SUPPORT
static int conn_ssl_write(int fd, void *buf, size_t count, void *ssl)
{
    int ret = uh_ssl_write(ssl, buf, count);
    if (ret < 0) {
        if (ret == UH_SSL_ERROR_AGAIN)
            return P_FD_PENDING;
        return P_FD_ERR;
    }
    return ret;

}
#endif

static void conn_write_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_connection *conn = container_of(w, struct uh_connection, iow);
    int ret;

#if UHTTPD_SSL_SUPPORT
    if (conn->ssl)
        ret = buffer_pull_to_fd_ex(&conn->wb, w->fd, buffer_length(&conn->wb), conn_ssl_write, conn->ssl);
    else
#endif
        ret = buffer_pull_to_fd(&conn->wb, w->fd, buffer_length(&conn->wb));

    if (ret < 0) {
        uh_log_err("write error: %s\n", strerror(errno));
        conn_free(conn);
        return;
    }

    if (buffer_length(&conn->wb) == 0) {
        if (conn->flags & CONN_F_SEND_AND_CLOSE)
            conn_free(conn);
        else
            ev_io_stop(loop, w);
    }
}

#if UHTTPD_SSL_SUPPORT
static int conn_ssl_read(int fd, void *buf, size_t count, void *ssl)
{
    int ret = uh_ssl_read(ssl, buf, count);
    if (ret < 0) {
        if (ret == UH_SSL_ERROR_AGAIN)
            return P_FD_PENDING;
        return P_FD_ERR;
    }
    return ret;
}
#endif

static void conn_read_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_connection *conn = container_of(w, struct uh_connection, ior);
    struct http_parser *parser = &conn->parser;
    static uint8_t sep[] = {'\r', '\n', '\r', '\n'};
    struct buffer *rb = &conn->rb;
    int ret, length, nparsed;
    bool eof;

    if (conn->flags & CONN_F_SEND_AND_CLOSE) {
        ev_io_stop(loop, w);
        return;
    }

#if UHTTPD_SSL_SUPPORT
    if (conn->ssl && !(conn->flags & CONN_F_SSL_HANDSHAKE_DONE)) {
        ret = uh_ssl_handshake(conn->ssl);
        if (ret == UH_SSL_ERROR_AGAIN)
            return;
        if (ret == UH_SSL_ERROR_UNKNOWN) {
            conn_free(conn);
            return;
        }
        conn->flags |= CONN_F_SSL_HANDSHAKE_DONE;
    }
#endif

    conn->activity = ev_now(loop);

#if UHTTPD_SSL_SUPPORT
    if (conn->ssl)
        ret = buffer_put_fd_ex(rb, w->fd, -1, &eof, conn_ssl_read, conn->ssl);
    else
#endif
        ret = buffer_put_fd(rb, w->fd, -1, &eof);

    if (ret < 0) {
        conn_error(conn, 500, NULL);
        uh_log_err("read error: %s\n", strerror(errno));
        return;
    }

    if (eof) {
        conn_free(conn);
        return;
    }

    if (buffer_find(rb, 0, 1024, sep, 4) < 0)
        return;

    length = buffer_length(rb);
    nparsed = http_parser_execute(parser, &settings, (const char *)rb->data, length);
    if (parser->upgrade)
        conn_error(conn, 501, NULL);
    else if (nparsed != length)
        conn_error(conn, 400, http_errno_description(parser->http_errno));
}

static void keepalive_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    struct uh_connection *conn = container_of(w, struct uh_connection, timer);
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

    conn_error(conn, 408, NULL);
}

struct uh_connection *uh_new_connection(struct uh_server *srv, int sock, struct sockaddr_in *addr)
{
    struct uh_connection *conn;

    conn = calloc(1, sizeof(struct uh_connection));
    if (!conn) {
        uh_log_err("malloc: %s\n", strerror(errno));
        return NULL;
    }

    conn->srv = srv;
    conn->sock = sock;
    conn->activity = ev_now(srv->loop);

    memcpy(&conn->addr, addr, sizeof(struct sockaddr_in));

    ev_io_init(&conn->iow, conn_write_cb, sock, EV_WRITE);

    ev_io_init(&conn->ior, conn_read_cb, sock, EV_READ);
    ev_io_start(srv->loop, &conn->ior);

    ev_timer_init(&conn->timer, keepalive_cb, UHTTPD_CONNECTION_TIMEOUT, 0.0);
    ev_timer_start(srv->loop, &conn->timer);

#if UHTTPD_SSL_SUPPORT
    if (srv->ssl_ctx)
        conn->ssl = uh_ssl_new(srv->ssl_ctx, sock);
#endif

    http_parser_init(&conn->parser, HTTP_REQUEST);

    conn->parser.data = conn;

    conn->free = conn_free;
    conn->send = conn_send;
    conn->printf = conn_printf;
    conn->vprintf = conn_vprintf;
    conn->send_status_line = conn_send_status_line;
    conn->send_head = conn_send_head;
    conn->error = conn_error;
    conn->redirect = conn_redirect;

    conn->chunk_send = conn_chunk_send;
    conn->chunk_printf = conn_chunk_printf;
    conn->chunk_vprintf = conn_chunk_vprintf;
    conn->chunk_end = conn_chunk_end;

    conn->get_url = conn_get_url;
    conn->get_header = conn_get_header;
    conn->get_body = conn_get_body;

    return conn;
}

