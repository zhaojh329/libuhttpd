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

#include "connection.h"
#include "uhttpd.h"
#include "utils.h"
#include "file.h"
#include "ssl.h"

static void conn_done(struct uh_connection *conn)
{
    struct ev_loop *loop = conn->srv->loop;

    buffer_pull(&conn->rb, NULL, buffer_length(&conn->rb));

    if (!http_should_keep_alive(&conn->parser))
        conn->flags |= CONN_F_SEND_AND_CLOSE;

    if (conn->flags & CONN_F_SEND_AND_CLOSE)
        ev_io_stop(loop, &conn->ior);

    ev_io_start(loop, &conn->iow);

    ev_timer_stop(loop, &conn->timer);
}

static void conn_send(struct uh_connection *conn, const void *data, ssize_t len)
{
    buffer_put_data(&conn->wb, data, len);
    ev_io_start(conn->srv->loop, &conn->iow);
}

static void conn_send_file(struct uh_connection *conn, const char *path)
{
    struct stat st;

    conn->file.fd = open(path, O_RDONLY);

    fstat(conn->file.fd, &st);

    conn->file.size = st.st_size;

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

    if (!http_should_keep_alive(&conn->parser))
        conn_printf(conn, "%s", "Connection: close\r\n");

    conn_send(conn, "\r\n", 2);
}

static void conn_error(struct uh_connection *conn, int code, const char *reason)
{
    if (conn->flags & CONN_F_SEND_AND_CLOSE)
        return;

    if (!reason)
        reason = http_status_str(code);
    conn_send_head(conn, code, strlen(reason), "Content-Type: text/plain\r\nConnection: close\r\n");
    conn_send(conn, reason, strlen(reason));

    conn->flags |= CONN_F_SEND_AND_CLOSE;

    conn_done(conn);
}

static void conn_redirect(struct uh_connection *conn, int code, const char *location, ...)
{
    struct buffer *wb = &conn->wb;
    va_list arg;

    assert((code == HTTP_STATUS_MOVED_PERMANENTLY || code == HTTP_STATUS_FOUND) && location);

    conn_send_status_line(conn, code, NULL);

    conn_printf(conn, "Location: ");
    va_start(arg, location);
    buffer_put_vprintf(wb, location, arg);
    va_end(arg);
    conn_send(conn, "\r\n", 2);

    conn_printf(conn, "Content-Length: 0\r\n");
    conn_send(conn, "\r\n", 2);

    conn_done(conn);
}

static const struct sockaddr *conn_get_addr(struct uh_connection *conn)
{
    return &conn->addr.sa;
}

static enum http_method conn_get_method(struct uh_connection *conn)
{
    return conn->parser.method;
}

static const char *conn_get_method_str(struct uh_connection *conn)
{
    return http_method_str(conn->parser.method);
}

/* offset of the request field */
#define ROF(c, a) (a - (const char *)c->rb.data)

/* data of the request field */
#define O2D(c, o) ((const char *)c->rb.data + o)

static struct uh_str conn_get_path(struct uh_connection *conn)
{
    struct http_parser_url *u = &conn->url_parser;
    struct uh_request *req = &conn->req;
    struct uh_str path;

    path.p = O2D(conn, u->field_data[UF_PATH].off) + req->url.offset;
    path.len = u->field_data[UF_PATH].len;

    return path;
}

static struct uh_str conn_get_query(struct uh_connection *conn)
{
    struct http_parser_url *u = &conn->url_parser;
    struct uh_request *req = &conn->req;
    struct uh_str query = {};

    if (!(u->field_set & (1 << UF_QUERY)))
        return query;

    query.p = O2D(conn, u->field_data[UF_QUERY].off) + req->url.offset;
    query.len = u->field_data[UF_QUERY].len;

    return query;
}

static struct uh_str conn_get_header(struct uh_connection *conn, const char *name)
{
    struct uh_request *req = &conn->req;
    int name_len = strlen(name);
    struct uh_str value = {};
    int i;

    for (i = 0; i < UHTTPD_MAX_HEADER_NUM; i++) {
        if (req->headers[i].field.offset == 0)
            return value;

        if (req->headers[i].field.length != name_len)
            continue;

        if (!strncasecmp(O2D(conn, req->headers[i].field.offset), name, name_len)) {
            value.p = O2D(conn, req->headers[i].value.offset);
            value.len = req->headers[i].value.length;
        }
    }

    return value;
}

static struct uh_str conn_get_body(struct uh_connection *conn)
{
    struct uh_request *req = &conn->req;
    struct uh_str body;

    body.p = O2D(conn, req->body.offset);
    body.len = req->body.length;

    return body;
}

static struct uh_str conn_extract_body(struct uh_connection *conn)
{
    struct uh_request *req = &conn->req;
    struct uh_str body;

    body.p = O2D(conn, req->body.offset);
    body.len = req->body.length;

    req->body.length = 0;

    buffer_discard(&conn->rb, body.len);

    return body;
}

static int on_message_begin_cb(struct http_parser *parser)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;

    memset(req, 0, sizeof(struct uh_request));

    req->last_was_header_value = true;

    http_parser_url_init(&conn->url_parser);

    ev_timer_start(conn->srv->loop, &conn->timer);

    return 0;
}

static int on_url_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;

    if (req->url.offset == 0)
        req->url.offset = ROF(conn, at);
    req->url.length += length;

    return 0;
}

static int on_header_field_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;

    if (req->last_was_header_value) {
        req->last_was_header_value = false;
        req->header_num++;

        if (req->header_num == UHTTPD_MAX_HEADER_NUM) {
            uh_log_err("Header too more\n");
            return 1;
        }

        req->headers[req->header_num - 1].field.offset = ROF(conn, at);
    }

    req->headers[req->header_num - 1].field.length += length;

    return 0;
}

static int on_header_value_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;

    if (!req->last_was_header_value) {
        req->last_was_header_value = true;
        req->headers[req->header_num - 1].value.offset = ROF(conn, at);
    }

    req->headers[req->header_num - 1].value.length += length;

    return 0;
}

static int on_headers_complete(struct http_parser *parser)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_server *srv = conn->srv;
    struct uh_request *req = &conn->req;
    struct uh_path_handler *h = srv->handlers;
    struct uh_plugin *p = srv->plugins;
    struct uh_str path;

    http_parser_parse_url(O2D(conn, req->url.offset), req->url.length, false, &conn->url_parser);

    if (conn->handler)
        return 0;

    path = conn->get_path(conn);

    while (h) {
        if (strlen(h->path) == path.len && !strncmp(path.p, h->path, path.len)) {
            conn->handler = h->handler;
            goto done;
        }
        h = h->next;
    }

    while (p) {
        if (strlen(p->h->path) == path.len && !strncmp(path.p, p->h->path, path.len)) {
            conn->handler = p->h->handler;
            goto done;
        }
        p = p->next;
    }

done:
    if (!conn->handler)
        conn->handler = srv->default_handler;

    if (!conn->handler) {
        conn_error(conn, HTTP_STATUS_NOT_FOUND, NULL);
        return -1;
    }

    conn->handler(conn, UH_EV_HEAD_COMPLETE);

    if (conn->flags & CONN_F_SEND_AND_CLOSE)
        return -1;

    return 0;
}

static int on_body_cb(struct http_parser *parser, const char *at, size_t length)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_request *req = &conn->req;

    if (req->body.offset == 0)
        req->body.offset = ROF(conn, at);
    req->body.length += length;

    conn->handler(conn, UH_EV_BODY);

    if (conn->flags & CONN_F_SEND_AND_CLOSE)
        return -1;

    return 0;
}

static int on_message_complete_cb(struct http_parser *parser)
{
    struct uh_connection *conn = (struct uh_connection *)parser->data;
    struct uh_server *srv = conn->srv;

    ev_timer_stop(srv->loop, &conn->timer);

    conn->handler(conn, UH_EV_COMPLETE);

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

void conn_free(struct uh_connection *conn)
{
    struct ev_loop *loop = conn->srv->loop;
    char addr_str[INET6_ADDRSTRLEN];
    int port;

    ev_timer_stop(loop, &conn->timer);
    ev_io_stop(loop, &conn->ior);
    ev_io_stop(loop, &conn->iow);

    buffer_free(&conn->rb);
    buffer_free(&conn->wb);

    if (conn->file.fd > 0)
        close(conn->file.fd);

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

    if (uh_log_get_threshold() == LOG_DEBUG) {
        saddr2str(&conn->addr.sa, addr_str, sizeof(addr_str), &port);
        uh_log_debug("Connection(%s %d) closed\n", addr_str, port);
    }

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
        if (conn->file.fd > 0) {
            ret = sendfile(w->fd, conn->file.fd, NULL, conn->file.size);
            if (ret < 0) {
                if (errno != EAGAIN) {
                    uh_log_err("write error: %s\n", strerror(errno));
                    conn_free(conn);
                }
                return;
            }

            if (ret < conn->file.size) {
                conn->file.size -= ret;
                return;
            }

            close(conn->file.fd);
            conn->file.fd = -1;
        }

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
    struct buffer *rb = &conn->rb;
    int ret, nread, length, nparsed;
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

    length = buffer_length(rb);

#if UHTTPD_SSL_SUPPORT
    if (conn->ssl)
        ret = buffer_put_fd_ex(rb, w->fd, -1, &eof, conn_ssl_read, conn->ssl);
    else
#endif
        ret = buffer_put_fd(rb, w->fd, -1, &eof);

    if (ret < 0) {
        conn_error(conn, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
        uh_log_err("read error: %s\n", strerror(errno));
        return;
    }

    if (eof) {
        conn_free(conn);
        return;
    }

    nread = buffer_length(rb) - length;

    nparsed = http_parser_execute(parser, &settings, (const char *)rb->data + length, nread);
    if (parser->upgrade)
        conn_error(conn, HTTP_STATUS_NOT_IMPLEMENTED, NULL);
    else if (nparsed != nread)
        conn_error(conn, HTTP_STATUS_BAD_REQUEST, http_errno_description(parser->http_errno));
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

    conn_error(conn, HTTP_STATUS_REQUEST_TIMEOUT, NULL);
}

struct uh_connection *uh_new_connection(struct uh_server *srv, int sock, struct sockaddr *addr)
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

    if (addr->sa_family == AF_INET)
        memcpy(&conn->addr, addr, sizeof(struct sockaddr_in));
    else
        memcpy(&conn->addr, addr, sizeof(struct sockaddr_in6));

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

    conn->done = conn_done;
    conn->send = conn_send;
    conn->send_file = conn_send_file;
    conn->printf = conn_printf;
    conn->vprintf = conn_vprintf;
    conn->send_status_line = conn_send_status_line;
    conn->send_head = conn_send_head;
    conn->error = conn_error;
    conn->redirect = conn_redirect;
    conn->serve_file = serve_file;

    conn->chunk_send = conn_chunk_send;
    conn->chunk_printf = conn_chunk_printf;
    conn->chunk_vprintf = conn_chunk_vprintf;
    conn->chunk_end = conn_chunk_end;

    conn->get_addr = conn_get_addr;
    conn->get_method = conn_get_method;
    conn->get_method_str = conn_get_method_str;
    conn->get_path = conn_get_path;
    conn->get_query = conn_get_query;
    conn->get_header = conn_get_header;
    conn->get_body = conn_get_body;
    conn->extract_body = conn_extract_body;

    return conn;
}
