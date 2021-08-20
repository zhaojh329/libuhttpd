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


static void conn_done(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct ev_loop *loop = conni->srv->loop;

    if (conni->flags & CONN_F_CLOSED)
        return;

    if (!http_should_keep_alive(&conni->parser))
        conni->flags |= CONN_F_SEND_AND_CLOSE;

    if (conni->flags & CONN_F_SEND_AND_CLOSE)
        ev_io_stop(loop, &conni->ior);

    ev_io_start(loop, &conni->iow);

    ev_timer_stop(loop, &conni->timer);

    /* This is needed for a connection requested multiple times on different path */
    conni->handler = NULL;
}

static void conn_send(struct uh_connection *conn, const void *data, ssize_t len)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (conni->flags & CONN_F_CLOSED)
        return;

    buffer_put_data(&conni->wb, data, len);
    ev_io_start(conni->srv->loop, &conni->iow);
}

static void conn_send_file(struct uh_connection *conn, const char *path, off_t offset, int64_t len)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct stat st;
    int fd;

    if (conni->flags & CONN_F_CLOSED)
        return;

    if (len == 0)
        return;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        log_err("open: %s\n", strerror(errno));
        return;
    }

    fstat(fd, &st);

    if (offset >= st.st_size) {
        close(fd);
        return;
    }

    lseek(fd, offset, SEEK_SET);
    st.st_size -= offset;

    if (len < 0 || len > st.st_size)
        len = st.st_size;

    /* If the file is not greater than 2K, then append it to the HTTP head, send once */
    if (len <= 2048) {
        bool eof = false;

        while (!eof)
            buffer_put_fd(&conni->wb, fd, -1, &eof);

        close(fd);
    } else {
        conni->file.size = len;
        conni->file.fd = fd;
#ifdef SSL_SUPPORT
        if (conni->ssl)
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
    }

    ev_io_start(conni->srv->loop, &conni->iow);
}

static void conn_printf(struct uh_connection *conn, const char *format, ...)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct buffer *wb = &conni->wb;
    va_list arg;

    if (conni->flags & CONN_F_CLOSED)
        return;

    va_start(arg, format);
    buffer_put_vprintf(wb, format, arg);
    va_end(arg);

    ev_io_start(conni->srv->loop, &conni->iow);
}

static void conn_vprintf(struct uh_connection *conn, const char *format, va_list arg)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (conni->flags & CONN_F_CLOSED)
        return;

    buffer_put_vprintf(&conni->wb, format, arg);
    ev_io_start(conni->srv->loop, &conni->iow);
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

static void conn_send_head(struct uh_connection *conn, int code, int64_t content_length, const char *extra_headers)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    conn_send_status_line(conn, code, extra_headers);
    if (content_length < 0)
        conn_printf(conn, "%s", "Transfer-Encoding: chunked\r\n");
    else
        conn_printf(conn, "Content-Length: %" PRIu64 "\r\n", content_length);

    if (!http_should_keep_alive(&conni->parser))
        conn_printf(conn, "%s", "Connection: close\r\n");

    conn_send(conn, "\r\n", 2);
}

static void conn_error(struct uh_connection *conn, int code, const char *reason)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (conni->flags & CONN_F_SEND_AND_CLOSE)
        return;

    if (!reason)
        reason = http_status_str(code);
    conn_send_head(conn, code, strlen(reason), "Content-Type: text/plain\r\nConnection: close\r\n");
    conn_send(conn, reason, strlen(reason));

    conni->flags |= CONN_F_SEND_AND_CLOSE;

    conn_done(conn);
}

static void conn_redirect(struct uh_connection *conn, int code, const char *location, ...)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct buffer *wb = &conni->wb;
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
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return &conni->addr.sa;
}

static enum http_method conn_get_method(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return conni->parser.method;
}

static const char *conn_get_method_str(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return http_method_str(conni->parser.method);
}

/* offset of the request field */
#define ROF(c, a) (a - (const char *)c->rb.data)

/* data of the request field */
#define O2D(c, o) ((const char *)c->rb.data + o)

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

    req->last_was_header_value = true;

    http_parser_url_init(&conn->url_parser);

    ev_timer_start(conn->srv->loop, &conn->timer);

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

static bool set_path_handler(struct uh_connection_internal *conn, struct uh_path_handler *h,
    struct uh_str *path, bool wildcard)
{
    while (h) {
        if (wildcard) {
            int match = 0;

            if (!(h->flags & UH_PATH_WILDCARD))
                goto next;

            if (path->len < h->len)
                goto next;

            if (h->flags & UH_PATH_MATCH_START) {
                if (strncmp(path->p, h->path, h->len))
                    goto next;
                match++;
            }

            if (h->flags & UH_PATH_MATCH_END) {
                if (strncmp(path->p + (path->len - h->len), h->path, h->len))
                    goto next;
                match++;
            }

            if (!match && !memmem(path->p, path->len, h->path, h->len))
                goto next;

            conn->handler = h->handler;
            return true;
        } else {
            if (h->flags & UH_PATH_WILDCARD)
                goto next;

            if (h->len == path->len && !strncmp(path->p, h->path, path->len)) {
                conn->handler = h->handler;
                return true;
            }
        }

next:
        h = h->next;
    }

    return false;
}

static int on_headers_complete(struct http_parser *parser)
{
    struct uh_connection_internal *conn = (struct uh_connection_internal *)parser->data;
    struct uh_server_internal *srv = conn->srv;
    struct uh_request *req = &conn->req;
    struct uh_plugin *p = srv->plugins;
    struct uh_str path;

    http_parser_parse_url(O2D(conn, req->url.offset), req->url.length, false, &conn->url_parser);

    path = conn->com.get_path(&conn->com);

    /* match non wildcard path handler */
    if (set_path_handler(conn, srv->handlers, &path, false))
        goto done;

    /* match wildcard path handler */
    if (set_path_handler(conn, srv->handlers, &path, true))
        goto done;

    /* match plugin */
    while (p) {
        if (p->len == path.len && !strncmp(path.p, p->h->path, path.len)) {
            conn->handler = p->h->handler;
            goto done;
        }
        p = p->next;
    }

done:
    if (!conn->handler)
        conn->handler = srv->default_handler;

    if (!conn->handler) {
        conn_error(&conn->com, HTTP_STATUS_NOT_FOUND, NULL);
        return -1;
    }

    conn->handler(&conn->com, UH_EV_HEAD_COMPLETE);

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
    struct uh_server_internal *srv = conn->srv;

    ev_timer_stop(srv->loop, &conn->timer);

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
    struct ev_loop *loop = conn->srv->loop;
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

    if (conn->prev)
        conn->prev->next = conn->next;
    else
        conn->srv->conns = conn->next;

    if (conn->next)
        conn->next->prev = conn->prev;

#ifdef SSL_SUPPORT
    ssl_session_free(conn->ssl);
#endif

  if (conn->srv->conn_closed_cb)
        conn->srv->conn_closed_cb(&conn->com);

    if (conn->sock > 0)
        close(conn->sock);

    log_debug("Connection(%s %d) closed\n",
            saddr2str(&conn->addr.sa, addr_str, sizeof(addr_str), &port), port);

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
            conn_error(&conn->com, HTTP_STATUS_NOT_IMPLEMENTED, NULL);
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
        conn_error(&conn->com, HTTP_STATUS_BAD_REQUEST, http_errno_description(parser->http_errno));
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
        log_err("ssl connect error(%d): %s\n", ssl_err_code, ssl_strerror(ssl_err_code, err_buf, sizeof(err_buf)));
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
        log_err("ssl_read(%d): %s\n", ssl_err_code,
                ssl_strerror(ssl_err_code, err_buf, sizeof(err_buf)));
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
            log_err("ssl_write(%d): %s\n", ssl_err_code,
                    ssl_strerror(ssl_err_code, err_buf, sizeof(err_buf)));
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
            ev_io_stop(loop, w);

            http_parser_pause(&conn->parser, false);

            if (buffer_length(&conn->rb) > 0)
                conn_http_parse(conn);
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

    conn_error(&conn->com, HTTP_STATUS_REQUEST_TIMEOUT, NULL);
}

static struct uh_server *conn_get_server(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return &conni->srv->com;
}

static struct ev_loop *conn_get_loop(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    return conni->srv->loop;
}

static void conn_init_cb(struct uh_connection *conn)
{
    conn->get_server = conn_get_server;
    conn->get_loop = conn_get_loop;
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
    conn->traverse_headers = conn_traverse_headers;
    conn->get_content_length = conn_get_content_length;
    conn->get_body = conn_get_body;
    conn->extract_body = conn_extract_body;

    conn->close = conn_close;

    conn->incref = conn_incref;
    conn->decref = conn_decref;
}

struct uh_connection_internal *uh_new_connection(struct uh_listener *l, int sock, struct sockaddr *addr)
{
    struct uh_server_internal *srv = l->srv;
    struct uh_connection_internal *conn;

    conn = calloc(1, sizeof(struct uh_connection_internal));
    if (!conn) {
        log_err("malloc: %s\n", strerror(errno));
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

#ifdef SSL_SUPPORT
    if (l->ssl)
        conn->ssl = ssl_session_new(srv->ssl_ctx, sock);
#endif

    http_parser_init(&conn->parser, HTTP_REQUEST);

    conn->parser.data = conn;

    conn_init_cb(&conn->com);

    conn_incref((struct uh_connection *)conn);

    log_debug("New connection: %p\n", conn);

    return conn;
}
