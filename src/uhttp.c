#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

#include "internal.h"
#include "uhttp/uhttp.h"
#include "uhttp/ssl.h"

const char *uh_version()
{
    return UHTTP_VERSION_STRING;
}

static const char *http_status_str(enum http_status s)
{
	switch (s) {
#define XX(num, name, string) case num : return #string;
	HTTP_STATUS_MAP(XX)
#undef XX
	}
	return "<unknown>";
}

static void uh_connection_destroy(struct uh_connection *con)
{
    if (con) {
        struct ev_loop *loop = con->srv->loop;
    
        if (con->sock > 0)
            close(con->sock);
        
        uh_buf_free(&con->read_buf);
        uh_buf_free(&con->write_buf);
        
        ev_io_stop(loop, &con->read_watcher);
        ev_io_stop(loop, &con->write_watcher);
        ev_timer_stop(loop, &con->timer_watcher);

        list_del(&con->list);

        uh_ssl_free(con);

        uh_log_debug("destroy connection(%p)", con);
        
        free(con);
    }
}

static void connection_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    struct uh_connection *con = container_of(w, struct uh_connection, timer_watcher);
    uh_log_debug("connection(%p) timeout", con);
    uh_send_error(con, HTTP_STATUS_REQUEST_TIMEOUT, NULL);
}

static int uh_con_reuse(struct uh_connection *con)
{
    con->flags = 0;
    memset(&con->req, 0, sizeof(struct uh_request));

    http_parser_init(&con->parser, HTTP_REQUEST);
    ev_timer_mode(con->srv->loop, &con->timer_watcher, UH_CONNECTION_TIMEOUT, 0);

    /* Retain pre allocated memory to improve performance */
    uh_buf_remove(&con->read_buf, con->read_buf.len);
    uh_buf_remove(&con->write_buf, con->write_buf.len);
    
    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t len)
{
    struct uh_connection *con = container_of(parser, struct uh_connection, parser);
    struct http_parser_url url;

    uh_log_debug("Url:[%.*s]", (int)len, at);

    con->req.url.at = at;
    con->req.url.len = len;

    if (len > UH_URI_SIZE_LIMIT) {
        uh_send_error(con, HTTP_STATUS_URI_TOO_LONG, NULL);
        return -1;
    }

    if (http_parser_parse_url(at, len, 0, &url)) {
        uh_log_err("http_parser_parse_url() failed");
        uh_send_error(con, HTTP_STATUS_BAD_REQUEST, NULL);
        return -1;
    }

    con->req.path.at = at + url.field_data[UF_PATH].off;
    con->req.path.len = url.field_data[UF_PATH].len;

    uh_log_debug("Path:[%.*s]", (int)con->req.path.len, con->req.path.at);
    
    if (url.field_set & (1 << UF_QUERY)) {
        con->req.query.at = at + url.field_data[UF_QUERY].off;
        con->req.query.len = url.field_data[UF_QUERY].len;
        uh_log_debug("Query:[%.*s]", (int)con->req.query.len, con->req.query.at);
    }
    
    return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t len)
{
    struct uh_connection *con = container_of(parser, struct uh_connection, parser);
    struct uh_header *header = con->req.header;

	uh_log_debug("header field:[%.*s]", (int)len, at);

    header[con->req.header_num].field.at = at;
    header[con->req.header_num].field.len = len;
    
    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t len)
{
    struct uh_connection *con = container_of(parser, struct uh_connection, parser);
    struct uh_header *header = con->req.header;

	uh_log_debug("header value:[%.*s]", (int)len, at);
	
    header[con->req.header_num].value.at = at;
    header[con->req.header_num].value.len = len;
    con->req.header_num += 1;
    
    return 0;
}

static int on_headers_complete(http_parser *parser)
{
    struct uh_connection *con = container_of(parser, struct uh_connection, parser);
    
    if (parser->method != HTTP_GET && parser->method != HTTP_POST) {
        uh_send_error(con, HTTP_STATUS_NOT_IMPLEMENTED, NULL);
        return -1;
    }
    
    return 0;
}

static int on_body(http_parser *parser, const char *at, size_t len)
{
    struct uh_connection *con = container_of(parser, struct uh_connection, parser);

	uh_log_debug("body:[%.*s]", (int)len, at);
	
    if (!con->req.body.at)
        con->req.body.at = at;
    
    con->req.body.len += len;

    if (con->req.body.len > UH_BODY_SIZE_LIMIT) {
        uh_send_error(con, HTTP_STATUS_PAYLOAD_TOO_LARGE, NULL);
        return -1;
    }
    
    return 0;
}


/* Return 1 for equal */
static int uh_str_cmp(struct uh_str *uv, const char *str)
{
    if (uv->len != strlen(str))
        return 0;

    return (!strncasecmp(uv->at, str, uv->len));
}

static int on_message_complete(http_parser *parser)
{
    struct uh_connection *con = container_of(parser, struct uh_connection, parser);
    struct uh_hook *h;

    list_for_each_entry(h, &con->srv->hooks, list) {
        if (uh_str_cmp(&con->req.path, h->path)) {
            h->cb(con);
            if (!(con->flags & UH_CON_CLOSE))
                con->flags |= UH_CON_REUSE;
            return 0;
        }
    }

    uh_send_error(con, HTTP_STATUS_NOT_FOUND, NULL);
    
    return 0;
}


static http_parser_settings parser_settings = {
    .on_url              = on_url,
    .on_header_field     = on_header_field,
    .on_header_value     = on_header_value,
    .on_headers_complete = on_headers_complete,
    .on_body             = on_body,
    .on_message_complete = on_message_complete
};

static void connection_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    struct uh_connection *con = container_of(w, struct uh_connection, read_watcher);
    struct uh_buf *buf = &con->read_buf;
    char *base;
    int len, parsered;
    
#if (UHTTP_SSL_ENABLED)
    if (con->flags & UH_CON_SSL_HANDSHAKE_DONE)
        goto handshake_done;

    uh_ssl_handshake(con);
    if (con->flags & UH_CON_CLOSE)
        uh_connection_destroy(con);
    return;
    
handshake_done:
#endif

    if (uh_buf_available(buf) < UH_BUFFER_SIZE)
        uh_buf_grow(buf, UH_BUFFER_SIZE);

    base = buf->base + buf->len;
    
    len = uh_ssl_read(con, base, UH_BUFFER_SIZE);
    if (unlikely(len <= 0)) {
        if (con->flags & UH_CON_CLOSE)
            uh_connection_destroy(con);
        return;
    }

    buf->len += len;

    uh_log_debug("read:[%.*s]", len, base);

    parsered = http_parser_execute(&con->parser, &parser_settings, base, len);

    if (unlikely(con->flags & UH_CON_CLOSE))
        return;
    
    if (unlikely(parsered != len)) {
        uh_log_err("http_parser_execute() failed:%s", http_errno_description(HTTP_PARSER_ERRNO(&con->parser)));
        uh_send_error(con, HTTP_STATUS_BAD_REQUEST, NULL);
        return;
    }

    ev_timer_mode(loop, &con->timer_watcher, UH_CONNECTION_TIMEOUT, 0);
}

static void connection_write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    struct uh_connection *con = container_of(w, struct uh_connection, write_watcher);
    struct uh_buf *buf = &con->write_buf;
    
    if (buf->len > 0) {
        int len = uh_ssl_write(con, buf->base, buf->len);
        if (len > 0)
            uh_buf_remove(buf, len);
    }

    if (buf->len == 0) {
        ev_io_stop(loop, w);

        if (!http_should_keep_alive(&con->parser))
            con->flags |= UH_CON_CLOSE;

        if (con->flags & UH_CON_REUSE)
            uh_con_reuse(con);
    }

    if (con->flags & UH_CON_CLOSE)
        uh_connection_destroy(con);
}

static void uh_accept_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    int sock = -1;
    struct uh_server *srv = container_of(w, struct uh_server, read_watcher);
    struct uh_connection *con = NULL;
    ev_io *read_watcher, *write_watcher;
    ev_timer *timer_watcher;
    
    con = calloc(1, sizeof(struct uh_connection));
    if (unlikely(!con)) {
        uh_log_err("calloc");
        return;
    }

    con->srv = srv;
    list_add(&con->list, &srv->connections);
        
    sock = uh_ssl_accept(con);
    if (unlikely(sock < 0))
        goto err;

    read_watcher = &con->read_watcher;
    ev_io_init(read_watcher, connection_read_cb, sock, EV_READ);
    ev_io_start(loop,read_watcher);

    write_watcher = &con->write_watcher;
    ev_io_init(write_watcher, connection_write_cb, sock, EV_WRITE);

    timer_watcher = &con->timer_watcher; 
    ev_timer_init(timer_watcher, connection_timeout_cb, UH_CONNECTION_TIMEOUT, 0);
    ev_timer_start(loop, timer_watcher);
        
    http_parser_init(&con->parser, HTTP_REQUEST);
    
    uh_log_debug("new connection:%p", con);
    return;
err:
    uh_connection_destroy(con);
}

struct uh_server *uh_server_new(struct ev_loop *loop, const char *ipaddr, int port)
{
    struct uh_server *srv = NULL;
    struct sockaddr_in addr;
    int sock = -1, on = 1;
    ev_io *read_watcher;
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ipaddr, &addr.sin_addr) <= 0) {
        uh_log_err("invalid ipaddr");
        return NULL;
    }
    
    srv = calloc(1, sizeof(struct uh_server));
    if (!srv) {
        uh_log_err("calloc");
        return NULL;
    }

    INIT_LIST_HEAD(&srv->hooks);
    INIT_LIST_HEAD(&srv->connections);
    
    sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        uh_log_err("socket");
        goto err;
    }

    srv->sock = sock;
    srv->loop = loop;
    
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
        uh_log_err("bind");
        goto err;
    }

    if (listen(sock, SOMAXCONN) < 0) {
        uh_log_err("listen");
        goto err;
    }

    read_watcher = &srv->read_watcher;
    ev_io_init(read_watcher, uh_accept_cb, sock, EV_READ);
    ev_io_start(loop, read_watcher);
    
    return srv;

err:
    uh_server_free(srv);
    return NULL;
}

void uh_server_free(struct uh_server *srv)
{
    if (srv) {
        struct uh_connection *con, *tmp_c;
        struct uh_hook *h, *tmp_h;
    
        if (srv->sock > 0)
            close(srv->sock);
        
        ev_io_stop(srv->loop, &srv->read_watcher);
        
        list_for_each_entry_safe(con, tmp_c, &srv->connections, list) {
            uh_connection_destroy(con);
        }

        list_for_each_entry_safe(h, tmp_h, &srv->hooks, list) {
            list_del(&h->list);
            free(h->path);
            free(h);
        }

        uh_ssl_ctx_free(srv);
        
        free(srv);
    }
}

int uh_send(struct uh_connection *con, const void *buf, int len)
{
    len = uh_buf_append(&con->write_buf, buf, len);
    if (len > 0)
        ev_io_start(con->srv->loop, &con->write_watcher);
    return len;
}

int uh_printf(struct uh_connection *con, const char *fmt, ...)
{
    int len = 0;
    va_list ap;
    char *str = NULL;

    assert(fmt);

    if (*fmt) {
        va_start(ap, fmt);
        len = vasprintf(&str, fmt, ap);
        va_end(ap);
    }
    
    if (len >= 0) {
        len = uh_send(con, str, len);
        free(str);
    }
    return len;
}

static void send_status_line(struct uh_connection *con, int code)
{
    const char *reason = http_status_str(code);
    uh_printf(con, "HTTP/1.1 %d %s\r\nServer: Libuhttp %s\r\n",
        code, reason, UHTTP_VERSION_STRING);
}

void uh_send_head(struct uh_connection *con, int status, int length, const char *extra_headers)
{
    send_status_line(con, status);
    
    if (length < 0)
        uh_printf(con, "%s", "Transfer-Encoding: chunked\r\n");
    else
        uh_printf(con, "Content-Length: %d\r\n", length);

    if (extra_headers) 
        uh_send(con, extra_headers, strlen(extra_headers));

    uh_send(con, "\r\n", 2);
}

void uh_send_error(struct uh_connection *con, int code, const char *reason)
{    
    if (!reason)
        reason = http_status_str(code);

    if (http_should_keep_alive(&con->parser) && code < HTTP_STATUS_BAD_REQUEST) {
        uh_send_head(con, code, strlen(reason), "Content-Type: text/plain\r\nConnection: keep-alive\r\n");
    } else {
        uh_send_head(con, code, strlen(reason), "Content-Type: text/plain\r\nConnection: close\r\n");
        con->flags |= UH_CON_CLOSE;
    }

    uh_send(con, reason, strlen(reason));
}

void uh_redirect(struct uh_connection *con, int code, const char *location)
{
    char body[128] = "";
    
    snprintf(body, sizeof(body), "<p>Moved <a href=\"%s\">here</a></p>", location);  

    send_status_line(con, code);

    uh_printf(con,
        "Location: %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-cache\r\n", location, strlen(body));
    
    uh_send(con, "\r\n", 2);
}

int uh_send_chunk(struct uh_connection *con, const char *buf, int len)
{
    int slen = 0;
    slen += uh_printf(con, "%X\r\n", len);
    slen += uh_send(con, buf, len);
    slen += uh_send(con, "\r\n", 2);
    return slen;
}

int uh_printf_chunk(struct uh_connection *con, const char *fmt, ...)
{
    int len = 0;
    va_list ap;
    char *str = NULL;

    assert(fmt);

    if (*fmt) {
        va_start(ap, fmt);
        len = vasprintf(&str, fmt, ap);
        va_end(ap);
    }

    if (len >= 0) {
        len = uh_send_chunk(con, str, len);
        free(str);
    }

    return len;
}

int uh_register_hook(struct uh_server *srv, const char *path, uh_hookfn_t cb)
{
    struct uh_hook *h;

    assert(path);

    h = calloc(1, sizeof(struct uh_hook));
    if (!h) {
        uh_log_err("calloc");
        return -1;
    }

    h->path = strdup(path);
    if (!h->path) {
        uh_log_err("strdup");
        free(h);
        return -1;
    }
    
    h->cb = cb;
    list_add(&h->list, &srv->hooks);
    
    return 0;   
}

inline struct uh_str *uh_get_url(struct uh_connection *con)
{
    return &con->req.url;
}

inline struct uh_str *uh_get_path(struct uh_connection *con)
{
    return &con->req.path;
}

inline struct uh_str *uh_get_query(struct uh_connection *con)
{
    return &con->req.query;
}

static inline char c2hex(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : c - 'a' + 10; /* accept small letters just in case */
}

int uh_unescape(const char *str, int len, char *out, int olen)
{
    const char *p = str;
    char *o = out;

    assert(str && out);

    olen -= 1;
    
    while ((p - str < len) && (o - out < olen)) {
        if (*p == '%') {
            p++;

            if (p + 1 - str < len) {
                *o = c2hex(*p++) << 4;
                *o += c2hex(*p++);
                o++;
            }
            
        } else if (*p == '+') {
            *o++ = ' ';
            p++;
        } else {
            *o++ = *p++;
        }
    }

    *o = 0;
    
    return 0;
}

struct uh_str uh_get_var(struct uh_connection *con, const char *name)
{
    struct uh_str *query = &con->req.query;
    const char *pos = query->at, *tail = query->at + query->len - 1;
    const char *p, *q;
    struct uh_str var = {.at = NULL, .len = 0};

    assert(con && name);
    
    if (query->len == 0)
        return var;

    while (pos < tail) {
        p = memchr(pos, '&', tail - pos);
        if (p) {
            q = memchr(pos, '=', p - pos);
            if (q) {
                if (q - pos != strlen(name)) {
                    pos = p + 1;
                    continue;
                }

                if (strncmp(pos, name, strlen(name))) {
                    pos = p + 1;
                    continue;
                }

                var.at = q + 1;
                var.len = p - q - 1;

                return var;
            }
            pos = p + 1;
        } else {
            p = tail;
            q = memchr(pos, '=', tail - pos);
            if (q) {                
                if (q - pos == strlen(name) && !strncmp(pos, name, strlen(name))) {
                    var.at = q + 1;
                    var.len = p - q;
                    return var;
                }
            }
            break;
        }
    }

    return var;
}

struct uh_str *uh_get_header(struct uh_connection *con, const char *name)
{
    int i;
    struct uh_header *header = con->req.header;
    
    for (i = 0; i < con->req.header_num; i++) {
        if (uh_str_cmp(&header[i].field, name))
            return &header[i].value;
    }
    return NULL;
}

