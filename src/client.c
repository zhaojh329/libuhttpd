/*
 * Copyright (C) 2017  Jianhui Zhao <jianhuizhao329@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "uhttpd.h"
#include "client.h"
#include "file.h"
#include "utils.h"
#include "uh_ssl.h"

const char *const http_versions[] = {
	[UH_HTTP_VER_0_9] = "HTTP/0.9",
	[UH_HTTP_VER_1_0] = "HTTP/1.0",
	[UH_HTTP_VER_1_1] = "HTTP/1.1"
};

const char *const http_methods[] = {
	[UH_HTTP_MSG_GET] = "GET",
	[UH_HTTP_MSG_POST] = "POST",
	[UH_HTTP_MSG_HEAD] = "HEAD"
};

static inline void client_send(struct uh_client *cl, const void *data, int len)
{
    ustream_write(cl->us, data, len, true);
}

static void client_send_header(struct uh_client *cl, int code, const char *summary, int length)
{
    struct http_request *r = &cl->request;

    cl->printf(cl, "%s %03i %s\r\n", http_versions[cl->request.version], code, summary);
    cl->printf(cl, "Server: Libuhttpd %s\r\n", UHTTPD_VERSION_STRING);

     if (length < 0) {
        r->chunked = true;
        cl->printf(cl, "Transfer-Encoding: chunked\r\n");
    } else {
        cl->printf(cl, "Content-Length: %d\r\n", length);
    }
}

static inline void client_append_header(struct uh_client *cl, const char *name, const char *value)
{
    cl->printf(cl, "%s: %s\r\n", name, value);
}

static inline void client_header_end(struct uh_client *cl)
{
    cl->printf(cl, "\r\n");
}

static void client_send_error(struct uh_client *cl, int code, const char *summary, const char *fmt, ...)
{
    va_list arg;

    cl->send_header(cl, code, summary, -1);
    cl->printf(cl, "Content-Type: text/html\r\n\r\n");

    cl->chunk_printf(cl, "<h1>%s</h1>", summary);

    if (fmt) {
        va_start(arg, fmt);
        cl->chunk_vprintf(cl, fmt, arg);
        va_end(arg);
    }

    cl->request_done(cl);
}

static inline const char *client_get_peer_addr(struct uh_client *cl)
{
    return inet_ntoa(cl->peer_addr.sin_addr);
}

static inline const char *client_get_path(struct uh_client *cl)
{
    return kvlist_get(&cl->request.hdr, "path");
}

static inline const char *client_get_query(struct uh_client *cl)
{
    return kvlist_get(&cl->request.hdr, "query");   
}

static inline const char *client_get_header(struct uh_client *cl, const char *name)
{
    return kvlist_get(&cl->request.hdr, name);
}

static inline const char *client_get_body(struct uh_client *cl, int *len)
{
    *len = cl->dispatch.action.post_len;
    return cl->dispatch.action.body;
}

static void uh_handle_request(struct uh_client *cl)
{
    char *path = kvlist_get(&cl->request.hdr, "path");
#if (UHTTPD_DEBUG)
    const char *name, *value;
    kvlist_for_each(&cl->request.hdr, name, value) {
        uh_log_debug("%s: %s", name, value);
    }
#endif

    if (handle_action_request(cl, path))
        return;

    if (handle_file_request(cl, path))
		return;

	cl->send_error(cl, 404, "Not Found", "The requested PATH %s was not found on this server.", path);
}

static inline void connection_close(struct uh_client *cl)
{
	cl->us->eof = true;
    cl->state = CLIENT_STATE_CLOSE;
	ustream_state_change(cl->us);
}

static inline void keepalive_cb(struct uloop_timeout *timeout)
{
	struct uh_client *cl = container_of(timeout, struct uh_client, timeout);

    connection_close(cl);
}

static void dispatch_done(struct uh_client *cl)
{
	if (cl->dispatch.free)
		cl->dispatch.free(cl);
}

static inline int hdr_get_len(struct kvlist *kv, const void *data)
{
    return strlen(data);
}

static void client_request_done(struct uh_client *cl)
{
    struct http_request *r = &cl->request;

	if (r->chunked)
        cl->printf(cl, "0\r\n\r\n");

    dispatch_done(cl);

	if (cl->connection_close) {
		connection_close(cl);
        return;
    }

    cl->state = CLIENT_STATE_INIT;

    memset(&cl->request, 0, sizeof(cl->request));
    memset(&cl->dispatch, 0, sizeof(cl->dispatch));
    kvlist_init(&cl->request.hdr, hdr_get_len);
    uloop_timeout_set(&cl->timeout, UHTTPD_CONNECTION_TIMEOUT * 1000);
}

static void client_free(struct uh_client *cl)
{
    if (cl) {
        dispatch_done(cl);
        uloop_timeout_cancel(&cl->timeout);
        if (cl->srv->ssl)
            uh_ssl_client_detach(cl);
        ustream_free(&cl->sfd.stream);
        shutdown(cl->sfd.fd.fd, SHUT_RDWR);
        close(cl->sfd.fd.fd);
        list_del(&cl->list);
        kvlist_free(&cl->request.hdr);
        cl->srv->nclients--;

        uh_log_debug("client_free: %s:%d", inet_ntoa(cl->peer_addr.sin_addr), cl->peer_addr.sin_port);
        free(cl);
    }
}

static int client_parse_request(struct uh_client *cl, char *data)
{
    struct http_request *req = &cl->request;
    char *type, *url, *version, *p;
    int h_method, h_version;
    static char path[PATH_MAX];

    type = strtok(data, " ");
    url = strtok(NULL, " ");
    version = strtok(NULL, " ");
    if (!type || !url || !version)
        return CLIENT_STATE_DONE;

    h_method = find_idx(http_methods, ARRAY_SIZE(http_methods), type);
    h_version = find_idx(http_versions, ARRAY_SIZE(http_versions), version);
    if (h_method < 0 || h_version < 0) {
        req->version = UH_HTTP_VER_1_0;
        return CLIENT_STATE_DONE;
    }

    p = strchr(url, '?');
    if (p) {
        *p = 0;
        if (p[1])
            kvlist_set(&cl->request.hdr, "query", p + 1);
    }

    if (uh_urldecode(path, sizeof(path) - 1, url, strlen(url)) < 0)
        return CLIENT_STATE_DONE;

    kvlist_set(&cl->request.hdr, "path", path);
    
    req->method = h_method;
    req->version = h_version;
    if (req->version < UH_HTTP_VER_1_1)
        cl->connection_close = true;

    uh_log_debug("http method: %s", http_methods[h_method]);
    uh_log_debug("http version: %s", http_versions[h_version]);

    return CLIENT_STATE_HEADER;
}

static bool client_init_cb(struct uh_client *cl, char *buf, int len)
{
    char *newline;

    newline = strstr(buf, "\r\n");
    if (!newline)
        return false;

    if (newline == buf) {
        ustream_consume(cl->us, 2);
        return true;
    }

	*newline = 0;
    
    cl->state = client_parse_request(cl, buf);
    ustream_consume(cl->us, newline + 2 - buf);
    if (cl->state == CLIENT_STATE_DONE)
        cl->send_error(cl, 400, "Bad Request", NULL);

    return true;
}

static void client_poll_post_data(struct uh_client *cl)
{
    struct dispatch *d = &cl->dispatch;
    struct http_request *r = &cl->request;
    char *buf;
    int len;

    if (cl->state == CLIENT_STATE_DONE)
        return;

    while (1) {
        int cur_len;

        buf = ustream_get_read_buf(cl->us, &len);
        if (!buf || !len)
            break;

        if (!d->data_send)
            return;

        cur_len = min(r->content_length, len);
        if (cur_len) {
            if (d->data_send)
                cur_len = d->data_send(cl, buf, cur_len);

            r->content_length -= cur_len;
            ustream_consume(cl->us, cur_len);
            continue;
        }
    }

    if (!r->content_length && cl->state != CLIENT_STATE_DONE) {
        if (cl->dispatch.data_done)
            cl->dispatch.data_done(cl);

        cl->state = CLIENT_STATE_DONE;
    }
}

static inline bool client_data_cb(struct uh_client *cl, char *buf, int len)
{
    client_poll_post_data(cl);
    return false;
}

static void client_parse_header(struct uh_client *cl, char *data)
{
    struct http_request *r = &cl->request;
    char *err;
    char *name;
    char *val;

    if (!*data) {
        uloop_timeout_cancel(&cl->timeout);
        cl->state = CLIENT_STATE_DATA;
        uh_handle_request(cl);
        return;
    }

    val = uh_split_header(data);
    if (!val) {
        cl->state = CLIENT_STATE_DONE;
        return;
    }

    for (name = data; *name; name++)
        if (isupper(*name))
            *name = tolower(*name);

    if (!strcmp(data, "content-length")) {
        r->content_length = strtoul(val, &err, 0);
        if (err && *err) {
            cl->send_error(cl, 400, "Bad Request", "Invalid Content-Length");
            return;
        }
    } else if (!strcmp(data, "transfer-encoding") && !strcmp(val, "chunked")) {
        cl->send_error(cl, 501, "Not Implemented", "Chunked body is not implemented");
        return;
    } else if (!strcmp(data, "connection") && !strcasecmp(val, "close")) {
        cl->connection_close = true;
    }

    kvlist_set(&cl->request.hdr, data, val);

    cl->state = CLIENT_STATE_HEADER;
}

static bool client_header_cb(struct uh_client *cl, char *buf, int len)
{
	char *newline;
    int line_len;

    newline = strstr(buf, "\r\n");
    if (!newline)
        return false;

    *newline = 0;
    client_parse_header(cl, buf);
    line_len = newline + 2 - buf;
    ustream_consume(cl->us, line_len);
    if (cl->state == CLIENT_STATE_DATA)
        return client_data_cb(cl, newline + 2, len - line_len);

    return true;
}

typedef bool (*read_cb_t)(struct uh_client *cl, char *buf, int len);
static read_cb_t read_cbs[] = {
	[CLIENT_STATE_INIT] = client_init_cb,
	[CLIENT_STATE_HEADER] = client_header_cb,
	[CLIENT_STATE_DATA] = client_data_cb,
};

void uh_client_read_cb(struct uh_client *cl)
{
    struct ustream *us = cl->us;
    char *str;
    int len;

    do {
        str = ustream_get_read_buf(us, &len);
        if (!str || !len)
            return;

        if (cl->state >= ARRAY_SIZE(read_cbs) || !read_cbs[cl->state])
            return;

        if (!read_cbs[cl->state](cl, str, len)) {
            if (len == us->r.buffer_len && cl->state != CLIENT_STATE_DATA)
                cl->send_error(cl, 413, "Request Entity Too Large", NULL);
            break;
        }
    } while(1);
}

static void client_ustream_read_cb(struct ustream *s, int bytes)
{
    struct uh_client *cl = container_of(s, struct uh_client, sfd.stream);
    uh_client_read_cb(cl);
}

static void client_ustream_write_cb(struct ustream *s, int bytes)
{
    struct uh_client *cl = container_of(s, struct uh_client, sfd.stream);

    if (cl->dispatch.write_cb)
        cl->dispatch.write_cb(cl);
}

void uh_client_notify_state(struct uh_client *cl)
{
    struct ustream *us = cl->us;

    if (!us->write_error) {
        if (cl->state == CLIENT_STATE_DATA)
            return;

        if (!us->eof || us->w.data_bytes)
            return;
    }

    client_free(cl);
}

static void client_notify_state(struct ustream *s)
{
	struct uh_client *cl = container_of(s, struct uh_client, sfd.stream);

    uh_client_notify_state(cl);
}

void uh_accept_client(struct uh_server *srv, bool ssl)
{
    struct uh_client *cl;
	unsigned int sl;
	int sfd;
    struct sockaddr_in addr;

    sl = sizeof(addr);
	sfd = accept(srv->fd.fd, (struct sockaddr *)&addr, &sl);
	if (sfd < 0) {
        uh_log_err("accept");
		return;
    }

    cl = calloc(1, sizeof(struct uh_client));
    if (!cl) {
        uh_log_err("calloc");
        goto err;
    }

    memcpy(&cl->peer_addr, &addr, sizeof(addr));

    cl->us = &cl->sfd.stream;
    if (ssl) {
        uh_ssl_client_attach(cl);
    } else {
        cl->us->notify_read = client_ustream_read_cb;
        cl->us->notify_write = client_ustream_write_cb;
        cl->us->notify_state = client_notify_state;
    }

    cl->us->string_data = true;
    ustream_fd_init(&cl->sfd, sfd);

    cl->timeout.cb = keepalive_cb;
    uloop_timeout_set(&cl->timeout, UHTTPD_CONNECTION_TIMEOUT * 1000);

    list_add(&cl->list, &srv->clients);
    kvlist_init(&cl->request.hdr, hdr_get_len);
    
    cl->srv = srv;
    cl->srv->nclients++;

    cl->free = client_free;
    cl->send_error = client_send_error;
    cl->send_header = client_send_header;
    cl->append_header = client_append_header;
    cl->header_end = client_header_end;
    cl->request_done = client_request_done;

    cl->send = client_send;
    cl->printf = uh_printf;
    cl->vprintf = uh_vprintf;
    cl->chunk_send = uh_chunk_send;
    cl->chunk_printf = uh_chunk_printf;
    cl->chunk_vprintf = uh_chunk_vprintf;

    cl->get_peer_addr = client_get_peer_addr;
    cl->get_path = client_get_path;
    cl->get_query = client_get_query;
    cl->get_header = client_get_header;
    cl->get_body = client_get_body;

    uh_log_debug("new connection: %s:%d", cl->get_peer_addr(cl), addr.sin_port);

    return;
err:
    close(sfd);
}

