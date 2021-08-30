/*
 * MIT License
 *
 * Copyright (c) 2021 Jianhui Zhao <zhaojh329@gmail.com>
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
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>

#include "file.h"
#include "cgi.h"

struct cgi_header_env {
    const char *header_name;
    int header_len;
    const char *env_name;
};

static struct cgi_header_env header_envs[] = {
    {"accept", strlen("accept"), "HTTP_ACCEPT"},
    {"accept-charset", strlen("accept-charset"), "HTTP_ACCEPT_CHARSET"},
    {"accept-encoding", strlen("accept-encoding"), "HTTP_ACCEPT_ENCODING"},
    {"accept-language", strlen("accept-language"), "HTTP_ACCEPT_LANGUAGE"},
    {"authorization", strlen("authorization"), "HTTP_AUTHORIZATION"},
    {"connection", strlen("connection"), "HTTP_CONNECTION"},
    {"cookie", strlen("cookie"), "HTTP_COOKIE"},
    {"host", strlen("host"), "HTTP_HOST"},
    {"origin", strlen("host"), "HTTP_ORIGIN"},
    {"referer", strlen("referer"), "HTTP_REFERER"},
    {"user-agent", strlen("user-agent"), "HTTP_USER_AGENT"},
    {"x-http-method-override", strlen("x-http-method-override"), "HTTP_X_HTTP_METHOD_OVERRIDE"},
    {"auth-user", strlen("auth-user"), "HTTP_AUTH_USER"},
    {"auth-pass", strlen("auth-pass"), "HTTP_AUTH_PASS"},
    {"content-type", strlen("content-type"), "CONTENT_TYPE"},
    {"content-length", strlen("content-length"), "CONTENT_LENGTH"},
    {}
};

static void ev_cgi_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    struct uh_cgi *cgi = container_of(w, struct uh_cgi, tmr);

    kill(cgi->proc.pid, SIGKILL);

    log_err("handle cgi timeout\n");
}

static void ev_cgi_exit_cb(struct ev_loop *loop, struct ev_child *w, int revents)
{
    struct uh_cgi *cgi = container_of(w, struct uh_cgi, proc);
    struct uh_connection *conn = cgi->conn;
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (!cgi->header_end) {
        conn->send_error(conn, HTTP_STATUS_BAD_GATEWAY, "The process did not produce any response");
        return;
    }

    conn->end_response(conn);

    cgi_free(conni);
}

static void ev_cgi_read_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_cgi *cgi = container_of(w, struct uh_cgi, ior);
    struct uh_connection *conn = cgi->conn;
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    bool eof;

    if (buffer_put_fd(&cgi->rb, w->fd, -1, &eof) < 0)
        return;

    if (!cgi->header_end) {
        int newline, header_len;
        char *buf;

        while (true) {
            newline = buffer_find(&cgi->rb, 0, 0, "\n", 1);
            if (newline < 0)
                goto check_eof;

            buf = buffer_data(&cgi->rb);
            header_len = newline;

            if (newline > 0 && buf[newline - 1] == '\r')
                header_len--;

            if (header_len) {
                buf[header_len] = '\0';

                if (!strncmp(buf, "Status:", 7)) {
                    char *sep;

                    buf += 7;

                    while (isspace(*buf))
                        buf++;
                    
                    sep = strchr(buf, ' ');
                    if (sep != buf + 3)
                        goto next;
                    *sep++ = '\0';
                    cgi->status_code = atoi(buf);
                    strncpy(cgi->status_msg, sep, sizeof(cgi->status_msg) - 1);
                } else {
                    buffer_put_data(&cgi->headers, buf, header_len);
                    buffer_put_data(&cgi->headers, "\r\n", 2);
                }
next:
                buffer_pull(&cgi->rb, NULL, newline + 1);
            } else {
                const char *status_msg = cgi->status_msg;

                buffer_pull(&cgi->rb, NULL, newline + 1);

                if (status_msg[0])
                    conn->send_head(conn, cgi->status_code, -1, "%s", status_msg);
                else
                    conn->send_head(conn, cgi->status_code, -1, NULL);

                buffer_put_data(&conni->wb, buffer_data(&cgi->headers), buffer_length(&cgi->headers));
                conn->end_headers(conn);

                if (conn->get_method(conn) == HTTP_HEAD)
                    cgi->skip_data = true;

                cgi->header_end = true;
                break;
            }
        }
    }

    if (!cgi->skip_data && buffer_length(&cgi->rb))
        conn->send(conn, buffer_data(&cgi->rb), buffer_length(&cgi->rb));
    buffer_pull(&cgi->rb, NULL, buffer_length(&cgi->rb));

check_eof:
    if (eof) {
        ev_io_stop(loop, w);
        close(w->fd);
        w->fd = -1;
    }

    ev_timer_stop(loop, &cgi->tmr);
    ev_timer_set(&cgi->tmr, CGI_TIMEOUT, 0);
    ev_timer_start(loop, &cgi->tmr);
}

static void ev_cgi_write_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct uh_cgi *cgi = container_of(w, struct uh_cgi, iow);
    int ret;

    ret = buffer_pull_to_fd(&cgi->wb, w->fd, -1);
    if (ret > 0)
        cgi->content_length -= ret;

    if (cgi->content_length == 0) {
        close(w->fd);
        ev_io_stop(loop, w);
        w->fd = -1;
        return;
    }

    if (buffer_length(&cgi->wb) == 0)
        ev_io_stop(loop, w);
}

static bool check_buf_length(char **buf, int *olen, int nlen)
{
    if (nlen > *olen) {
        char *temp = realloc(*buf, nlen + 1);
        if (!temp)
            return false;

        *olen = nlen;
        *buf = temp;
    }

    return true;
}

static int set_env_us(char **buf, int *olen, const char *name, struct uh_str *value)
{
    if (!check_buf_length(buf, olen, value->len))
        return -1;

    memcpy(*buf, value->p, value->len);
    (*buf)[value->len] = '\0';

    setenv(name, *buf, 1);

    return 0;
}

static int set_env_addr(char **buf, int *olen, const char *name_prefix, const struct sockaddr *addr)
{
    char name[128];
    int port;

    if (!check_buf_length(buf, olen, INET6_ADDRSTRLEN))
        return -1;

    saddr2str(addr, *buf, INET6_ADDRSTRLEN + 1, &port);

    snprintf(name, sizeof(name), "%s_NAME", name_prefix);
    setenv(name, *buf, 1);

    snprintf(name, sizeof(name), "%s_ADDR", name_prefix);
    setenv(name, *buf, 1);

    sprintf(*buf, "%d", port);
    snprintf(name, sizeof(name), "%s_PORT", name_prefix);
    setenv(name, *buf, 1);

    return 0;
}

static void set_header_envs(struct uh_connection *conn)
{
    struct cgi_header_env *he = header_envs;
    char *buf = NULL;
    int len = 0;

    while (he->header_name) {
        struct uh_str value = conn->get_header(conn, he->header_name);
        if (value.len == 0)
            goto next;

        if (set_env_us(&buf, &len, he->env_name, &value))
            break;
next:
        he++;
    }

    free(buf);
}

static void set_extra_vars(struct uh_connection *conn, struct path_info *pi)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct uh_server_internal *srv = conni->l->srv;
    struct uh_str query = conn->get_query(conn);
    struct uh_str uri = conn->get_uri(conn);
    char *buf = NULL;
    int len = 0;

    setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
    setenv("SERVER_SOFTWARE", "libuhttpd", 1);
    setenv("SCRIPT_NAME", pi->name, 1);
    setenv("PATH_INFO", pi->info, 1);
    setenv("SCRIPT_FILENAME", pi->phys, 1);
    setenv("DOCUMENT_ROOT", srv->docroot, 1);
    setenv("REQUEST_METHOD", conn->get_method_str(conn), 1);

    if (conni->ssl)
        setenv("HTTPS", "on", 1);

    if (set_env_us(&buf, &len, "REQUEST_URI", &uri))
        goto free;

    if (set_env_us(&buf, &len, "QUERY_STRING", &query))
        goto free;

    if (!check_buf_length(&buf, &len, 8))
        goto free;
    snprintf(buf, len + 1, "HTTP/%d.%d", conni->parser.http_major, conni->parser.http_minor);
    setenv("SERVER_PROTOCOL", buf, 1);

    if (set_env_addr(&buf, &len, "SERVER", &conni->saddr.sa))
        goto free;

    if (set_env_addr(&buf, &len, "REMOTE", &conni->paddr.sa))
        goto free;

free:
    free(buf);
}

static int create_cgi(struct uh_connection *conn, struct path_info *pi)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct uh_server_internal *srv = conni->l->srv;
    struct ev_loop *loop = srv->loop;
    struct uh_cgi *cgi;
    int rfd[2], wfd[2];
    pid_t pid;

    if (pipe2(rfd, O_CLOEXEC))
        return -1;

    if (pipe2(wfd, O_CLOEXEC))
        goto close_rfd;

    cgi = calloc(1, sizeof(struct uh_cgi));
    if (!cgi)
        goto close_wfd;

    cgi->status_code = HTTP_STATUS_OK;
    cgi->conn = conn;
    cgi->content_length = conni->parser.content_length;

    pid = fork();
    if (pid < 0)
        goto free_cgi;

    if (!pid) {
        close(0);
        close(1);
        close(2);

        dup2(rfd[1], STDOUT_FILENO);
        dup2(wfd[0], STDIN_FILENO);

        close(rfd[0]);
        close(rfd[1]);
        close(wfd[0]);
        close(wfd[1]);

        clearenv();
        set_extra_vars(conn, pi);
        set_header_envs(conn);

        if (!chdir(pi->root))
            execl(pi->phys, pi->phys, NULL);

        printf("Status: 500 Internal Server Error\r\n\r\n"
               "Unable to launch the requested CGI program:\n"
               "  %s: %s\n", pi->phys, strerror(errno));

        exit(0);
    }

    close(rfd[1]);
    close(wfd[0]);

    ev_io_init(&cgi->ior, ev_cgi_read_cb, rfd[0], EV_READ);
    ev_io_start(loop, &cgi->ior);

    ev_io_init(&cgi->iow, ev_cgi_write_cb, wfd[1], EV_WRITE);

    ev_child_init(&cgi->proc, ev_cgi_exit_cb, pid, 0);
    ev_child_start(loop, &cgi->proc);

    ev_timer_init(&cgi->tmr, ev_cgi_timeout_cb, CGI_TIMEOUT, 0);
    ev_timer_start(loop, &cgi->tmr);

    conni->cgi = cgi;

    return 0;

free_cgi:
    free(cgi);

close_wfd:
    close(wfd[0]);
    close(wfd[1]);

close_rfd:
    close(rfd[0]);
    close(rfd[1]);

    return -1;
}

void serve_cgi(struct uh_connection *conn, int event)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;

    if (event == UH_EV_HEAD_COMPLETE) {
        struct path_info *pi;
        struct stat st;

        pi = parse_path_info(conni);
        if (!pi) {
            conn->send_error(conn, HTTP_STATUS_BAD_REQUEST, NULL);
            return;
        }

        if (stat(pi->phys, &st) < 0) {
            int code;

            switch (errno) {
            case EACCES:
                code = HTTP_STATUS_FORBIDDEN;
            break;
                case ENOENT:
                code = HTTP_STATUS_NOT_FOUND;
            break;
            default:
                code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
            };

            conn->send_error(conn, code, NULL);
            return;
        }

        if (!S_ISLNK(st.st_mode) && !S_ISREG(st.st_mode)) {
            conn->send_error(conn, 403, NULL);
            return;
        }

        if (access(pi->phys, X_OK)) {
            conn->send_error(conn, 403, NULL);
            return;
        }

        if (create_cgi(conn, pi) < 0) {
            conn->send_error(conn, HTTP_STATUS_INTERNAL_SERVER_ERROR,
                "Failed to create CGI process: %s", strerror(errno));
            return;
        }
    } else if (event == UH_EV_BODY) {
        struct uh_str body = conn->extract_body(conn);
        struct uh_cgi *cgi = conni->cgi;

        buffer_put_data(&cgi->wb, body.p, body.len);
        ev_io_start(conni->l->srv->loop, &cgi->iow);
    }
}

void cgi_free(struct uh_connection_internal *conn)
{
    struct uh_server_internal *srv = conn->l->srv;
    struct ev_loop *loop = srv->loop;
    struct uh_cgi *cgi = conn->cgi;

    if (!conn->cgi)
        return;

    ev_child_stop(loop, &cgi->proc);
    ev_timer_stop(loop, &cgi->tmr);

    buffer_free(&cgi->headers);
    buffer_free(&cgi->rb);
    buffer_free(&cgi->wb);

    if (cgi->ior.fd > -1) {
        close(cgi->ior.fd);
        ev_io_stop(loop, &cgi->ior);
    }

    if (cgi->iow.fd > -1) {
        close(cgi->ior.fd);
        ev_io_stop(loop, &cgi->iow);
    }

    free(cgi);

    conn->cgi = NULL;
}
