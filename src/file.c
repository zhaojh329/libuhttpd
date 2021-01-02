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

#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <inttypes.h>
#include <ctype.h>

#include "uhttpd_internal.h"
#include "mimetypes.h"
#include "file.h"

static const char *file_mktag(struct stat *s, char *buf, int len)
{
    snprintf(buf, len, "\"%" PRIx64 "-%" PRIx64 "-%" PRIx64 "\"",
             (uint64_t)s->st_ino, s->st_size, (uint64_t)s->st_mtime);

    return buf;
}

static char *unix2date(time_t ts, char *buf, int len)
{
    struct tm *t = gmtime(&ts);

    strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT", t);

    return buf;
}

static time_t date2unix(const struct uh_str date)
{
    struct tm t;
    char buf[128] = "";

    memset(&t, 0, sizeof(t));

    strncpy(buf, date.p, date.len);

    if (strptime(buf, "%a, %d %b %Y %H:%M:%S %Z", &t) != NULL)
        return timegm(&t);

    return 0;
}

static void file_response_ok_hdrs(struct uh_connection *conn, struct stat *s)
{
    char buf[128];
    
    if (s) {
        conn->printf(conn, "ETag: %s\r\n", file_mktag(s, buf, sizeof(buf)));
        conn->printf(conn, "Last-Modified: %s\r\n", unix2date(s->st_mtime, buf, sizeof(buf)));

    }
    conn->printf(conn, "Date: %s\r\n", unix2date(time(NULL), buf, sizeof(buf)));
}

static void file_response_304(struct uh_connection *conn, struct stat *s)
{
    conn->send_status_line(conn, HTTP_STATUS_NOT_MODIFIED, NULL);

    file_response_ok_hdrs(conn, s);
}

static bool file_if_modified_since(struct uh_connection *conn, struct stat *s)
{
    const struct uh_str hdr = conn->get_header(conn, "If-Modified-Since");
    if (!hdr.p)
        return true;

    if (date2unix(hdr) >= s->st_mtime) {
        file_response_304(conn, s);
        return false;
    }

    return true;
}

static bool file_if_range(struct uh_connection *conn, struct stat *s)
{
    const struct uh_str hdr = conn->get_header(conn, "If-Range");
    if (hdr.p) {
        conn->error(conn, HTTP_STATUS_PRECONDITION_FAILED, NULL);
        return false;
    }

    return true;
}

static bool file_if_unmodified_since(struct uh_connection *conn, struct stat *s)
{
    const struct uh_str hdr = conn->get_header(conn, "If-Unmodified-Since");
    if (hdr.p && date2unix(hdr) <= s->st_mtime) {
        conn->error(conn, HTTP_STATUS_PRECONDITION_FAILED, NULL);
        return false;
    }

    return true;
}

static void file_if_gzip(struct uh_connection *conn, const char *path, const char *mime)
{
    const struct uh_str hdr = conn->get_header(conn, "Accept-Encoding");
    uint8_t magic[2] = {};
    int fd;

    if (!hdr.p || !memmem(hdr.p, hdr.len, "gzip", 4))
        return;

    if (strcmp(mime, "text/css") && strcmp(mime, "text/javascript") && strcmp(mime, "text/html"))
        return;

    fd = open(path, O_RDONLY);
    if (read(fd, magic, 2) != 2) {
        close(fd);
        return;
    }
    close(fd);

    /* gzip magic */
    if (magic[0] != 0x1f || magic[1] != 0x8b)
        return;

    conn->printf(conn, "Content-Encoding: gzip\r\n");
}

static bool file_range(struct uh_connection *conn, size_t size, size_t *start, size_t *end, bool *ranged)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    const struct uh_str hdr = conn->get_header(conn, "Range");
    int content_length;
    const char *reason;
    const char *p, *e;
    char buf[32];
    int i;

    *start = 0;
    *end = size - 1;

    if (!hdr.p) {
        *ranged = false;
        return true;
    }

    if (hdr.len < 8)
        goto err;

    p = hdr.p;
    e = hdr.p + hdr.len;

    if (strncmp(p, "bytes=", 6))
        goto err;

    p += 6;
    i = 0;

    while (p < e) {
        if (i >= sizeof(buf) - 1)
            goto err;

        if (isdigit(*p)) {
            buf[i++] = *p++;
            continue;
        }

        if (*p != '-')
            goto err;

        p++;
        buf[i] = '\0';

        break;
    }

    *start = strtoul(buf, NULL, 0);

    i = 0;

    while (p < e) {
        if (i >= (sizeof(buf) - 1) || !isdigit(*p))
            goto err;
        buf[i++] = *p++;
    }

    buf[i] = '\0';
    *end = strtoul(buf, NULL, 0);

    if (*start >= size)
        goto err;

    if (*end == 0)
        *end = size - 1;

    if (*end < *start)
        goto err;

    if (*end > size - 1)
        *end = size - 1;

    *ranged = true;

    return true;

err:
    reason = http_status_str(HTTP_STATUS_RANGE_NOT_SATISFIABLE);
    content_length = strlen(reason);

    conn->send_status_line(conn, HTTP_STATUS_RANGE_NOT_SATISFIABLE, "Content-Type: text/plain\r\nConnection: close\r\n");
    conn->printf(conn, "Content-Length: %d\r\n", content_length);
    conn->printf(conn, "Content-Range: bytes */%" PRIu64 "\r\n", size);

    conn->send(conn, "\r\n", 2);

    conn->send(conn, reason, content_length);

    conni->flags |= CONN_F_SEND_AND_CLOSE;

    conn->done(conn);

    return false;
}

void serve_file(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    const struct uh_str path = conn->get_path(conn);
    struct uh_server_internal *srv = conni->srv;
    const char *docroot = srv->docroot;
    const char *index_page = srv->index_page;
    static char fullpath[512];
    size_t start, end;
    const char *mime;
    struct stat st;
    bool ranged;

    if (!docroot || !docroot[0])
        docroot = ".";

    if (!index_page || !index_page[0])
        index_page = "index.html";

    strcpy(fullpath, docroot);

    if (!strncmp(path.p, "/", path.len)) {
        strcat(fullpath, "/");
        strcat(fullpath, index_page);
    } else {
        strncat(fullpath, path.p, path.len);
    }

    if (stat(fullpath, &st) < 0) {
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

        conn->error(conn, code, NULL);
        return;
    }

    if (!S_ISLNK(st.st_mode) && !S_ISREG(st.st_mode)) {
        conn->error(conn, 403, NULL);
        return;
    }

    switch (conn->get_method(conn)) {
    case HTTP_GET:
    case HTTP_HEAD:
        break;
    default:
        conn->error(conn, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
        return;
    }

    if (!file_range(conn, st.st_size, &start, &end, &ranged))
        return;

    if (!file_if_modified_since(conn, &st) ||
        !file_if_range(conn, &st) ||
        !file_if_unmodified_since(conn, &st)) {
        conn->printf(conn, "\r\n");
        return;
    }

    if (ranged)
        conn->send_status_line(conn, HTTP_STATUS_PARTIAL_CONTENT, NULL);
    else
        conn->send_status_line(conn, HTTP_STATUS_OK, NULL);

    file_response_ok_hdrs(conn, &st);

    mime = file_mime_lookup(fullpath);

    conn->printf(conn, "Content-Type: %s\r\n", mime);
    conn->printf(conn, "Content-Length: %" PRIu64 "\r\n", end - start + 1);

    if (ranged)
        conn->printf(conn, "Content-Range: bytes %" PRIu64 "-%" PRIu64 "/%" PRIu64 "\r\n", start, end, st.st_size);
    else
        file_if_gzip(conn, fullpath, mime);

    conn->printf(conn, "\r\n");

    if (conn->get_method(conn) == HTTP_HEAD)
        return;

    conn->send_file(conn, fullpath, start, end - start + 1);

    conn->done(conn);
}
