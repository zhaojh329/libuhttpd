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

struct path_info *parse_path_info(struct uh_connection_internal *conn)
{
    struct uh_server_internal *srv = conn->l->srv;
    struct uh_str path = conn->com.get_path(&conn->com);
    const char *docroot = srv->docroot;
    const char *index_page = srv->index_page;
    static char buf[PATH_MAX];
    static char path_phys[PATH_MAX];
    static char path_info[PATH_MAX];
    static struct path_info pi = {};
    static struct stat st;
    int docroot_len, i;

    if (!docroot || !docroot[0])
        docroot = ".";

    docroot_len = strlen(docroot);

    if (docroot[docroot_len - 1] == '/')
        docroot_len--;

    if (!index_page || !index_page[0])
        index_page = "index.html";

    memcpy(buf, docroot, docroot_len);

    if (path.len == 1) {
        buf[docroot_len] = '/';
        strcpy(buf + docroot_len + 1, index_page);
    } else if (urldecode(buf + docroot_len, PATH_MAX - docroot_len, path.p, path.len) < 0) {
        return NULL;
    }

    for (i = strlen(buf); i > docroot_len; i--) {
        char ch = buf[i];

        if (ch != '\0' && ch != '/')
            continue;

        memcpy(path_phys, buf, i);
        path_phys[i] = '\0';

        if (stat(path_phys, &st) || !S_ISREG(st.st_mode))
            continue;

        snprintf(path_info, sizeof(path_info), "%s", buf + i);
        break;
    }

    memset(&pi, 0, sizeof(struct path_info));

    if (i > docroot_len) {
        pi.phys = path_phys;
        pi.name = &path_phys[docroot_len];
        pi.st = &st;
    } else {
        pi.phys = buf;
        pi.name = &buf[docroot_len];
        pi.st = stat(pi.phys, &st) ? NULL : &st;
    }

    pi.root = docroot;
    pi.info = path_info;

    log_info("phys: %s, name: %s, info: %s\n", pi.phys, pi.name, pi.info);

    return &pi;
}

static const char *file_mktag(struct stat *s, char *buf, int len)
{
    snprintf(buf, len, "\"%" PRIx64 "-%" PRIx64 "-%" PRIx64 "\"",
             (uint64_t)s->st_ino, (uint64_t)s->st_size, (uint64_t)s->st_mtime);

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
        conn->send_header(conn, "ETag", "%s", file_mktag(s, buf, sizeof(buf)));
        conn->send_header(conn, "Last-Modified", "%s", unix2date(s->st_mtime, buf, sizeof(buf)));
    }
    conn->send_header(conn, "Date", "%s", unix2date(time(NULL), buf, sizeof(buf)));
}

static void file_response_304(struct uh_connection *conn, struct stat *s)
{
    conn->send_head(conn, HTTP_STATUS_NOT_MODIFIED, 0, NULL);

    file_response_ok_hdrs(conn, s);

    conn->end_headers(conn);
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
        conn->send_error(conn, HTTP_STATUS_PRECONDITION_FAILED, NULL);
        return false;
    }

    return true;
}

static bool file_if_unmodified_since(struct uh_connection *conn, struct stat *s)
{
    const struct uh_str hdr = conn->get_header(conn, "If-Unmodified-Since");
    if (hdr.p && date2unix(hdr) <= s->st_mtime) {
        conn->send_error(conn, HTTP_STATUS_PRECONDITION_FAILED, NULL);
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

    conn->send_header(conn, "Content-Encoding", "gzip");
}

static bool file_range(struct uh_connection *conn, uint64_t size, uint64_t *start, uint64_t *end, bool *ranged)
{
    const struct uh_str hdr = conn->get_header(conn, "Range");
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
        return false;

    p = hdr.p;
    e = hdr.p + hdr.len;

    if (strncmp(p, "bytes=", 6))
        return false;

    p += 6;
    i = 0;

    while (p < e) {
        if (i >= sizeof(buf) - 1)
            return false;

        if (isdigit(*p)) {
            buf[i++] = *p++;
            continue;
        }

        if (*p != '-')
            return false;

        p++;
        buf[i] = '\0';

        break;
    }

    *start = strtoull(buf, NULL, 0);

    i = 0;

    while (p < e) {
        if (i >= (sizeof(buf) - 1) || !isdigit(*p))
            return false;
        buf[i++] = *p++;
    }

    buf[i] = '\0';
    *end = strtoull(buf, NULL, 0);

    if (*start >= size)
        return false;

    if (*end == 0)
        *end = size - 1;

    if (*end < *start)
        return false;

    if (*end > size - 1)
        *end = size - 1;

    *ranged = true;

    return true;
}

static void __serve_file(struct uh_connection *conn, struct stat *st, const char *path, const char *filename)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    uint64_t start, end;
    const char *mime;
    bool ranged;
    int fd, len;

    if (!st) {
        conn->send_error(conn, HTTP_STATUS_NOT_FOUND, NULL);
        return;
    }

    if (!S_ISREG(st->st_mode)) {
        conn->send_error(conn, HTTP_STATUS_FORBIDDEN, NULL);
        return;
    }

    if (!file_range(conn, st->st_size, &start, &end, &ranged)) {
        conn->send_head(conn, HTTP_STATUS_RANGE_NOT_SATISFIABLE, 0, NULL);
        conn->send_header(conn, "Content-Range", "bytes */%" PRIu64, st->st_size);
        conn->send_header(conn, "Content-Type", "text/plain");
        conn->send_header(conn, "Connection", "close");
        conn->end_headers(conn);
        conni->flags |= CONN_F_SEND_AND_CLOSE;
        return;
    }

    if (!file_if_modified_since(conn, st) ||
        !file_if_range(conn, st) ||
        !file_if_unmodified_since(conn, st)) {
        conn->end_response(conn);
        return;
    }

    if (ranged)
        conn->send_head(conn, HTTP_STATUS_PARTIAL_CONTENT, end - start + 1, NULL);
    else
        conn->send_head(conn, HTTP_STATUS_OK, end - start + 1, NULL);

    file_response_ok_hdrs(conn, st);

    mime = file_mime_lookup(path);

    if (filename) {
        conn->send_header(conn, "Content-Disposition", "attachment; filename=\"%s\"", filename);
        conn->send_header(conn, "Content-Type", "application/octet-stream");
    } else {
        conn->send_header(conn, "Content-Type", "%s", mime);
    }

    if (ranged)
        conn->send_header(conn, "Content-Range", "bytes %" PRIu64 "-%" PRIu64 "/%" PRIu64, start, end, (uint64_t)st->st_size);
    else
        file_if_gzip(conn, path, mime);

    conn->end_headers(conn);

    if (conn->get_method(conn) == HTTP_HEAD)
        goto done;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        log_err("open: %s\n", strerror(errno));
        conn->close(conn);
        return;
    }

    lseek(fd, start, SEEK_SET);
    st->st_size -= start;

    len = end - start + 1;

    /* If the file is greater than 2K, use sendfile */
    if (len > 2048) {
        conni->file.size = len;
        conni->file.fd = fd;
#ifdef SSL_SUPPORT
        if (conni->ssl)
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
    } else {
        while (len)
            len -= buffer_put_fd(&conni->wb, fd, len, NULL);

        close(fd);
    }

done:
    conn->end_response(conn);
}

void serve_file(struct uh_connection *conn)
{
    struct uh_connection_internal *conni = (struct uh_connection_internal *)conn;
    struct path_info *pi = parse_path_info(conni);

    if (!pi) {
        conn->send_error(conn, HTTP_STATUS_BAD_REQUEST, NULL);
        return;
    }

    switch (conn->get_method(conn)) {
    case HTTP_GET:
    case HTTP_HEAD:
        break;
    default:
        conn->send_error(conn, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
        return;
    }

    __serve_file(conn, pi->st, pi->phys, NULL);
}

void download_file(struct uh_connection *conn, const char *path, const char *filename)
{
    struct stat st;

    if (stat(path, &st))
        __serve_file(conn, NULL, path, filename);
    else
        __serve_file(conn, &st, path, filename);
}
