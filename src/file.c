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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>

#include "connection.h"
#include "mimetypes.h"


static const char *file_mktag(struct stat *s, char *buf, int len)
{
    snprintf(buf, len, "\"%" PRIx64 "-%" PRIx64 "-%" PRIx64 "\"",
             s->st_ino, s->st_size, (uint64_t)s->st_mtime);

    return buf;
}

static char *unix2date(time_t ts, char *buf, int len)
{
    struct tm *t = gmtime(&ts);

    strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT", t);

    return buf;
}

static time_t date2unix(const char *date)
{
    struct tm t;

    memset(&t, 0, sizeof(t));

    if (strptime(date, "%a, %d %b %Y %H:%M:%S %Z", &t) != NULL)
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
    const char *hdr = conn->get_header(conn, "If-Modified-Since");
    if (!hdr)
        return true;

    if (date2unix(hdr) >= s->st_mtime) {
        file_response_304(conn, s);
        return false;
    }

    return true;
}

static bool file_if_range(struct uh_connection *conn, struct stat *s)
{
    if (conn->get_header(conn, "If-Range")) {
        conn->error(conn, HTTP_STATUS_PRECONDITION_FAILED, NULL);
        return false;
    }

    return true;
}

static bool file_if_unmodified_since(struct uh_connection *conn, struct stat *s)
{
    const char *hdr = conn->get_header(conn, "If-Modified-Since");
    if (hdr && date2unix(hdr) <= s->st_mtime) {
        conn->error(conn, HTTP_STATUS_PRECONDITION_FAILED, NULL);
        return false;
    }

    return true;
}

static void file_if_gzip(struct uh_connection *conn, const char *path)
{
    const char *hdr = conn->get_header(conn, "Accept-Encoding");
    const char *extn = rindex(path, '.');

    if (!hdr || !strstr(hdr, "gzip"))
        return;

    if (extn && !strcmp(extn, ".gz"))
        conn->printf(conn, "Content-Encoding: gzip\r\n");
}

void serve_file(struct uh_connection *conn, const char *docroot, const char *index_page)
{
    const char *path = conn->get_path(conn);
    static char fullpath[512];
    struct stat st;

    if (!docroot || !docroot[0])
        docroot = ".";

    if (!index_page || !index_page[0])
        index_page = "index.html";

    strcpy(fullpath, docroot);

    if (!strcmp(path, "/")) {
        strcat(fullpath, "/");
        path = index_page;
    }
    
    strcat(fullpath, path);

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

    if (!file_if_modified_since(conn, &st) ||
        !file_if_range(conn, &st) ||
        !file_if_unmodified_since(conn, &st)) {
        conn->printf(conn, "\r\n");
        return;
    }

    conn->send_status_line(conn, HTTP_STATUS_OK, NULL);
    file_response_ok_hdrs(conn, &st);

    conn->printf(conn, "Content-Type: %s\r\n", file_mime_lookup(path));
    conn->printf(conn, "Content-Length: %" PRIu64 "\r\n", st.st_size);

    file_if_gzip(conn, path);

    conn->printf(conn, "\r\n");

    if (conn->get_method(conn) == HTTP_HEAD)
        return;

    conn->send_file(conn, fullpath);
}
