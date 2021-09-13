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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "uhttpd.h"

void echo_handler(struct uh_connection *conn, int event)
{
    if (event == UH_EV_COMPLETE) {
        struct uh_str path = conn->get_path(conn);
        struct uh_str query = conn->get_query(conn);
        struct uh_str ua = conn->get_header(conn, "User-Agent");
        struct uh_str body = conn->get_body(conn);

        conn->send_head(conn, HTTP_STATUS_OK, -1, NULL);
        conn->send_header(conn, "Content-Type", "text/plain");
        conn->end_headers(conn);

        conn->printf(conn, "I'm Libuhttpd: %s\n", UHTTPD_VERSION_STRING);
        conn->printf(conn, "Method: %s\n", conn->get_method_str(conn));
        conn->printf(conn, "Path: %.*s\n", (int)path.len, path.p);
        conn->printf(conn, "Query: %.*s\n", (int)query.len, query.p);
        conn->printf(conn, "User-Agent: %.*s\n", (int)ua.len, ua.p);
        conn->printf(conn, "Body: %.*s\n", (int)body.len, body.p);

        conn->end_response(conn);
    }
}

void upload_handler(struct uh_connection *conn, int event)
{
    if (event == UH_EV_HEAD_COMPLETE) {
        uint64_t content_length = conn->get_content_length(conn);

        if (content_length > 1024 * 1024 * 1024) {
            conn->send_error(conn, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Too big");
            return;
        }

        conn->check_expect_100_continue(conn);

        conn->userdata = (void *)(intptr_t)-1;

    } if (event == UH_EV_BODY) {
        struct uh_str body = conn->extract_body(conn);
        int fd = (intptr_t)conn->userdata;

        if (fd < 0) {
            fd = open("upload.bin", O_RDWR | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                conn->send_error(conn, HTTP_STATUS_INTERNAL_SERVER_ERROR, "open: %s", strerror(errno));
                return;
            }
        }

        if (write(fd, body.p, body.len) < 0) {
            conn->send_error(conn, HTTP_STATUS_INTERNAL_SERVER_ERROR, "write: %s", strerror(errno));
            close(fd);
            return;
        }

        conn->userdata = (void *)(intptr_t)fd;
    } else if (event == UH_EV_COMPLETE) {
        int fd = (intptr_t)conn->userdata;
        struct stat st;
        size_t size = 0;

        conn->send_head(conn, HTTP_STATUS_OK, -1, NULL);
        conn->end_headers(conn);

        if (fd > 0) {
            fstat(fd, &st);
            close(fd);

            fd = -1;
            size = st.st_size;
        }

        conn->printf(conn, "Upload size: %zd\n", size);
        conn->end_response(conn);
    }
}
