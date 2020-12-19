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

static bool serve_file = false;
static const char *docroot = ".";
static const char *index_page = "index.html";

static void default_handler(struct uh_connection *conn, int event)
{
    if (event != UH_EV_COMPLETE)
        return;

    if (!serve_file) {
        struct uh_str path = conn->get_path(conn);
        struct uh_str query = conn->get_query(conn);
        struct uh_str ua = conn->get_header(conn, "User-Agent");
        struct uh_str body = conn->get_body(conn);

        conn->send_head(conn, HTTP_STATUS_OK, -1, NULL);
        conn->chunk_printf(conn, "I'm Libuhttpd: %s\n", UHTTPD_VERSION_STRING);
        conn->chunk_printf(conn, "Method: %s\n", conn->get_method_str(conn));
        conn->chunk_printf(conn, "Path: %.*s\n", path.len ,path.p);
        conn->chunk_printf(conn, "Query: %.*s\n", query.len, query.p);
        conn->chunk_printf(conn, "User-Agent: %.*s\n", ua.len, ua.p);
        conn->chunk_printf(conn, "Body: %.*s\n", body.len, body.p);
        conn->chunk_end(conn);
        conn->done(conn);
    } else {
        conn->serve_file(conn, docroot, index_page);
    }
}

static void upload_handler(struct uh_connection *conn, int event)
{
    static int fd = -1;

    if (event == UH_EV_BODY) {
        struct uh_str body = conn->extract_body(conn);

        if (fd < 0) {
            fd = open("upload.bin", O_RDWR | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                conn->error(conn, HTTP_STATUS_INTERNAL_SERVER_ERROR, strerror(errno));
                return;
            }
        }

        if (write(fd, body.p, body.len) < 0) {
            conn->error(conn, HTTP_STATUS_INTERNAL_SERVER_ERROR, strerror(errno));
            close(fd);
            return;
        }
    } else {
        struct stat st;
        size_t size = 0;

        conn->send_head(conn, HTTP_STATUS_OK, -1, NULL);

        if (fd > 0) {
            fstat(fd, &st);
            close(fd);

            fd = -1;
            size = st.st_size;
        }

        conn->chunk_printf(conn, "Upload size: %zd\n", size);
        conn->chunk_end(conn);
        conn->done(conn);
    }
}

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    if (w->signum == SIGINT) {
        ev_break(loop, EVBREAK_ALL);
        uh_log_info("Normal quit\n");
    }
}


static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [option]\n"
            "          -a addr  # Default addr is localhost\n"
            "          -p port  # Default port is 8080\n"
            "          -s       # SSl on\n"
            "          -f       # Serve file\n"
            "          -P       # plugin path\n"
            "          -v       # verbose\n", prog);
    exit(1);
}

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    struct ev_signal signal_watcher;
    struct uh_server *srv = NULL;
    const char *plugin_path = NULL;
    bool verbose = false;
    bool ssl = false;
    const char *addr = "localhost";
    int port = 8080;
    int opt;

    while ((opt = getopt(argc, argv, "a:p:sfP:v")) != -1) {
        switch (opt) {
        case 'a':
            addr = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 's':
            ssl = true;
            break;
        case 'f':
            serve_file = true;
            break;
        case 'P':
            plugin_path = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    if (!verbose)
        uh_log_threshold(LOG_ERR);

    uh_log_info("libuhttpd version: %s\n", UHTTPD_VERSION_STRING);

    signal(SIGPIPE, SIG_IGN);

    srv = uh_server_new(loop, addr, port);
    if (!srv)
        return -1;

#if UHTTPD_SSL_SUPPORT
    if (ssl && srv->ssl_init(srv, "server-cert.pem", "server-key.pem") < 0)
        goto err;
#endif

    srv->default_handler = default_handler;

    srv->add_path_handler(srv, "/upload", upload_handler);

    if (plugin_path)
        srv->load_plugin(srv, plugin_path);

    ev_signal_init(&signal_watcher, signal_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher);

    ev_run(loop, 0);

err:
    srv->free(srv);
    free(srv);

    ev_loop_destroy(loop);

    return 0;
}
