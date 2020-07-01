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

#include "uhttpd.h"

static void on_request(struct uh_connection *conn)
{
    int body_len;
    const char *body = conn->get_body(conn, &body_len);

    conn->send_head(conn, HTTP_STATUS_OK, -1, NULL);
    conn->chunk_printf(conn, "I'm Libuhttpd: %s\n", UHTTPD_VERSION_STRING);
    conn->chunk_printf(conn, "Method: %s\n", conn->get_method_str(conn));
    conn->chunk_printf(conn, "Path: %s\n", conn->get_path(conn));
    conn->chunk_printf(conn, "Query: %s\n", conn->get_query(conn));
    conn->chunk_printf(conn, "User-Agent: %s\n", conn->get_header(conn, "User-Agent"));
    conn->chunk_printf(conn, "Body: %.*s\n", body_len, body);
    conn->chunk_end(conn);
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
            "          -p port  # Default port is 8080\n"
            "          -s       # SSl on\n"
            "          -v       # verbose\n", prog);
    exit(1);
}

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    struct ev_signal signal_watcher;
    struct uh_server *srv = NULL;
    bool verbose = false;
    bool ssl = false;
    int port = 8080;
    int opt;

    while ((opt = getopt(argc, argv, "p:sv")) != -1) {
        switch (opt) {
        case 'p':
            port = atoi(optarg);
            break;
        case 's':
            ssl = true;
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

    srv = uh_server_new(loop, "0.0.0.0", port);
    if (!srv)
        return -1;

#if UHTTPD_SSL_SUPPORT
    if (ssl && srv->ssl_init(srv, "server-cert.pem", "server-key.pem") < 0)
        goto err;
#endif

    srv->on_request = on_request;

    srv->load_plugin(srv, "/usr/local/lib/uhttpd/test.so");

    uh_log_info("Listen on: *:%d\n", port);

    ev_signal_init(&signal_watcher, signal_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher);

    ev_run(loop, 0);

err:
    srv->free(srv);
    free(srv);

    return 0;
}

