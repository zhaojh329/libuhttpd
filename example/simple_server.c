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

#include "handler.h"

static void conn_closed_cb(struct uh_connection *conn)
{
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
            "          -h docroot     # Document root, default is .\n"
            "          -i index_page  # Index page, default is index.html\n"
            "          -a addr        # address to listen\n"
            "          -s addr        # address to listen with ssl\n"
            "          -P             # plugin path\n"
            "          -v             # verbose\n", prog);
    exit(1);
}

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    struct ev_signal signal_watcher;
    struct uh_server *srv = NULL;
    const char *plugin_path = NULL;
    bool verbose = false;
    const char *docroot = ".";
    const char *index_page = "index.html";
    int opt;

    srv = uh_server_new(loop);
    if (!srv)
        return -1;

    while ((opt = getopt(argc, argv, "h:i:a:s:P:v")) != -1) {
        switch (opt) {
        case 'h':
            docroot = optarg;
            break;
        case 'i':
            index_page = optarg;
            break;
        case 'a':
            if (srv->listen(srv, optarg, false) < 1)
                goto err;
            break;
        case 's':
            if (srv->listen(srv, optarg, true) < 1)
                goto err;
            break;
        case 'P':
            plugin_path = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        default:
            usage(argv[0]);
        }
    }

    if (!verbose)
        uh_log_threshold(LOG_ERR);

    uh_log_info("libuhttpd version: %s\n", UHTTPD_VERSION_STRING);

    signal(SIGPIPE, SIG_IGN);

#ifdef SSL_SUPPORT
    srv->ssl_init(srv, "cert.pem", "key.pem");
#endif

    srv->set_docroot(srv, docroot);
    srv->set_index_page(srv, index_page);

    srv->set_conn_closed_cb(srv, conn_closed_cb);
    srv->set_default_handler(srv, default_handler);
    srv->add_path_handler(srv, "/echo", echo_handler);
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
