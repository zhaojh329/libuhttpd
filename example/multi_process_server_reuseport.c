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

#include <sys/sysinfo.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "handler.h"

#define MAX_WORKER  10

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    int i;

    if (w->signum == SIGINT) {
        pid_t *workers = w->data;

        for (i = 0; i < MAX_WORKER; i++) {
            if (workers[i] == 0)
                break;
            kill(workers[i], SIGKILL);
        }

        ev_break(loop, EVBREAK_ALL);
        uh_log_info("Normal quit\n");
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [option]\n"
            "          -h docroot     # Document root, default is .\n"
            "          -i index_page  # Index page, default is index.html\n"
            "          -a addr        # Default addr is localhost\n"
            "          -p port        # Default port is 8080\n"
            "          -s             # SSl on\n"
            "          -P             # plugin path\n"
            "          -w             # worker process number, default is equal to available CPUs\n"
            "          -v             # verbose\n", prog);
    exit(1);
}

static void start_server(const char *addr, int port, const char *docroot, const char *index_page, const char *plugin, bool ssl)
{
    struct ev_loop *loop = ev_loop_new(0);
    struct uh_server *srv = NULL;

    signal(SIGPIPE, SIG_IGN);

    srv = uh_server_new(loop, addr, port);
    if (!srv)
        return;

#if UHTTPD_SSL_SUPPORT
    if (ssl && srv->ssl_init(srv, "server-cert.pem", "server-key.pem") < 0)
        return;
#endif

    srv->set_docroot(srv, docroot);
    srv->set_index_page(srv, index_page);

    srv->set_default_handler(srv, default_handler);
    srv->add_path_handler(srv, "/echo", echo_handler);
    srv->add_path_handler(srv, "/upload", upload_handler);

    if (plugin)
        srv->load_plugin(srv, plugin);

    ev_run(loop, 0);
}

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    struct ev_signal signal_watcher;
    const char *plugin_path = NULL;
    bool verbose = false;
    bool ssl = false;
    const char *docroot = ".";
    const char *index_page = "index.html";
    const char *addr = "localhost";
    pid_t workers[MAX_WORKER] = {};
    int nworker = get_nprocs();
    int port = 8080;
    int opt, i;

    while ((opt = getopt(argc, argv, "h:i:a:p:sP:w:v")) != -1) {
        switch (opt) {
        case 'h':
            docroot = optarg;
            break;
        case 'i':
            index_page = optarg;
            break;
        case 'a':
            addr = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 's':
            ssl = true;
            break;
        case 'P':
            plugin_path = optarg;
            break;
        case 'w':
            nworker = atoi(optarg);
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

    if (!support_so_reuseport()) {
        uh_log_err("Not support SO_REUSEPORT\n");
        return -1;
    }

    if (nworker < 1)
        return 0;

    for (i = 0; i < nworker; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            uh_log_info("fork: %s\n", strerror(errno));
            break;
        }

        if (pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            start_server(addr, port, docroot, index_page, plugin_path, ssl);
            return 0;
        }

        workers[i] = pid;
    }

    ev_signal_init(&signal_watcher, signal_cb, SIGINT);
    signal_watcher.data = workers;
    ev_signal_start(loop, &signal_watcher);

    ev_run(loop, 0);

    ev_loop_destroy(loop);

    return 0;
}
