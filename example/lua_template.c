#include <ev.h>
#include <stdio.h>
#include <uhttp.h>

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    printf("Got signal: %d\n", w->signum);
    ev_break(loop, EVBREAK_ALL);
}

static void lua_template(struct uh_connection *con)
{
    uh_template(con);
}

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    ev_signal *sig_watcher = NULL;
    struct uh_server *srv = NULL;

    uh_log_info("libuhttp version: %s", uh_version());

    sig_watcher = calloc(1, sizeof(ev_signal));
    if (!sig_watcher)
        return -1;
    
    ev_signal_init(sig_watcher, signal_cb, SIGINT);
    ev_signal_start(loop, sig_watcher);

    srv = uh_server_new(loop, "0.0.0.0", 8000);
    if (!srv) {
        uh_log_err("uh_server_new failed");
        goto err;
    }

#if (UHTTP_SSL_ENABLED)
    if (uh_ssl_init(srv, "server-cert.pem", "server-key.pem") < 0)
        goto err;
#endif

    uh_register_default_hook(srv, lua_template);
    
    uh_log_info("Listen on 8000...");
    
    ev_run(loop, 0);
    
err:
    free(sig_watcher);
    uh_server_free(srv);
    
    return 0;
}



