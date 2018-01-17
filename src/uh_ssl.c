/*
 *   Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 *   Copyright (C) 2010-2013 Jo-Philipp Wich <xm@subsignal.org>
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <dlfcn.h>
#include <errno.h>

#include "uhttpd.h"
#include "uh_ssl.h"
#include "log.h"

static bool _init = false;
static struct ustream_ssl_ops *ops;
static void *dlh;
static void *ctx;

int uh_ssl_init(struct uh_server *srv, const char *key, const char *crt)
{
    srv->ssl = true;

    if (_init)
        return 0;

    dlh = dlopen("libustream-ssl.so", RTLD_LAZY | RTLD_LOCAL);
    if (!dlh) {
        uh_log_err("Failed to load ustream-ssl library: %s", dlerror());
        return -ENOENT;
    }

    ops = dlsym(dlh, "ustream_ssl_ops");
    if (!ops) {
        uh_log_err("Could not find required symbol 'ustream_ssl_ops' in ustream-ssl library");
        return -ENOENT;
    }

    ctx = ops->context_new(true);
    if (!ctx) {
        uh_log_err("Failed to initialize ustream-ssl");
        return -EINVAL;
    }

    if (ops->context_set_crt_file(ctx, crt) ||
        ops->context_set_key_file(ctx, key)) {
        uh_log_err("Failed to load certificate/key files");
        return -EINVAL;
    }

    _init = true;

    return 0;
}

void uh_ssl_free()
{
    if (_init) {
        _init = false;
        ops->context_free(ctx);
    }
}

static void ssl_ustream_read_cb(struct ustream *s, int bytes)
{
    struct uh_client *cl = container_of(s, struct uh_client, ssl.stream);

    uh_client_read_cb(cl);
}

static void ssl_ustream_write_cb(struct ustream *s, int bytes)
{
    struct uh_client *cl = container_of(s, struct uh_client, ssl.stream);

    if (cl->dispatch.write_cb)
        cl->dispatch.write_cb(cl);
}

static void ssl_notify_state(struct ustream *s)
{
    struct uh_client *cl = container_of(s, struct uh_client, ssl.stream);

    uh_client_notify_state(cl);
}

void uh_ssl_client_attach(struct uh_client *cl)
{
    cl->us = &cl->ssl.stream;
    ops->init(&cl->ssl, &cl->sfd.stream, ctx, true);
    cl->us->notify_read = ssl_ustream_read_cb;
    cl->us->notify_write = ssl_ustream_write_cb;
    cl->us->notify_state = ssl_notify_state;
}

void uh_ssl_client_detach(struct uh_client *cl)
{
    ustream_free(&cl->ssl.stream);
}
