/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
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
