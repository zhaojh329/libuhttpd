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
 
#ifndef _UHTTPD_H
#define _UHTTPD_H

#include "config.h"
#include "client.h"
#include "action.h"

struct uh_server {
    bool ssl;
    struct uloop_fd fd;
    char *docroot;
    char *index_file;
    int nclients;
    struct avl_tree actions;
    struct list_head clients;

    void (*free)(struct uh_server *srv);
    void (*set_docroot)(struct uh_server *srv, const char *docroot);
    void (*set_index_file)(struct uh_server *srv, const char *index_file);
    void (*error404_cb)(struct uh_client *cl);
    int (*add_action)(struct uh_server *srv, const char *path, action_cb_t cb);

#if (UHTTPD_SSL_SUPPORT)
    int (*ssl_init)(struct uh_server *srv, const char *key, const char *crt);
#endif
#if (UHTTPD_LUA_SUPPORT)
    void *L;
#endif
};

struct uh_server *uh_server_new(const char *host, int port);

#if (UHTTPD_LUA_SUPPORT)
    void uh_template(struct uh_client *cl);
#endif

#endif
