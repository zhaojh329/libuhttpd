/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#ifndef _UHTTPD_H
#define _UHTTPD_H

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

#if (UHTTPD_SSL_SUPPORT)
    int (*ssl_init)(struct uh_server *srv, const char *key, const char *crt);
#endif    
};

struct uh_server *uh_server_new(const char *host, const char *port);

#endif
