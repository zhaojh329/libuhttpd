/*
 * Copyright (C) 2017  Jianhui Zhao <jianhuizhao329@gmail.com>
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
 
#ifndef _UHTTP_INTERNAL_H
#define _UHTTP_INTERNAL_H

#include <lua.h>

#include "list.h"
#include "uhttp/uhttp.h"

#define UH_BUFFER_SIZE        2048
#define UH_CONNECTION_TIMEOUT 30
#define UH_URI_SIZE_LIMIT     1024
#define UH_HEAD_SIZE_LIMIT    1024
#define UH_BODY_SIZE_LIMIT    (2 * 1024 * 1024)
#define UH_HEADER_NUM_LIMIT   20

#define UH_CON_CLOSE                (1 << 0)
#define UH_CON_SSL_HANDSHAKE_DONE   (1 << 1)    /* SSL hanshake has completed */
#define UH_CON_REUSE                (1 << 2)

#define likely(x)   (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))

#define ev_timer_mode(l,w,after,repeat) do { \
    ev_timer_stop(l, w); \
    ev_timer_init(w, ev_cb(w), after, repeat); \
    ev_timer_start(l, w); \
    } while (0)

struct uh_hook {
    char *path;
    uh_hookfn_t cb;
    struct list_head list;
};

struct uh_server {
    int sock;
#if (UHTTP_SSL_ENABLED) 
    void *ssl_ctx;
#endif
    char *docroot;
    lua_State *L;
    ev_io read_watcher;
    struct ev_loop *loop;
    uh_hookfn_t default_cb;
    struct list_head hooks;
    struct list_head connections;
};

struct uh_header {
    struct uh_str field;
    struct uh_str value;
};

struct uh_request {
    struct uh_str url;
    struct uh_str path;
    struct uh_str query;
    struct uh_str body;
    int header_num;
    struct uh_header header[UH_HEADER_NUM_LIMIT];
};

struct uh_connection {  
    int sock;
#if (UHTTP_SSL_ENABLED) 
    void *ssl;
#endif
    unsigned char flags;
    struct uh_buf read_buf;
    struct uh_buf write_buf;
    ev_child child_watcher;
    ev_io read_watcher_lua;
    ev_io read_watcher;
    ev_io write_watcher;
    ev_timer timer_watcher;
    struct uh_request req;
    http_parser parser;
    struct list_head list;
    struct uh_server *srv;
};

#endif
