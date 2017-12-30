/*
 * The Action handler is a simple libuhttpd handler that processes requests
 * by invoking registered C functions. The action handler is ideal for
 * situations when you want to generate a simple response using C code. 
 *
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

#ifndef _ACTION_H
#define _ACTION_H

#include "client.h"

typedef void (*action_cb_t)(struct uh_client *cl);

struct uh_action {
    struct avl_node avl;
    char path[PATH_MAX];
    action_cb_t cb;
};

int uh_add_action(struct uh_server *srv, const char *path, action_cb_t cb);

bool handle_action_request(struct uh_client *cl, const char *path);

void uh_action_free(struct uh_server *srv);

#endif
