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

#ifndef _ACTION_H
#define _ACTION_H

#include "client.h"

typedef void (*action_cb_t)(struct uh_client *cl);

struct uh_action {
    struct avl_node avl;
    action_cb_t cb;
    char path[0];
};

int uh_add_action(struct uh_server *srv, const char *path, action_cb_t cb);

bool handle_action_request(struct uh_client *cl, const char *path);

void uh_action_free(struct uh_server *srv);

#endif
