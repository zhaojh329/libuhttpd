/*
 * The Action handler is a simple libuhttpd handler that processes requests
 * by invoking registered C functions. The action handler is ideal for
 * situations when you want to generate a simple response using C code. 
 *
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

#include "action.h"
#include "uhttpd.h"

int uh_add_action(struct uh_server *srv, const char *path, action_cb_t cb)
{
    struct uh_action *a;

    a = calloc(1, sizeof(struct uh_action));
    if (!a) {
        uh_log_err("calloc");
        return -1;
    }

    if (strlen(path) > sizeof(a->path) - 1) {
        uh_log_err("The given path is too long");
        goto err;
    }

    a->avl.key = strcpy(a->path, path);
    a->cb = cb;
    avl_insert(&srv->actions, &a->avl);

    return 0;
    
err:
    free(a);
    return -1;
}

bool handle_action_request(struct uh_client *cl, const char *path)
{
    struct uh_action *a;

    a = avl_find_element(&cl->srv->actions, path, a, avl);
    if (a) {
        a->cb(cl);
        return true;
    }
    return false;
}


void uh_action_free(struct uh_server *srv)
{
    struct uh_action *node, *tmp;

    avl_remove_all_elements(&srv->actions, node, avl, tmp)
        free(node);
}
