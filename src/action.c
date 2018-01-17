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

#include <stdlib.h>

#include "action.h"
#include "uhttpd.h"
#include "log.h"

#define UH_ACTION_DATA_BUF_SIZE   1024
#define UH_ACTION_MAX_POST_SIZE   4096

int uh_add_action(struct uh_server *srv, const char *path, action_cb_t cb)
{
    struct uh_action *a;

    a = calloc(1, sizeof(struct uh_action) + strlen(path) + 1);
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

static int action_data_send(struct uh_client *cl, const char *data, int len)
{
    struct dispatch *d = &cl->dispatch;
    d->action.post_len += len;

    if (d->action.post_len > UH_ACTION_MAX_POST_SIZE)
        goto err;

    if (d->action.post_len > UH_ACTION_DATA_BUF_SIZE) {
        d->action.body = realloc(d->action.body, UH_ACTION_MAX_POST_SIZE);
        if (!d->action.body) {
            cl->send_error(cl, 500, "Internal Server Error", "No memory");
            return 0;
        }
    }

    memcpy(d->action.body, data, len);
    return len;
err:
    cl->send_error(cl, 413, "Request Entity Too Large", NULL);
    return 0;
}

static void action_data_done(struct uh_client *cl)
{
    struct uh_action *a = cl->dispatch.action.a;
    a->cb(cl);
}

static void action_data_free(struct uh_client *cl)
{
    struct dispatch *d = &cl->dispatch;
    free(d->action.body);
}

bool handle_action_request(struct uh_client *cl, const char *path)
{
    struct dispatch *d = &cl->dispatch;
    struct uh_action *a;

    a = avl_find_element(&cl->srv->actions, path, a, avl);
    if (a) {
        switch (cl->request.method) {
        case UH_HTTP_MSG_POST:
            d->action.a = a;
            d->data_send = action_data_send;
            d->data_done = action_data_done;
            d->free = action_data_free;
            d->action.body = calloc(1, UH_ACTION_DATA_BUF_SIZE);
            if (!d->action.body)
                cl->send_error(cl, 500, "Internal Server Error", "No memory");
            break;

        case UH_HTTP_MSG_GET:
            a->cb(cl);
            break;

        default:
            cl->send_error(cl, 400, "Bad Request", "Invalid Request");
            break;
        }
    }

    return a ? true : false;
}


void uh_action_free(struct uh_server *srv)
{
    struct uh_action *node, *tmp;

    avl_remove_all_elements(&srv->actions, node, avl, tmp)
        free(node);
}
