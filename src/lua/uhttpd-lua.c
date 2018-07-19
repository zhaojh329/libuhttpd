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

#include <string.h>

#include "uhttpd.h"
#include "uhttpd-lua.h"

static void *uh_create_userdata(lua_State *L, size_t size, const luaL_Reg *reg, lua_CFunction gc)
{
    void *obj = lua_newuserdata(L, size);

    memset(obj, 0, size);

    /* creare metatable */
    lua_newtable(L);

    /* metatable.__index = metatable */
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, gc);
    lua_setfield(L, -2, "__gc");

    luaL_setfuncs(L, reg, 0);

    lua_setmetatable(L, -2);

    return obj;
}

static inline void add_all_var(struct uh_client *cl, lua_State *L)
{
    const char *name, *value;

    lua_newtable(L);

    kvlist_for_each(&cl->request.var, name, value) {
        lua_pushstring(L, value);
        lua_setfield(L, -2, name);
    }

    lua_setfield(L, -2, "vars");
}

static inline void add_all_header(struct uh_client *cl, lua_State *L)
{
    const char *name, *value;

    lua_newtable(L);

    kvlist_for_each(&cl->request.header, name, value) {
        lua_pushstring(L, value);
        lua_setfield(L, -2, name);
    }

    lua_setfield(L, -2, "headers");
}

static inline void add_body(struct uh_client *cl, lua_State *L)
{
    int len;
    const char *body;

    body = cl->get_body(cl, &len);

    lua_pushlstring(L, body, len);
    lua_setfield(L, -2, "body");
}

static void lua_prepare_action_argument(struct uh_client *cl, lua_State *L)
{
    lua_pushlightuserdata(L, cl);

    lua_newtable(L);

    lua_pushstring(L, cl->get_peer_addr(cl));
    lua_setfield(L, -2, "peer_addr");

    lua_pushstring(L, cl->get_method(cl));
    lua_setfield(L, -2, "method");

    lua_pushstring(L, cl->get_version(cl));
    lua_setfield(L, -2, "version");

    lua_pushstring(L, cl->get_path(cl));
    lua_setfield(L, -2, "path");

    lua_pushstring(L, cl->get_url(cl));
    lua_setfield(L, -2, "url");

    lua_pushstring(L, cl->get_query(cl));
    lua_setfield(L, -2, "query");

    add_body(cl, L);

    add_all_var(cl, L);
    add_all_header(cl, L);
}

static void lua_uh_action(struct uh_client *cl)
{
    struct uh_server *srv = cl->srv;
    lua_State *L = srv->L;

    lua_getglobal(L, "__uh_action_cb");
    lua_getfield(L, -1, cl->get_path(cl));

    lua_prepare_action_argument(cl, L);

    lua_call(L, 2, 0);
}

static int lua_uh_ssl_init(lua_State *L)
{
#if (!UHTTPD_SSL_SUPPORT)
    lua_pushstring(L, "SSL is not compiled in");
    lua_error(L);
#else
    struct lua_uh_server *lsrv = lua_touserdata(L, 1);
    const char *cert = lua_tostring(L, 2);
    const char *key = lua_tostring(L, 3);

    if (lsrv->srv.ssl_init(&lsrv->srv, key, cert) < 0) {
        lua_pushstring(L, "SSL init failed");
        lua_error(L);
    }
#endif

    return 0;
}

static int lua_uh_add_action(lua_State *L)
{
    struct lua_uh_server *lsrv = lua_touserdata(L, 1);
    const char *path = lua_tostring(L, -2);

    if (!path || !path[0] || !lua_isfunction(L, -1)) {
        lua_pushstring(L, "invalid arg list");
        lua_error(L);
        return 0;
    }

    lsrv->srv.add_action(&lsrv->srv, path, lua_uh_action);

    lua_getglobal(L, "__uh_action_cb");
    lua_pushvalue(L, -2);
    lua_setfield(L, -2, path);

    return 0;
}

static void http_callback_404(struct uh_client *cl)
{
    struct lua_uh_server *lsrv = container_of(cl->srv, struct lua_uh_server, srv);
    lua_State *L = cl->srv->L;

    lua_getglobal(L, "__uh_error404_cb");
    lua_rawgeti(L, -1, lsrv->error404_cb_ref);
    lua_remove(L, -2);

    lua_prepare_action_argument(cl, L);

    lua_call(L, 2, 0);
}

static int lua_uh_set_error404_cb(lua_State *L)
{
    struct lua_uh_server *lsrv = lua_touserdata(L, 1);

    if (!lua_isfunction(L, 2)) {
        lua_pushstring(L, "invalid arg list");
        lua_error(L);
        return 0;
    }

    lua_getglobal(L, "__uh_error404_cb");
    lua_pushvalue(L, 2);
    lsrv->error404_cb_ref = luaL_ref(L, -2);

    lsrv->srv.error404_cb = http_callback_404;

    return 0;
}

static int lua_uh_server_free(lua_State *L)
{
    struct lua_uh_server *lsrv = lua_touserdata(L, 1);

    lsrv->srv.free(&lsrv->srv);

    return 0;
}

static const luaL_Reg server_mt[] = {
    { "ssl_init", lua_uh_ssl_init },
    { "add_action", lua_uh_add_action },
    { "set_error404_cb", lua_uh_set_error404_cb },
    { "free", lua_uh_server_free },
    { NULL, NULL }
};

static int lua_uh_new(lua_State *L)
{
    int port = lua_tointeger(L, -1);
    const char *host = lua_tostring(L, -2);
    struct lua_uh_server *lsrv;
    int sock;

    sock = uh_server_open(host, port);
    if (!sock) {
        lua_pushnil(L);
        lua_pushstring(L, "Bind sock failed");
        return 2;
    }

    lsrv = uh_create_userdata(L, sizeof(struct lua_uh_server), server_mt, lua_uh_server_free);

    uh_server_init(&lsrv->srv, sock);
    lsrv->srv.L = L;

    return 1;
}

static int lua_uh_send_header(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    int code = lua_tointeger(L, 2);
    const char *summary = lua_tostring(L, 3);
    int len = lua_tointeger(L, 4);

    cl->send_header(cl, code, summary, len);

    return 0;
}

static int lua_uh_append_header(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *name = lua_tostring(L, 2);
    const char *value = lua_tostring(L, 2);

    cl->append_header(cl, name, value);

    return 0;
}

static int lua_uh_header_end(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);

    cl->header_end(cl);

    return 0;
}

static int lua_uh_send(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *data;
    size_t len;

    data = lua_tolstring(L, 2, &len);
    cl->send(cl, data, len);

    return 0;

}

static int lua_uh_chunk_send(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *data;
    size_t len;

    data = lua_tolstring(L, 2, &len);
    cl->chunk_send(cl, data, len);

    return 0;

}

static int lua_uh_request_done(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);

    cl->request_done(cl);

    return 0;
}

static const luaL_Reg uhttpd_fun[] = {
    {"new", lua_uh_new},
    {"send_header", lua_uh_send_header},
    {"append_header", lua_uh_append_header},
    {"header_end", lua_uh_header_end},
    {"send", lua_uh_send},
    {"chunk_send", lua_uh_chunk_send},
    {"request_done", lua_uh_request_done},
    {NULL, NULL}
};

int luaopen_uhttpd(lua_State *L)
{
    lua_newtable(L);
    lua_setglobal(L, "__uh_action_cb");

    lua_newtable(L);
    lua_setglobal(L, "__uh_error404_cb");

    lua_newtable(L);
    luaL_setfuncs(L, uhttpd_fun, 0);

    lua_pushstring(L, UHTTPD_VERSION_STRING);
    lua_setfield(L, -2, "VERSION");

    return 1;
}
