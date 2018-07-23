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

#include "log.h"
#include "uhttpd.h"
#include "uhttpd-lua.h"

static void *uh_create_userdata(lua_State *L, size_t size, const luaL_Reg *reg, lua_CFunction gc)
{
    void *obj = lua_newuserdata(L, size);

    memset(obj, 0, size);

    luaL_newmetatable(L, LUA_UH_SERVER_MT);

    /* metatable.__index = metatable */
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, gc);
    lua_setfield(L, -2, "__gc");

    luaL_setfuncs(L, reg, 0);

    lua_setmetatable(L, -2);

    return obj;
}

static int lua_on_request(struct uh_client *cl)
{
    struct lua_uh_server *lsrv = container_of(cl->srv, struct lua_uh_server, srv);
    const char *path = cl->get_path(cl);
    lua_State *L = cl->srv->L;

    lua_getglobal(L, "__uh_on_request");
    lua_rawgeti(L, -1, lsrv->request_ref);
    lua_remove(L, -2);

    lua_pushlightuserdata(L, cl);
    lua_pushstring(L, path);

    lua_call(L, 2, 1);

    return lua_tointeger(L, -1);
}

static int lua_uh_ssl_init(lua_State *L)
{
#if (!UHTTPD_SSL_SUPPORT)
    lua_pushstring(L, "SSL is not compiled in");
    lua_error(L);
#else
    struct lua_uh_server *lsrv = luaL_checkudata(L, 1, LUA_UH_SERVER_MT);
    const char *cert = luaL_checkstring(L, 2);
    const char *key = luaL_checkstring(L, 3);

    if (lsrv->srv.ssl_init(&lsrv->srv, key, cert) < 0)
        luaL_error(L, "SSL init failed");
#endif

    return 0;
}

static void lua_on_error404(struct uh_client *cl)
{
    struct lua_uh_server *lsrv = container_of(cl->srv, struct lua_uh_server, srv);
    const char *path = cl->get_path(cl);
    lua_State *L = cl->srv->L;

    lua_getglobal(L, "__uh_on_error404");
    lua_rawgeti(L, -1, lsrv->error404_ref);
    lua_remove(L, -2);

    lua_pushlightuserdata(L, cl);
    lua_pushstring(L, path);

    lua_call(L, 2, 0);
}

static int lua_uh_set_options(lua_State *L)
{
    struct lua_uh_server *lsrv = luaL_checkudata(L, 1, LUA_UH_SERVER_MT);
    struct uh_server *srv = &lsrv->srv;

    luaL_checktype(L, 2, LUA_TTABLE);

    lua_getfield(L, 2, "docroot");
    if (lua_tostring(L, -1))
        srv->set_docroot(srv, lua_tostring(L, -1));
    lua_pop(L, 1);

    lua_getfield(L, 2, "index");
    if (lua_tostring(L, -1))
        srv->set_index_file(srv, lua_tostring(L, -1));
    lua_pop(L, 1);

    lua_getfield(L, 2, "on_error404");
    if (!lua_isnil(L, -1)) {
        luaL_checktype(L, -1, LUA_TFUNCTION);
        lua_getglobal(L, "__uh_on_error404");
        lua_pushvalue(L, -2);
        lsrv->error404_ref = luaL_ref(L, -2);
        lsrv->srv.on_error404 = lua_on_error404;
        lua_pop(L, 1);
    }

    lua_getfield(L, 2, "on_request");
    if (!lua_isnil(L, -1)) {
        luaL_checktype(L, -1, LUA_TFUNCTION);
        lua_getglobal(L, "__uh_on_request");
        lua_pushvalue(L, -2);
        lsrv->request_ref = luaL_ref(L, -2);
        lsrv->srv.on_request = lua_on_request;
        lua_pop(L, 1);
    }

    return 0;
}

static int lua_uh_server_free(lua_State *L)
{
    struct lua_uh_server *lsrv = luaL_checkudata(L, 1, LUA_UH_SERVER_MT);

    lsrv->srv.free(&lsrv->srv);

    return 0;
}

static const luaL_Reg server_mt[] = {
    { "ssl_init", lua_uh_ssl_init },
    { "set_options", lua_uh_set_options },
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

static int lua_uh_send_error(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    int code = lua_tointeger(L, 2);
    const char *summary = lua_tostring(L, 3);
    const char *msg = lua_tostring(L, 4);

    cl->send_error(cl, code, summary, msg);

    return 0;
}

static int lua_uh_redirect(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    int code = lua_tointeger(L, 2);
    const char *url = lua_tostring(L, 3);

    cl->redirect(cl, code, url);

    return 0;
}

static int lua_uh_request_done(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);

    cl->request_done(cl);

    return 0;
}

static int lua_uh_get_http_method(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);

    lua_pushinteger(L, cl->request.method);

    return 1;
}

static int lua_uh_get_http_version(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);

    lua_pushinteger(L, cl->request.version);

    return 1;
}

static int lua_uh_get_remote_addr(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *addr = cl->get_peer_addr(cl);

    if (addr)
        lua_pushstring(L, addr);
    else
        lua_pushnil(L);

    return 1;
}

static int lua_uh_get_header(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *name = lua_tostring(L, 2);
    const char *value;

    if (name) {
        value = cl->get_header(cl, name);
        if (value)
            lua_pushstring(L, value);
        else
            lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);

    kvlist_for_each(&cl->request.header, name, value) {
        lua_pushstring(L, value);
        lua_setfield(L, -2, name);
    }

    return 1;
}

static int lua_uh_get_var(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *name = lua_tostring(L, 2);
    const char *value;

    if (name) {
        value = cl->get_var(cl, name);
        if (value)
            lua_pushstring(L, value);
        else
            lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);

    kvlist_for_each(&cl->request.var, name, value) {
        lua_pushstring(L, value);
        lua_setfield(L, -2, name);
    }

    return 1;
}

static int lua_uh_get_query(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *query = cl->get_query(cl);

    if (query)
        lua_pushstring(L, query);
    else
        lua_pushnil(L);

    return 1;
}

static int lua_uh_get_url(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *url = cl->get_url(cl);

    if (url)
        lua_pushstring(L, url);
    else
        lua_pushnil(L);

    return 1;
}

static int lua_uh_get_body(lua_State *L)
{
    struct uh_client *cl = lua_touserdata(L, 1);
    const char *body;
    int len;

    body = cl->get_body(cl, &len);
    if (body)
        lua_pushlstring(L, body, len);
    else
        lua_pushnil(L);

    return 1;
}

static int lua_uh_log(lua_State *L)
{
    int priority = lua_tointeger(L, 1);
    const char *msg = lua_tostring(L, 2);

    luaL_where(L, 1);

    ulog(priority, "%s%s\n", lua_tostring(L, -1), msg);

    return 0;
}

static int lua_uh_set_log_threshold(lua_State *L)
{
    ulog_threshold(lua_tointeger(L, 1));

    return 0;
}

static const luaL_Reg uhttpd_fun[] = {
    {"new", lua_uh_new},
    {"send_header", lua_uh_send_header},
    {"append_header", lua_uh_append_header},
    {"header_end", lua_uh_header_end},
    {"send", lua_uh_send},
    {"chunk_send", lua_uh_chunk_send},
    {"send_error", lua_uh_send_error},
    {"redirect", lua_uh_redirect},
    {"request_done", lua_uh_request_done},
    {"get_http_method", lua_uh_get_http_method},
    {"get_http_version", lua_uh_get_http_version},
    {"get_remote_addr", lua_uh_get_remote_addr},
    {"get_header", lua_uh_get_header},
    {"get_var", lua_uh_get_var},
    {"get_query", lua_uh_get_query},
    {"get_url", lua_uh_get_url},
    {"get_body", lua_uh_get_body},
    {"log", lua_uh_log},
    {"set_log_threshold", lua_uh_set_log_threshold},
    {NULL, NULL}
};

int luaopen_uhttpd(lua_State *L)
{
    lua_newtable(L);
    lua_setglobal(L, "__uh_on_request");

    lua_newtable(L);
    lua_setglobal(L, "__uh_on_error404");

    lua_newtable(L);
    luaL_setfuncs(L, uhttpd_fun, 0);

    lua_pushstring(L, UHTTPD_VERSION_STRING);
    lua_setfield(L, -2, "VERSION");

#if (UHTTPD_SSL_SUPPORT)
    lua_pushboolean(L, 1);
#else
    lua_pushboolean(L, 0);
#endif
    lua_setfield(L, -2, "SSL_SUPPORTED");

    lua_pushinteger(L, LOG_DEBUG);
    lua_setfield(L, -2, "LOG_DEBUG");

    lua_pushinteger(L, LOG_INFO);
    lua_setfield(L, -2, "LOG_INFO");

    lua_pushinteger(L, LOG_ERR);
    lua_setfield(L, -2, "LOG_ERR");

    lua_pushinteger(L, UH_REQUEST_DONE);
    lua_setfield(L, -2, "REQUEST_DONE");

    lua_pushinteger(L, UH_REQUEST_CONTINUE);
    lua_setfield(L, -2, "REQUEST_CONTINUE");

    lua_pushinteger(L, UH_HTTP_VER_09);
    lua_setfield(L, -2, "HTTP_VER_09");

    lua_pushinteger(L, UH_HTTP_VER_10);
    lua_setfield(L, -2, "HTTP_VER_10");

    lua_pushinteger(L, UH_HTTP_VER_11);
    lua_setfield(L, -2, "HTTP_VER_11");

    lua_pushinteger(L, UH_HTTP_METHOD_GET);
    lua_setfield(L, -2, "HTTP_METHOD_GET");

    lua_pushinteger(L, UH_HTTP_METHOD_POST);
    lua_setfield(L, -2, "HTTP_METHOD_POST");

    lua_pushinteger(L, UH_HTTP_METHOD_HEAD);
    lua_setfield(L, -2, "HTTP_METHOD_HEAD");

    return 1;
}
