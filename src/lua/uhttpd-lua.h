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
 
#ifndef _UHTTPD_LUA_H
#define _UHTTPD_LUA_H

#include <lauxlib.h>
#include <lualib.h>

/* Compatibility defines */		
#if LUA_VERSION_NUM <= 501
		
#define lua_setuservalue(L, i) lua_setfenv((L), (i))		
#define lua_getuservalue(L, i) lua_getfenv((L), (i))

/* NOTE: this only works if nups == 0! */
#define luaL_setfuncs(L, fns, nups) luaL_register((L), NULL, (fns))

#define lua_rawlen(L, i) lua_objlen((L), (i))

#endif

struct lua_uh_server {
	struct uh_server *srv;
};

#endif
