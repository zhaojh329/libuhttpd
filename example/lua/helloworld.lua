#!/usr/bin/env lua

--[[
  Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
  USA
 --]]

local uloop = require "uloop"
local uh = require "uhttpd"

local verbose = true
local port = 8914

-- LOG_DEBUG LOG_INFO LOG_ERR
if not verbose then
    uh.set_log_threshold(uh.LOG_ERR)
end

uloop.init()

uh.log(uh.LOG_INFO, "uhttpd version:" .. uh.VERSION)

local srv = uh.new(port)

-- srv:set_options({docroot = "/home/zjh/www", index = "lua.html"})
-- srv:ssl_init("uhttpd.crt", "uhttpd.key")

uh.log(uh.LOG_INFO, "Listen on:" .. port)

srv:set_error404_cb(function(cl, path)
    uh.send_header(cl, 200, "OK", -1)
    uh.header_end(cl)

    uh.chunk_send(cl, string.format("<h1>Libuhttpd-Lua: '%s' Not found</h1>", path))

    uh.request_done(cl)
end)

local http_methods = {
    [uh.HTTP_METHOD_GET] = "GET",
    [uh.HTTP_METHOD_POST] = "POST",
    [uh.HTTP_METHOD_HEAD] = "HEAD"
}
local http_version = {
    [uh.HTTP_VER_09] = "HTTP/0.9",
    [uh.HTTP_VER_10] = "HTTP/1.0",
    [uh.HTTP_VER_11] = "HTTP/1.1"
}

srv:set_request_cb(function(cl, path)
    if path ~= "/hello" then
        return uh.REQUEST_CONTINUE
    end

    uh.send_header(cl, 200, "OK", -1)
    uh.append_header(cl, "Myheader", "Hello")
    uh.header_end(cl)

    uh.chunk_send(cl, string.format("<h1>Hello Libuhttpd %s</h1>", uh.VERSION))
    uh.chunk_send(cl, string.format("<h1>REMOTE_ADDR: %s</h1>", uh.get_remote_addr(cl)))
    uh.chunk_send(cl, string.format("<h1>METHOD: %s</h1>", http_methods[uh.get_http_method(cl)]))
    uh.chunk_send(cl, string.format("<h1>HTTP Version: %s</h1>", http_version[uh.get_http_version(cl)]))
    uh.chunk_send(cl, string.format("<h1>URL: %s</h1>", uh.get_url(cl)))
    uh.chunk_send(cl, string.format("<h1>QUERY: %s</h1>", uh.get_query(cl) or ""))
    uh.chunk_send(cl, string.format("<h1>Body: %s</h1>", uh.get_body(cl) or ""))

    -- Get a http var
    local var_x = uh.get_var(cl, "x")
    uh.chunk_send(cl, string.format("<h1>Var x: %s</h1>", var_x or ""))

    -- Get a http header
    local user_agent = uh.get_header(cl, "user-agent")
    uh.chunk_send(cl, string.format("<h1>User-Agent: %s</h1>", user_agent))

    uh.chunk_send(cl, "<hr />")
    -- Get all http vars
    local vars = uh.get_var(cl)
    for k, v in pairs(vars) do
        uh.chunk_send(cl, string.format("<h1>%s: %s</h1>", k, v))
    end

    uh.chunk_send(cl, "<hr />")
    -- Get all http headers
    local headers = uh.get_header(cl)
    for k, v in pairs(headers) do
        uh.chunk_send(cl, string.format("<h1>%s: %s</h1>", k, v))
    end

    uh.request_done(cl)

    return uh.REQUEST_DONE
end)

uloop.run()
