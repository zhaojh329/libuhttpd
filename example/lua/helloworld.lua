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

uloop.init()

-- LOG_DEBUG LOG_INFO LOG_ERR
if not verbose then
    uh.set_log_threshold(uh.LOG_ERR)
end

uh.log(uh.LOG_INFO, "uhttpd version:" .. uh.VERSION)

local srv = uh.new(port)

-- srv:ssl_init("uhttpd.crt", "uhttpd.key")
-- srv:set_options({docroot = "/home/zjh/www", index = "lua.html"})

uh.log(uh.LOG_INFO, "Listen on:" .. port)



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

srv:on_error404(function(cl, path)
    cl:send_header(200, "OK", -1)
    cl:header_end()
    cl:chunk_send(string.format("<h1>Libuhttpd-Lua: '%s' Not found</h1>", path))
    cl:request_done()
end)


srv:on_request(function(cl, path)
    if path ~= "/hello" then
        return uh.REQUEST_CONTINUE
    end

    cl:send_header(200, "OK", -1)
    cl:append_header("Myheader", "Hello")
    cl:header_end()

    cl:chunk_send(string.format("<h1>Hello Libuhttpd %s</h1>", uh.VERSION))
    cl:chunk_send(string.format("<h1>REMOTE_ADDR: %s</h1>", cl:get_remote_addr()))
    cl:chunk_send(string.format("<h1>METHOD: %s</h1>", http_methods[cl:get_http_method()]))
    cl:chunk_send(string.format("<h1>HTTP Version: %s</h1>", http_version[cl:get_http_version()]))
    cl:chunk_send(string.format("<h1>URL: %s</h1>", cl:get_url()))
    cl:chunk_send(string.format("<h1>QUERY: %s</h1>", cl:get_query() or ""))
    cl:chunk_send(string.format("<h1>Body: %s</h1>", cl:get_body() or ""))

    -- Get a http var
    local var_x = cl:get_var("x")
    cl:chunk_send(string.format("<h1>Var x: %s</h1>", var_x or ""))

    -- Get a http header
    local user_agent = cl:get_header("user-agent")
    cl:chunk_send(string.format("<h1>User-Agent: %s</h1>", user_agent))

    cl:chunk_send("<hr />")
    -- Get all http vars
    local vars = cl:get_var()
    for k, v in pairs(vars) do
        cl:chunk_send(string.format("<h1>%s: %s</h1>", k, v))
    end

    cl:chunk_send("<hr />")
    -- Get all http headers
    local headers = cl:get_header()
    for k, v in pairs(headers) do
        cl:chunk_send(string.format("<h1>%s: %s</h1>", k, v))
    end

    cl:request_done()

    return uh.REQUEST_DONE
end)


uloop.run()
