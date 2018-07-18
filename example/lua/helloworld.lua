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

local port = 8914

uloop.init()

print("uhttpd version:", uh.VERSION)

local srv = uh.new(port)

print("Listen on:", port)

srv:add_action("/lua", function(cl, opt)
    uh.send_header(cl, 200, "OK", -1)
    uh.append_header(cl, "Myheader", "Hello")
    uh.header_end(cl)

    uh.chunk_send(cl, string.format("<h1>Hello Libuhttpd %s</h1>", uh.VERSION))
    uh.chunk_send(cl, string.format("<h1>REMOTE_ADDR: %s</h1>", opt.peer_addr))
    uh.chunk_send(cl, string.format("<h1>METHOD: %s</h1>", opt.method))
    uh.chunk_send(cl, string.format("<h1>HTTP Version: %s</h1>", opt.version))
    uh.chunk_send(cl, string.format("<h1>PATH: %s</h1>", opt.path))
    uh.chunk_send(cl, string.format("<h1>URL: %s</h1>", opt.url))
    uh.chunk_send(cl, string.format("<h1>QUERY: %s</h1>", opt.query))
    uh.chunk_send(cl, string.format("<h1>Body: %s</h1>", opt.body and opt.body or ""))

    for k, v in pairs(opt.vars) do
        uh.chunk_send(cl, string.format("<h1>%s: %s</h1>", k, v))
    end

    for k, v in pairs(opt.headers) do
        uh.chunk_send(cl, string.format("<h1>%s: %s</h1>", k, v))
    end

    uh.request_done(cl)
end)

uloop.run()
