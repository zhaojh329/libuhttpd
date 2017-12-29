add_executable(helloworld helloworld.c)
target_link_libraries(helloworld uhttpd)

add_executable(lua_template lua_template.c)
target_link_libraries(lua_template uhttpd)

