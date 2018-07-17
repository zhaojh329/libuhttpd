include_directories(${CMAKE_SOURCE_DIR}/src)

add_library(uhttpd-lua MODULE uhttpd-lua.c)
set_target_properties(uhttpd-lua PROPERTIES OUTPUT_NAME uhttpd PREFIX "")
    
target_link_libraries(uhttpd-lua uhttpd util)

install(TARGETS uhttpd-lua
    LIBRARY DESTINATION lib/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}
)