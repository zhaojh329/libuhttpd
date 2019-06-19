
add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE -Wno-misleading-indentation)

# The version number.
set(UHTTPD_VERSION_MAJOR 2)
set(UHTTPD_VERSION_MINOR 2)
set(UHTTPD_VERSION_PATCH 2)

# Check the third party Libraries
find_package(Libubox REQUIRED)
find_package(Lua)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${LIBUBOX_INCLUDE_DIR})

set(EXTRA_LIBS ${LIBUBOX_LIBRARY} dl)
set(SOURCE_FILES uhttpd.c client.c log.c utils.c file.c)

set(UHTTPD_SSL_SUPPORT_CONFIG 1)
option(UHTTPD_SSL_SUPPORT "SSL support" ON)


set(LUA_SUPPORT_DEFAULT "ON")
if (NOT LUA_FOUND)
    set(LUA_SUPPORT_DEFAULT "OFF")
endif (NOT LUA_FOUND)

set(UHTTPD_LUA_SUPPORT_CONFIG 1)
option(UHTTPD_LUA_SUPPORT "LUA support" ${LUA_SUPPORT_DEFAULT})

if (UHTTPD_SSL_SUPPORT)
    list(APPEND SOURCE_FILES uh_ssl.c)
else ()
    set(UHTTPD_SSL_SUPPORT_CONFIG 0)
endif ()

if (UHTTPD_LUA_SUPPORT)
    if (NOT LUA_FOUND)
        message(FATAL_ERROR "Lua was not found on your system")
    endif (NOT LUA_FOUND)

    include_directories(${LUA_INCLUDE_DIR})
    list(APPEND EXTRA_LIBS ${LUA_LIBRARY})

    list(APPEND SOURCE_FILES lua_template.c)

    add_subdirectory(lua)
else ()
    set(UHTTPD_LUA_SUPPORT_CONFIG 0)
endif ()

add_library(uhttpd SHARED ${SOURCE_FILES})
set_target_properties(uhttpd PROPERTIES VERSION ${UHTTPD_VERSION_MAJOR}.${UHTTPD_VERSION_MINOR}.${UHTTPD_VERSION_PATCH})
target_link_libraries(uhttpd ${EXTRA_LIBS})

# configure a header file to pass some of the CMake settings to the source code
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

install(
    FILES
	    ${CMAKE_CURRENT_BINARY_DIR}/config.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/uhttpd.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/client.h
    DESTINATION
    	include/uhttpd
)

install(
    TARGETS uhttpd LIBRARY
    DESTINATION lib
)

message("")
message(STATUS "UHTTPD_VERSION: ${UHTTPD_VERSION_MAJOR}.${UHTTPD_VERSION_MINOR}.${UHTTPD_VERSION_PATCH}")
message(STATUS "UHTTPD_SSL_SUPPORT: ${UHTTPD_SSL_SUPPORT}")
message(STATUS "UHTTPD_LUA_SUPPORT: ${UHTTPD_LUA_SUPPORT}")
message("")
