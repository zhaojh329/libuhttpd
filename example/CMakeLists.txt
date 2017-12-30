cmake_minimum_required(VERSION 2.8)

project(libuhttpd-example C)

#set(CMAKE_VERBOSE_MAKEFILE ON)

list(APPEND CMAKE_MODULE_PATH "../cmake/Modules/")

add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE -Wno-misleading-indentation)

find_package(Libuhttpd REQUIRED)
find_package(Libubox REQUIRED)

include_directories(${LIBUHTTPD_INCLUDE_DIR})

add_executable(helloworld helloworld.c)
target_link_libraries(helloworld ${LIBUHTTPD_LIBRARY} ${LIBUBOX_LIBRARY})
