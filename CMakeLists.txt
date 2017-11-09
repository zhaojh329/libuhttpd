cmake_minimum_required(VERSION 2.8)

project(libuhttp C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

#set(CMAKE_VERBOSE_MAKEFILE ON)
#add_definitions(--DUH_DEBUG)

add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE)

include_directories(${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)

add_subdirectory(src)
add_subdirectory(example)
