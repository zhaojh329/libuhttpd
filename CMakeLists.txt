cmake_minimum_required(VERSION 2.8)

project(libuhttpd C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

#set(CMAKE_VERBOSE_MAKEFILE ON)

add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/src/include
	${CMAKE_CURRENT_SOURCE_DIR}/src/include/uhttpd
	${CMAKE_CURRENT_BINARY_DIR}/src/include
)

add_subdirectory(src)
add_subdirectory(example)
