cmake_minimum_required(VERSION 2.8)

project(libuhttpd C)

INCLUDE(CheckLibraryExists)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

add_subdirectory(src)
add_subdirectory(example)

