cmake_minimum_required(VERSION 2.8.12)

project(libuhttpd C)

option(BUILD_EXAMPLE "Build example" ON)

INCLUDE(CheckLibraryExists)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

add_subdirectory(src)
if(BUILD_EXAMPLE)
    add_subdirectory(example)
endif()

