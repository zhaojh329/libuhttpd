cmake_minimum_required(VERSION 3.0)

project(libuhttpd C)

include(CheckLibraryExists)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

add_definitions(-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64)
add_compile_options(-O -Wall --std=gnu99)

option(BUILD_WERROR "Build with -Werror" ON)

if(BUILD_WERROR)
    add_compile_options(-Werror)
endif()

option(BUILD_STATIC "Build static library" OFF)

option(BUILD_EXAMPLE "Build example" ON)

if(BUILD_STATIC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()

find_package(Libev REQUIRED)

add_subdirectory(src/ssl)

add_subdirectory(src)

if(BUILD_EXAMPLE)
    add_subdirectory(example)
endif()
