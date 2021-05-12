# The version number.
set(UHTTPD_VERSION_MAJOR 3)
set(UHTTPD_VERSION_MINOR 11)
set(UHTTPD_VERSION_PATCH 0)

aux_source_directory(. SOURCES)
aux_source_directory(log SOURCES)
aux_source_directory(buffer SOURCES)

list(APPEND SOURCES http-parser/http_parser.c)

if(BUILD_STATIC)
    if(SSL_SUPPORT)
        list(APPEND SOURCES ${SSL_SRC})
    endif()

    add_library(uhttpd STATIC ${SOURCES})

    if(SSL_SUPPORT)
        target_compile_definitions(uhttpd PRIVATE ${SSL_DEFINE})
        target_include_directories(uhttpd PRIVATE ${SSL_INC})
    endif()
else()
    add_library(uhttpd SHARED ${SOURCES})

    check_library_exists(dl dlopen "" HAVE_DLOPEN)

    if(HAVE_DLOPEN)
        target_compile_definitions(uhttpd PRIVATE HAVE_DLOPEN)
        target_link_libraries(uhttpd PRIVATE dl)
    endif()

    if(SSL_SUPPORT)
        target_link_libraries(uhttpd PRIVATE ${SSL_TARGET})
    endif()

    target_link_libraries(uhttpd PRIVATE ${LIBEV_LIBRARY})
    set_target_properties(uhttpd PROPERTIES VERSION ${UHTTPD_VERSION_MAJOR}.${UHTTPD_VERSION_MINOR}.${UHTTPD_VERSION_PATCH})
endif()

target_include_directories(uhttpd PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${LIBEV_INCLUDE_DIR} http-parser buffer log)

install(
    TARGETS uhttpd
    DESTINATION lib
)

# configure a header file to pass some of the CMake settings to the source code
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

install(
    FILES
        uhttpd.h
        log/log.h
        utils.h
        buffer/buffer.h
        http-parser/http_parser.h
        ${CMAKE_CURRENT_BINARY_DIR}/config.h
    DESTINATION include/uhttpd
)

message(STATUS "UHTTPD_VERSION: ${UHTTPD_VERSION_MAJOR}.${UHTTPD_VERSION_MINOR}.${UHTTPD_VERSION_PATCH}")
