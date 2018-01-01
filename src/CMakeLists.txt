
add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE -Wno-misleading-indentation)

# The version number.
set(UHTTPD_VERSION_MAJOR 1)
set(UHTTPD_VERSION_MINOR 0)
set(UHTTPD_VERSION_PATCH 4)

# Check the third party Libraries
find_package(Libubox REQUIRED)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${LIBUBOX_INCLUDE_DIR})

set(EXTRA_LIBS ${LIBUBOX_LIBRARY} dl)
set(SOURCE_FILES uhttpd.c client.c log.c utils.c file.c action.c)

set(UHTTPD_DEBUG_CONFIG 0)
option(UHTTPD_DEBUG "Turn on debug" OFF)
if(UHTTPD_DEBUG)
    set(UHTTPD_DEBUG_CONFIG 1)
endif()

set(UHTTPD_SSL_SUPPORT_CONFIG 1)
option(UHTTPD_SSL_SUPPORT "SSL support" ON)


if(UHTTPD_SSL_SUPPORT)
    list(APPEND SOURCE_FILES uh_ssl.c)
else()
    set(UHTTPD_SSL_SUPPORT_CONFIG 0)
endif()

add_library(uhttpd SHARED ${SOURCE_FILES})
set_target_properties(uhttpd PROPERTIES VERSION ${UHTTPD_VERSION_MAJOR}.${UHTTPD_VERSION_MINOR}.${UHTTPD_VERSION_PATCH})
target_link_libraries(uhttpd ${EXTRA_LIBS})

# configure a header file to pass some of the CMake settings to the source code
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

install(
    FILES
	    ${CMAKE_CURRENT_BINARY_DIR}/config.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/uhttpd.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/log.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/client.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/common.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/action.h
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
message(STATUS "UHTTPD_DEBUG: ${UHTTPD_DEBUG}")
message("")
