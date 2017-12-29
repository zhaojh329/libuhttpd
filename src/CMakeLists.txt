# The version number.
set(UHTTPD_VERSION_MAJOR 0)
set(UHTTPD_VERSION_MINOR 3)
set(UHTTPD_VERSION_PATCH 0)

# Check the third party Libraries
find_package(Libev REQUIRED)
find_package(OpenSSL)
find_package(CyaSSL)
find_package(Lua)

include_directories(${LIBEV_INCLUDE_DIR} ${LUA_INCLUDE_DIR})
set(EXTRA_LIBS ${LIBEV_LIBRARIES} ${LUA_LIBRARIES})
set(SOURCE_FILES uhttpd.c log.c buf.c ssl.c parser.c template.c)

set(UHTTPD_DEBUG_CONFIG 0)
option(UHTTPD_DEBUG "Turn on debug" OFF)
if(UHTTPD_DEBUG)
    set(UHTTPD_DEBUG_CONFIG 1)
endif()

option(UHTTPD_DISABLE_SSL "Disable ssl support" OFF)
option(UHTTPD_USE_OPENSSL "Explicit use OpenSSL as SSL backend" OFF)
option(UHTTPD_USE_CYASSL "Explicit use CyaSSL as SSL backend" OFF)

set(UHTTPD_SSL_ENABLED OFF)
set(UHTTPD_SSL_ENABLED_CONFIG 0)
set(UHTTPD_USE_OPENSSL_CONFIG 0)
set(UHTTPD_USE_CYASSL_CONFIG 0)

if(NOT UHTTPD_DISABLE_SSL)
    if(UHTTPD_USE_OPENSSL)
        if(NOT OPENSSL_FOUND)
            message(FATAL_ERROR "Could NOT find OpenSSL")
        endif()

        set(UHTTPD_SSL_ENABLED ON)
        set(UHTTPD_SSL_ENABLED_CONFIG 1)
        set(UHTTPD_USE_OPENSSL_CONFIG 1)

        list(APPEND EXTRA_LIBS ${OPENSSL_LIBRARIES})
        include_directories(${OPENSSL_INCLUDE_DIR})
    elseif(UHTTPD_USE_CYASSL)
        if (NOT CYASSL_FOUND)
            message(FATAL_ERROR "Could NOT find CyaSSL")
        endif()

        set(UHTTPD_SSL_ENABLED ON)
        set(UHTTPD_SSL_ENABLED_CONFIG 1)
        set(UHTTPD_USE_CYASSL_CONFIG 1)

        list(APPEND EXTRA_LIBS ${CYASSL_LIBRARIES})
        include_directories(${CYASSL_INCLUDE_DIR})
    endif()

    if(NOT UHTTPD_SSL_ENABLED)
        if(OPENSSL_FOUND)
            set(UHTTPD_SSL_ENABLED ON)
            set(UHTTPD_SSL_ENABLED_CONFIG 1)
            set(UHTTPD_USE_OPENSSL_CONFIG 1)

            list(APPEND EXTRA_LIBS ${OPENSSL_LIBRARIES})
            include_directories(${OPENSSL_INCLUDE_DIR})
        elseif(CYASSL_FOUND)
            set(UHTTPD_SSL_ENABLED ON)
            set(UHTTPD_SSL_ENABLED_CONFIG 1)
            set(UHTTPD_USE_CYASSL_CONFIG 1)

            list(APPEND EXTRA_LIBS ${CYASSL_LIBRARIES})
            include_directories(${CYASSL_INCLUDE_DIR})
        endif()
    endif()
endif()

add_library(uhttpd SHARED ${SOURCE_FILES})
set_target_properties(uhttpd PROPERTIES VERSION ${UHTTPD_VERSION_MAJOR}.${UHTTPD_VERSION_MINOR}.${UHTTPD_VERSION_PATCH})
target_link_libraries(uhttpd ${EXTRA_LIBS})

# configure a header file to pass some of the CMake settings to the source code
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/uhttpd/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/uhttpd/config.h)

install(
    FILES
	    ${CMAKE_CURRENT_BINARY_DIR}/include/uhttpd/config.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/include/uhttpd/uhttpd.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/include/uhttpd/log.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/include/uhttpd/buf.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/uhttpd/str.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/include/uhttpd/parser.h
    DESTINATION
    	include/uhttpd
)

install(
    FILES
	    ${CMAKE_CURRENT_SOURCE_DIR}/include/uhttpd.h
    DESTINATION
    	include
)

install(
    TARGETS uhttpd LIBRARY
    DESTINATION lib
)

message("")
message(STATUS "UHTTPD_VERSION: ${UHTTPD_VERSION_MAJOR}.${UHTTPD_VERSION_MINOR}.${UHTTPD_VERSION_PATCH}")
if(UHTTPD_USE_OPENSSL_CONFIG)
message(STATUS "UHTTPD_SSL_ENABLED: OpenSSL")
elseif(UHTTPD_USE_CYASSL_CONFIG)
message(STATUS "UHTTPD_SSL_ENABLED: CyaSSL")
else()
message(STATUS "UHTTPD_SSL_ENABLED: None")
endif()
message(STATUS "DEBUG: ${UHTTPD_DEBUG}")
message("")
