# The version number.
set(UHTTP_VERSION_MAJOR 0)
set(UHTTP_VERSION_MINOR 1)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Check the third party Libraries
find_package(Libev REQUIRED)
find_package(HttpParser REQUIRED)
find_package(OpenSSL)
find_package(CyaSSL)

include_directories(${LIBEV_INCLUDE_DIRS} ${HTTPPARSER_INCLUDE_DIRS})
set(EXTRA_LIBS ${LIBEV_LIBRARIES} ${HTTPPARSER_LIBRARIES})
set(SOURCE_FILES uhttp.c uhttp_log.c uhttp_buf.c)

set(UHTTP_FOUND_SSL OFF)

option(UHTTP_DISABLE_SSL "Disable ssl support" OFF)

if(NOT UHTTP_DISABLE_SSL)
	if(OPENSSL_FOUND)
		set(UHTTP_FOUND_SSL ON)
		list(APPEND EXTRA_LIBS ${OPENSSL_LIBRARIES})
		include_directories(${OPENSSL_INCLUDE_DIR})
	elseif(CYASSL_FOUND)
		set(UHTTP_FOUND_SSL ON)
		list(APPEND EXTRA_LIBS ${CYASSL_LIBRARIES})
		include_directories(${CYASSL_INCLUDE_DIR})
	endif()
endif()

if(UHTTP_FOUND_SSL)
	list(APPEND SOURCE_FILES uhttp_ssl.c)
endif()

add_library(uhttp SHARED ${SOURCE_FILES})
set_target_properties(uhttp PROPERTIES VERSION ${UHTTP_VERSION_MAJOR}.${UHTTP_VERSION_MINOR})
target_link_libraries(uhttp ${EXTRA_LIBS})

# configure a header file to pass some of the CMake settings to the source code
configure_file(uhttp_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/uhttp_config.h)

install(
	FILES uhttp.h ${CMAKE_CURRENT_BINARY_DIR}/uhttp_config.h uhttp_log.h uhttp_buf.h
	DESTINATION include
)

install(
	TARGETS uhttp LIBRARY
	DESTINATION lib
)

message("")
message(STATUS "UHTTP_VERSION = ${UHTTP_VERSION_MAJOR}.${UHTTP_VERSION_MINOR}")
message(STATUS "UHTTP_DISABLE_SSL = ${UHTTP_DISABLE_SSL}")
message(STATUS "UHTTP_FOUND_SSL = ${UHTTP_FOUND_SSL}")
message("")