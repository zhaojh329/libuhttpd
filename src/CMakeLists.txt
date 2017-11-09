# The version number.
set(UHTTP_VERSION_MAJOR 0)
set(UHTTP_VERSION_MINOR 1)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Check the necessary Libraries
find_package(Libev REQUIRED)
find_package(HttpParser REQUIRED)

include_directories(${LIBEV_INCLUDE_DIRS} ${HTTPPARSER_INCLUDE_DIRS})
set(EXTRA_LIBS ${LIBEV_LIBRARIES} ${HTTPPARSER_LIBRARIES})
set(SOURCE_FILES uhttp.c uhttp_log.c uhttp_buf.c)

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
