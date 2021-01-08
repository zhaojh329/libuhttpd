include_directories(
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_SOURCE_DIR}/src/http-parser
	${CMAKE_SOURCE_DIR}/src/buffer
	${CMAKE_BINARY_DIR}/src
	${LIBEV_INCLUDE_DIR})

set(LIBS ${LIBEV_LIBRARY})

if(BUILD_SHARED_LIBS)
	list(APPEND LIBS uhttpd)
else()
	list(APPEND LIBS uhttpd_s)
endif()

add_executable(simple_server simple_server.c handler.c)
target_link_libraries(simple_server ${LIBS})

add_executable(multi_process_server_reuseport multi_process_server_reuseport.c handler.c)
target_link_libraries(multi_process_server_reuseport ${LIBS})

add_executable(multi_process_server multi_process_server.c handler.c)
target_link_libraries(multi_process_server ${LIBS})

if(HAVE_DLOPEN)
	add_library(test_plugin MODULE  test_plugin.c)
	set_target_properties(test_plugin PROPERTIES OUTPUT_NAME test_plugin PREFIX "")

	install(
		TARGETS test_plugin
		LIBRARY DESTINATION lib/uhttpd
	)
endif()