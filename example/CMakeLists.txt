include_directories(${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)

add_executable(helloworld helloworld.c)
target_link_libraries(helloworld uhttpd ${LIBUBOX_LIBRARY})

add_executable(template template.c)
target_link_libraries(template uhttpd ${LIBUBOX_LIBRARY})
