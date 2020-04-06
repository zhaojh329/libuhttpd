include_directories(${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/buffer ${CMAKE_BINARY_DIR}/src ${LIBEV_INCLUDE_DIR})

add_executable(example example.c)

if(BUILD_SHARED_LIBS)
    target_link_libraries(example uhttpd ${LIBEV_LIBRARY})
else()
    target_link_libraries(example uhttpd_s ${LIBEV_LIBRARY})
endif()
