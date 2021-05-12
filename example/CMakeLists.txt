set(LIBS ${LIBEV_LIBRARY} uhttpd)

if(SSL_SUPPORT)
    list(APPEND LIBS ${SSL_LIBS})
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/http-parser
    ${CMAKE_SOURCE_DIR}/src/buffer
    ${CMAKE_SOURCE_DIR}/src/log
    ${CMAKE_BINARY_DIR}/src
    ${LIBEV_INCLUDE_DIR})

add_executable(simple_server simple_server.c handler.c)
target_link_libraries(simple_server PRIVATE ${LIBS})

add_executable(multi_process_server_reuseport multi_process_server_reuseport.c handler.c)
target_link_libraries(multi_process_server_reuseport PRIVATE ${LIBS})

add_executable(multi_process_server multi_process_server.c handler.c)
target_link_libraries(multi_process_server PRIVATE ${LIBS})

if(HAVE_DLOPEN)
    add_library(test_plugin MODULE test_plugin.c)
    set_target_properties(test_plugin PROPERTIES OUTPUT_NAME test_plugin PREFIX "")

    install(
        TARGETS test_plugin
        DESTINATION lib/uhttpd
    )
endif()
