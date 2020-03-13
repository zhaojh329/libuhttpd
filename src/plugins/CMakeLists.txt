option(BUILD_TEST_PLUGIN "Build test plugin" ON)

set(PLUGINS "")

if(BUILD_TEST_PLUGIN)
	set(PLUGINS ${PLUGINS} test_plugin)
	add_library(test_plugin MODULE  test.c)
	set_target_properties(test_plugin PROPERTIES OUTPUT_NAME test PREFIX "")
endif()

install(
    TARGETS ${PLUGINS}
    LIBRARY DESTINATION lib/uhttpd
)
