# - Try to find http-parser
# Once done this will define
#  HTTPPARSER_FOUND        - System has http-parser
#  HTTPPARSER_INCLUDE_DIRS - The http-parser include directories
#  HTTPPARSER_LIBRARIES    - The libraries needed to use http-parser

find_path(HTTPPARSER_INCLUDE_DIR
  NAMES http_parser.h
)
find_library(HTTPPARSER_LIBRARY
  NAMES http_parser
)

if(HTTPPARSER_INCLUDE_DIR)
  file(STRINGS "${HTTPPARSER_INCLUDE_DIR}/http_parser.h"
    HTTP_PARSER_VERSION_MAJOR REGEX "^#define[ \t]+HTTP_PARSER_VERSION_MAJOR[ \t]+[0-9]+")
  file(STRINGS "${HTTPPARSER_INCLUDE_DIR}/http_parser.h"
    HTTP_PARSER_VERSION_MINOR REGEX "^#define[ \t]+HTTP_PARSER_VERSION_MINOR[ \t]+[0-9]+")
  string(REGEX REPLACE "[^0-9]+" "" HTTP_PARSER_VERSION_MAJOR "${HTTP_PARSER_VERSION_MAJOR}")
  string(REGEX REPLACE "[^0-9]+" "" HTTP_PARSER_VERSION_MINOR "${HTTP_PARSER_VERSION_MINOR}")
  set(HTTP_PARSER_VERSION "${HTTP_PARSER_VERSION_MAJOR}.${HTTP_PARSER_VERSION_MINOR}")
  unset(HTTP_PARSER_VERSION_MINOR)
  unset(HTTP_PARSER_VERSION_MAJOR)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set HTTPPARSER_FOUND to TRUE
# if all listed variables are TRUE and the requested version matches.
find_package_handle_standard_args(HttpParser REQUIRED_VARS
                                  HTTPPARSER_LIBRARY HTTPPARSER_INCLUDE_DIR
                                  VERSION_VAR HTTP_PARSER_VERSION)

if(HTTPPARSER_FOUND)
  set(HTTPPARSER_LIBRARIES     ${HTTPPARSER_LIBRARY})
  set(HTTPPARSER_INCLUDE_DIRS  ${HTTPPARSER_INCLUDE_DIR})
endif()

mark_as_advanced(HTTPPARSER_INCLUDE_DIR HTTPPARSER_LIBRARY)