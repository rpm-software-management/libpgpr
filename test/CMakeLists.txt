ADD_EXECUTABLE (testpgpr testpgpr.c)
TARGET_LINK_LIBRARIES (testpgpr libpgpr)

ADD_EXECUTABLE (runtest runtest.c)

FILE(GLOB tests "${CMAKE_CURRENT_SOURCE_DIR}/[_a-zA-Z0-9]*/[_a-zA-Z0-9]*.t")

FOREACH(test ${tests})
    FILE(RELATIVE_PATH myname "${CMAKE_CURRENT_SOURCE_DIR}/" ${test})
    CMAKE_PATH(GET myname FILENAME myname_test)
    CMAKE_PATH(GET myname PARENT_PATH myname_dir)
    FILE(TO_NATIVE_PATH "${CMAKE_BINARY_DIR}/test/runtest" RUNTEST_BINARY)
    STRING(REPLACE \\ \\\\ RUNTEST_BINARY ${RUNTEST_BINARY})
    ADD_TEST(NAME ${myname} COMMAND "${RUNTEST_BINARY}" "${myname_test}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${myname_dir})
ENDFOREACH ()




