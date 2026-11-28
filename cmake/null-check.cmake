# Run by the check-null target: cmake -DCLANG_QUERY=... -DBUILD_DIR=... -DQUERY=... -DSOURCES=... -P
execute_process(
    COMMAND "${CLANG_QUERY}" -p "${BUILD_DIR}" -f "${QUERY}" ${SOURCES}
    OUTPUT_VARIABLE out
    ERROR_VARIABLE  err
    RESULT_VARIABLE rc)

if(NOT rc EQUAL 0)
    message(FATAL_ERROR "clang-query failed (${rc}):\n${err}")
endif()

string(REGEX MATCHALL "[^\n]*: note: \"pointer\" binds here" hits "${out}")
if(hits)
    list(REMOVE_DUPLICATES hits)
    list(LENGTH hits n)
    string(REPLACE ";" "\n" hits "${hits}")
    string(REPLACE ": note: \"pointer\" binds here" ": compare with NULL explicitly" hits "${hits}")
    message(FATAL_ERROR "${n} implicit NULL check(s):\n${hits}")
endif()
message(STATUS "check-null: no implicit NULL checks")
