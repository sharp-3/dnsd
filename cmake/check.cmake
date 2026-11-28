find_program(CLANG_QUERY_EXECUTABLE NAMES clang-query clang-query-21)

if(NOT CLANG_QUERY_EXECUTABLE)
    message(WARNING "clang-query not found; add_null_check() will not create any targets")
endif()

# add_null_check(<name> <sources>...): a target that fails when a source checks a pointer
# against NULL implicitly (see cmake/null-check.query). Needs compile_commands.json.
function(add_null_check name)
    if(NOT CLANG_QUERY_EXECUTABLE)
        return()
    endif()

    add_custom_target(${name}
        COMMAND ${CMAKE_COMMAND}
            -DCLANG_QUERY=${CLANG_QUERY_EXECUTABLE}
            -DBUILD_DIR=${CMAKE_BINARY_DIR}
            -DQUERY=${CMAKE_SOURCE_DIR}/cmake/null-check.query
            "-DSOURCES=${ARGN}"
            -P ${CMAKE_SOURCE_DIR}/cmake/null-check.cmake
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Checking for implicit NULL checks (${name})"
        VERBATIM)
endfunction()
