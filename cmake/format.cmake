find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format)

if(NOT CLANG_FORMAT_EXECUTABLE)
    message(WARNING "clang-format not found; add_format() will not create any targets")
endif()

function(add_format name)
    if(NOT CLANG_FORMAT_EXECUTABLE)
        return()
    endif()

    cmake_parse_arguments(ARG "EXCLUDE_FROM_ALL" "" "" ${ARGN})

    set(all ALL)
    if(ARG_EXCLUDE_FROM_ALL)
        set(all "")
    endif()

    set(sources "")
    foreach(src IN LISTS ARG_UNPARSED_ARGUMENTS)
        get_filename_component(abs "${src}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
        list(APPEND sources "${abs}")
    endforeach()

    if(NOT sources)
        add_custom_target(${name} ${all})
        return()
    endif()

    add_custom_target(${name} ${all}
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i --style=file ${sources}
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Formatting sources with clang-format (${name})"
        VERBATIM)
endfunction()
