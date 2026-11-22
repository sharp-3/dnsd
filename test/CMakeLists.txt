cmake_minimum_required(VERSION 3.21)

project(dnsd_test LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(TEST_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(TEST_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/bin")

file(GLOB TEST_LIB_FILES CONFIGURE_DEPENDS "${TEST_LIB_DIR}/*.c" "${TEST_LIB_DIR}/*.h")
file(GLOB TEST_BINS CONFIGURE_DEPENDS "${TEST_BIN_DIR}/*.c")

add_library(dns_test STATIC ${TEST_LIB_FILES})
target_include_directories(dns_test PUBLIC "${TEST_LIB_DIR}")
target_compile_options(dns_test PUBLIC -Wall -Wextra)

foreach(src IN LISTS TEST_BINS)
    get_filename_component(name "${src}" NAME_WE)
    add_executable(test_${name} "${src}")
    target_link_libraries(test_${name} PRIVATE dns_test)
    set_target_properties(test_${name} PROPERTIES
        OUTPUT_NAME "${name}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
endforeach()
