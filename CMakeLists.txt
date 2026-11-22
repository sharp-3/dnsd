cmake_minimum_required(VERSION 3.21)

project(dnsd LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(cmake/format.cmake)

set(HEADER_DIR "${CMAKE_SOURCE_DIR}/include")
set(SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "${HEADER_DIR}/*.h")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${SOURCE_DIR}/*.c")

set(LIB_SOURCES ${SOURCES})
list(FILTER LIB_SOURCES EXCLUDE REGEX "^${SOURCE_DIR}/(main\\.c|bin/)")

add_library(${PROJECT_NAME}_core STATIC ${LIB_SOURCES} ${HEADERS})
target_include_directories(${PROJECT_NAME}_core PUBLIC "${HEADER_DIR}")
target_compile_options(${PROJECT_NAME}_core PUBLIC -Wall -Wextra)

add_executable(${PROJECT_NAME} "${SOURCE_DIR}/main.c")
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_core)
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra)

add_executable(query "${SOURCE_DIR}/bin/query.c")
target_link_libraries(query PRIVATE ${PROJECT_NAME}_core)
target_compile_options(query PRIVATE -Wall -Wextra)

add_subdirectory(test)

file(GLOB_RECURSE TEST_FILES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/test/*.c" "${CMAKE_SOURCE_DIR}/test/*.h")
add_format(format EXCLUDE_FROM_ALL ${SOURCES} ${HEADERS} ${TEST_FILES})
