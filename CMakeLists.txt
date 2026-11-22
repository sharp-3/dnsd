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

add_executable(${PROJECT_NAME} "${SOURCE_DIR}/main.c")
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra)

add_format(format EXCLUDE_FROM_ALL ${SOURCES} ${HEADERS})
