cmake_minimum_required(VERSION 3.10)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
# set the project name with the current directory name
get_filename_component(ProjectId ${CMAKE_SOURCE_DIR} NAME_WE)
string(REPLACE " " "_" ProjectId ${ProjectId})

# set the project name and version
project(${ProjectId})

set(CMAKE_CXX_STANDARD 17)
set(SOURCE_FOLDER ${PROJECT_SOURCE_DIR}/src CACHE STRING "Source folder")

if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_definitions(_DEBUG)
    add_compile_definitions(SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG)
endif()

find_package(OpenSSL QUIET)
find_package(Threads REQUIRED)

# include top level include directory
include_directories(${PROJECT_SOURCE_DIR}/inc)

add_subdirectory(3rd)
add_subdirectory(src)
add_subdirectory(test)
