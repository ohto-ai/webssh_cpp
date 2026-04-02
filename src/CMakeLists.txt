cmake_minimum_required(VERSION 3.10)

# set the project name and version
project(${ProjectId} LANGUAGES CXX)

# set project maintainer and contact
set(PROJECT_MAINTAINER "OhtoAi")
set(PROJECT_CONTACT "zhu.thatboy@outlook.com")
set(PROJECT_DESCRIPTION "A cmake project template")
set(PROJECT_DEBIAN_DEPENDENCIES "libssl1.1 (>= 1.1.0)")
set(PROJECT_HOMEPAGE "https://github.com/Ohto-Ai/CMakeProjectTemplate/")

# trans project name
string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_VAR)
string(REPLACE "-" "_" PROJECT_NAME_VAR ${PROJECT_NAME_VAR})

# Build ssh_connection as a static library so tests can link against it
add_library(webssh_cpp_ssh_lib STATIC
    ssh_connection/ssh_connection.cpp
)
target_include_directories(webssh_cpp_ssh_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${PROJECT_BINARY_DIR}/generated/inc)
target_link_libraries(webssh_cpp_ssh_lib PUBLIC
    Threads::Threads
    $<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:OpenSSL::SSL>
    $<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:OpenSSL::Crypto>
    libssh2_static
    $<$<NOT:$<PLATFORM_ID:Windows>>:atomic>
    spdlog
    $<$<PLATFORM_ID:Windows>:ws2_32>)

# Add source files for the main executable
set(SOURCES
    main.cpp
)

# Build the executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE inc)
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_BINARY_DIR}/generated/inc)

target_link_libraries(${PROJECT_NAME} PRIVATE
    webssh_cpp_ssh_lib
    hv_static)
