cmake_minimum_required(VERSION 3.10)
project(test)

enable_testing()

add_custom_target(${PROJECT_NAME} ALL)

# Add test files
file(GLOB test_files "*.test.cpp")
foreach (test_file ${test_files})
    set(SOURCES ${test_file})
    get_filename_component(test_name ${test_file} NAME_WLE)
    add_executable(${test_name} ${SOURCES})
    target_compile_definitions(${test_name} PRIVATE CATCH_CONFIG_MAIN)
    target_include_directories(${test_name} PRIVATE ${CMAKE_BINARY_DIR}/src/generated/inc)
    target_link_libraries(${test_name} PRIVATE
        Catch2 Catch2WithMain
        Threads::Threads
        $<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:OpenSSL::SSL>
        $<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:OpenSSL::Crypto>
        spdlog $<$<BOOL:${MINGW}>:ws2_32>)
    target_compile_options(${test_name}
        PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/bigobj>)
    add_test(NAME ${test_name} COMMAND ${test_name})
    add_dependencies(${PROJECT_NAME} ${test_name})
    list(APPEND test_list ${test_name})
endforeach ()

if(GENERATE_CODE_COVERAGE AND LINUX AND CMAKE_BUILD_TYPE MATCHES Debug)
    setup_target_for_coverage_lcov(NAME coverage
        EXECUTABLE ctest --build-config Debug --output-on-failure
        BASE_DIRECTORY ${SOURCE_FOLDER}
        EXCLUDE "/usr/*" "${CMAKE_SOURCE_DIR}/inc/*" "${CMAKE_SOURCE_DIR}/build/*" "${CMAKE_SOURCE_DIR}/3rd/*"
        DEPENDENCIES ${test_list})
endif(GENERATE_CODE_COVERAGE AND LINUX AND CMAKE_BUILD_TYPE MATCHES Debug)
