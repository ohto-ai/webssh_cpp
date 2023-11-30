include(FetchContent)

# libuv
set(BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC ON CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_UNITTEST OFF CACHE BOOL "" FORCE)
set(WITH_PROTOCOL OFF CACHE BOOL "" FORCE)
set(WITH_PROTOCOL OFF CACHE BOOL "" FORCE)

# libssh2
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    spdlog
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/spdlog
)
FetchContent_Declare(
    libssh2
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libssh2
)
FetchContent_Declare(
    libhv
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libhv
)
FetchContent_Declare(
    catch2
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/catch2
)

FetchContent_MakeAvailable(spdlog)
FetchContent_MakeAvailable(libssh2)
FetchContent_MakeAvailable(libhv)
FetchContent_MakeAvailable(catch2)
