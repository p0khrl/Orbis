cmake_minimum_required(VERSION 3.20)
project(orbis_engine VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ORBIS_BUILD_TESTS "Build unit/integration tests" ON)
option(ORBIS_BUILD_EXAMPLES "Build example applications" ON)
option(ORBIS_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)

add_library(orbis_engine
    src/core/engine.cpp
    src/core/logger.cpp
    src/tunnel/plugin_registry.cpp
    src/tunnel/wireguard_adapter.cpp
    src/tunnel/wireguard_registration.cpp
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(orbis_engine PRIVATE
        src/platform/linux/netlink_util.cpp
        src/platform/linux/kernel_wireguard_backend.cpp
    )
endif()

if (WIN32)
    target_sources(orbis_engine PRIVATE
        src/platform/windows/wireguard_nt_backend.cpp
    )
    target_link_libraries(orbis_engine PUBLIC iphlpapi ws2_32)
endif()
target_include_directories(orbis_engine PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if (MSVC)
    target_compile_options(orbis_engine PRIVATE /W4 $<$<BOOL:${ORBIS_WARNINGS_AS_ERRORS}>:/WX>)
else()
    target_compile_options(orbis_engine PRIVATE -Wall -Wextra -Wpedantic
        $<$<BOOL:${ORBIS_WARNINGS_AS_ERRORS}>:-Werror>)
endif()

if (ORBIS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if (ORBIS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
