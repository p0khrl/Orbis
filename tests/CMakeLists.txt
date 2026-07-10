include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
FetchContent_MakeAvailable(googletest)

add_executable(orbis_tests engine_test.cpp wireguard_adapter_test.cpp)
target_link_libraries(orbis_tests PRIVATE orbis_engine gtest_main)
add_test(NAME orbis_tests COMMAND orbis_tests)
