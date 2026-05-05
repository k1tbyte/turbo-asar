cmake_minimum_required(VERSION 3.16)
project(turbo-asar C)

# --- basic project settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

# default to Release
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

option(ENABLE_NATIVE_ARCH "Enable native CPU architecture optimizations" ON)
option(BUILD_SHARED_LIBS "Build shared library (in addition to static)" OFF)
option(BUILD_CLI "Build command line tool" ON)
option(BUILD_TESTS "Build tests" ON)
option(BUILD_BENCHMARKS "Build benchmarks" ON)

set(LIB_SOURCES
        src/sha256.c
        src/pickle.c
        src/filesystem.c
        src/asar.c
        src/glob.c
        vendor/cjson/cJSON.c
)

# --- Compilation Flags ---

set(GCC_CLANG_FLAGS_RELEASE "-O3" "-funroll-loops" "-DNDEBUG" "-fstrict-aliasing")
set(GCC_CLANG_FLAGS_DEBUG   "-g" "-O0" "-DDEBUG")
set(MSVC_FLAGS_RELEASE "/O2" "/Oi" "/Ot" "/GL" "/DNDEBUG")
set(MSVC_FLAGS_DEBUG   "/Od" "/Zi" "/DDEBUG")
if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
endif()

set(ARCH_FLAGS "")

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(ENABLE_NATIVE_ARCH)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
            list(APPEND ARCH_FLAGS "-march=armv8-a+crypto")
        else()
            list(APPEND ARCH_FLAGS "-march=native" "-mtune=native")
        endif()
    endif()

    include(CheckIPOSupported)
    check_ipo_supported(RESULT result OUTPUT output)
    if(result)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    else()
        message(STATUS "LTO/IPO is not supported by this compiler, disabling it.")
    endif()
elseif(MSVC)
    if(ENABLE_NATIVE_ARCH)
        list(APPEND ARCH_FLAGS "/arch:AVX2")
    endif()
endif()

# --- Helper Function ---
function(configure_target_for_build target)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:${GCC_CLANG_FLAGS_RELEASE} ${ARCH_FLAGS}>
                $<$<CONFIG:Debug>:${GCC_CLANG_FLAGS_DEBUG}>
                -Wall -Wextra
        )

        if(NOT APPLE)
            target_link_options(${target} PRIVATE $<$<CONFIG:Release>:-Wl,--gc-sections>)
        endif()
        target_compile_options(${target} PRIVATE $<$<CONFIG:Release>:-ffunction-sections -fdata-sections>)

    elseif(MSVC)
        target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:${MSVC_FLAGS_RELEASE} ${ARCH_FLAGS}>
                $<$<CONFIG:Debug>:${MSVC_FLAGS_DEBUG}>
                /W4
        )
        target_link_options(${target} PRIVATE
                $<$<CONFIG:Release>:/OPT:REF /OPT:ICF /LTCG>
        )
    endif()
endfunction()

# --- Targets ---

# Static library is always built. Tests, CLI, benchmarks link to it
# unconditionally so they work regardless of BUILD_SHARED_LIBS and so internal
# (non-exported) symbols stay reachable for tests under DLL builds.
add_library(turbo_asar_static STATIC ${LIB_SOURCES})
target_include_directories(turbo_asar_static PUBLIC ${PROJECT_ROOT}/include ${PROJECT_ROOT}/vendor/cjson)
set_target_properties(turbo_asar_static PROPERTIES OUTPUT_NAME turbo_asar)
target_compile_definitions(turbo_asar_static PUBLIC TURBO_ASAR_BUILD_STATIC)
configure_target_for_build(turbo_asar_static)

# Shared library, optional, alongside static.
if(BUILD_SHARED_LIBS)
    # When both are built, give the static a suffix so its .lib doesn't
    # collide with the shared's import .lib.
    set_target_properties(turbo_asar_static PROPERTIES OUTPUT_NAME turbo_asar_static)

    add_library(turbo_asar_shared SHARED ${LIB_SOURCES})
    target_include_directories(turbo_asar_shared PUBLIC ${PROJECT_ROOT}/include ${PROJECT_ROOT}/vendor/cjson)
    set_target_properties(turbo_asar_shared PROPERTIES OUTPUT_NAME turbo_asar)
    target_compile_definitions(turbo_asar_shared PRIVATE TURBO_ASAR_BUILD_DLL)
    configure_target_for_build(turbo_asar_shared)
    set(TURBO_ASAR_INSTALL_TARGETS turbo_asar_static turbo_asar_shared)
else()
    set(TURBO_ASAR_INSTALL_TARGETS turbo_asar_static)
endif()

# Internal targets (CLI, tests, benchmarks) link statically — keeps internal
# headers usable even with DLL output, and avoids runtime DLL search problems.
set(TURBO_ASAR_LINK_TARGET turbo_asar_static)

# CLI
if(BUILD_CLI)
    add_executable(turbo_asar_cli src/main.c)
    target_link_libraries(turbo_asar_cli PRIVATE ${TURBO_ASAR_LINK_TARGET})
    set_target_properties(turbo_asar_cli PROPERTIES OUTPUT_NAME turbo-asar)
    configure_target_for_build(turbo_asar_cli)
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()

    macro(add_turbo_test test_name source_file)
        add_executable(${test_name} ${source_file})
        target_link_libraries(${test_name} PRIVATE ${TURBO_ASAR_LINK_TARGET})
        configure_target_for_build(${test_name})
        add_test(NAME ${test_name} COMMAND ${test_name} WORKING_DIRECTORY ${PROJECT_ROOT})
    endmacro()

    add_turbo_test(test_pickle tests/test_pickle.c)
    add_turbo_test(test_sha256 tests/test_sha256.c)
    add_turbo_test(test_asar tests/test_asar.c)
endif()

# Benchmarks
if(BUILD_BENCHMARKS)
    add_executable(benchmark_asar benchmarks/benchmark_asar.c)
    target_link_libraries(benchmark_asar PRIVATE ${TURBO_ASAR_LINK_TARGET})
    configure_target_for_build(benchmark_asar)

    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        add_executable(benchmark_sha256 benchmarks/benchmark_sha256.c)
        target_link_libraries(benchmark_sha256 PRIVATE ${TURBO_ASAR_LINK_TARGET} OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(benchmark_sha256 PRIVATE ${OPENSSL_INCLUDE_DIR})
        configure_target_for_build(benchmark_sha256)
        message(STATUS "OpenSSL found - building SHA256 benchmark")
    else()
        message(STATUS "OpenSSL not found - SHA256 benchmark will not be built")
    endif()
endif()

# Installation
install(
        TARGETS ${TURBO_ASAR_INSTALL_TARGETS}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)
install(FILES include/turbo_asar.h DESTINATION include)
if(BUILD_CLI)
    install(TARGETS turbo_asar_cli RUNTIME DESTINATION bin)
endif()

message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME} (${CMAKE_SYSTEM_PROCESSOR})")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID}")
message(STATUS "Arch Flags: ${ARCH_FLAGS}")
message(STATUS "Shared library: ${BUILD_SHARED_LIBS}")
