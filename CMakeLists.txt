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
option(BUILD_SHARED_LIBS "Build as shared library" OFF)
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

# Base optimizations
set(GCC_CLANG_FLAGS_RELEASE "-O3" "-funroll-loops" "-DNDEBUG" "-fstrict-aliasing")
set(GCC_CLANG_FLAGS_DEBUG   "-g" "-O0" "-DDEBUG")
set(MSVC_FLAGS_RELEASE "/Ox" "/Oi" "/Ot" "/GL" "/DNDEBUG")
set(MSVC_FLAGS_DEBUG   "/Od" "/Zi" "/DDEBUG")

# Architecture specific optimizations
set(ARCH_FLAGS "")

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(ENABLE_NATIVE_ARCH)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
            # CRITICAL: On ARM64, we must explicitly request crypto extensions
            # to get __ARM_FEATURE_CRYPTO and the intrinsics.
            # Apple Silicon (M1/M2/M3/M4) supports this.
            list(APPEND ARCH_FLAGS "-march=armv8-a+crypto")
        else()
            # x86/x64
            list(APPEND ARCH_FLAGS "-march=native" "-mtune=native")
        endif()
    endif()

    # Enable LTO/IPO only if supported
    include(CheckIPOSupported)
    check_ipo_supported(RESULT result OUTPUT output)
    if(result)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    else()
        message(STATUS "LTO/IPO is not supported by this compiler, disabling it.")
    endif()
elseif(MSVC)
    if(ENABLE_NATIVE_ARCH)
        list(APPEND ARCH_FLAGS "/arch:AVX2") # Good default for modern x86 Windows
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

        # Strip unused sections in Release
        if(NOT APPLE)
            # macOS linker doesn't support --gc-sections the same way
            target_link_options(${target} PRIVATE $<$<CONFIG:Release>:-Wl,--gc-sections>)
        endif()
        target_compile_options(${target} PRIVATE $<$<CONFIG:Release>:-ffunction-sections -fdata-sections>)

    elseif(MSVC)
        target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:${MSVC_FLAGS_RELEASE} ${ARCH_FLAGS}>
                $<$<CONFIG:Debug>:${MSVC_FLAGS_DEBUG}>
                /W4
        )
        set_target_properties(${target} PROPERTIES
                LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG"
        )
    endif()
endfunction()

# --- Targets ---

# Shared Library
if(BUILD_SHARED_LIBS)
    add_library(turbo_asar_shared SHARED ${LIB_SOURCES})
    target_include_directories(turbo_asar_shared PUBLIC ${PROJECT_ROOT}/include ${PROJECT_ROOT}/vendor/cjson)
    set_target_properties(turbo_asar_shared PROPERTIES OUTPUT_NAME turbo_asar)
    target_compile_definitions(turbo_asar_shared PUBLIC TURBO_ASAR_BUILD_DLL)
    configure_target_for_build(turbo_asar_shared)
else ()
    add_library(turbo_asar_static STATIC ${LIB_SOURCES})
    target_include_directories(turbo_asar_static PUBLIC ${PROJECT_ROOT}/include ${PROJECT_ROOT}/vendor/cjson)
    set_target_properties(turbo_asar_static PROPERTIES OUTPUT_NAME turbo_asar)
    target_compile_definitions(turbo_asar_static PUBLIC TURBO_ASAR_BUILD_STATIC)
    configure_target_for_build(turbo_asar_static)
endif()



# CLI
if(BUILD_CLI)
    add_executable(turbo_asar_cli src/main.c src/glob.c
            include/defines.h)
    target_link_libraries(turbo_asar_cli PRIVATE turbo_asar_static)
    set_target_properties(turbo_asar_cli PROPERTIES OUTPUT_NAME turbo-asar)
    configure_target_for_build(turbo_asar_cli)
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()

    macro(add_turbo_test test_name source_file)
        add_executable(${test_name} ${source_file})
        target_link_libraries(${test_name} PRIVATE turbo_asar_static)
        configure_target_for_build(${test_name})
        add_test(NAME ${test_name} COMMAND ${test_name} WORKING_DIRECTORY ${PROJECT_ROOT})
    endmacro()

    add_turbo_test(test_pickle tests/test_pickle.c)
    add_turbo_test(test_sha256 tests/test_sha256.c)
    add_turbo_test(test_asar tests/test_asar.c)
endif()

# Benchmarks
if(BUILD_BENCHMARKS)
    add_executable(benchmark_asar benchmarks/benchmark_asar.c include/glob.h)
    target_link_libraries(benchmark_asar PRIVATE turbo_asar_static)
    configure_target_for_build(benchmark_asar)

    # SHA256 benchmark
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        add_executable(benchmark_sha256 benchmarks/benchmark_sha256.c)
        target_link_libraries(benchmark_sha256 PRIVATE turbo_asar_static OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(benchmark_sha256 PRIVATE ${OPENSSL_INCLUDE_DIR})
        configure_target_for_build(benchmark_sha256)
        message(STATUS "OpenSSL found - building SHA256 benchmark")
    else()
        message(STATUS "OpenSSL not found - SHA256 benchmark will not be built")
    endif()
endif()

# Installation
install(TARGETS turbo_asar_static ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
install(FILES include/turbo_asar.h DESTINATION include)
if(BUILD_CLI)
    install(TARGETS turbo_asar_cli RUNTIME DESTINATION bin)
endif()

message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME} (${CMAKE_SYSTEM_PROCESSOR})")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID}")
message(STATUS "Arch Flags: ${ARCH_FLAGS}")
