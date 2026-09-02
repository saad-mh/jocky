cmake_minimum_required(VERSION 3.20)

project(jocky
    VERSION 0.1.0
    DESCRIPTION "Jocky compiler frontend / agent"
    LANGUAGES C CXX
)

# Project-wide settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # generates compile_commands.json for clangd/IDEs

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

# LLVM_DIR is set by bootstrap.sh / bootstrap.ps1
# find_package(LLVM) reads that to locate LLVMConfig.cmake.
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "LLVM_DIR: ${LLVM_DIR}")
message(STATUS "LLVM include dirs: ${LLVM_INCLUDE_DIRS}")

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# Map the specific LLVM components the frontend needs onto library names.
# Extend this list as the compiler frontend grows (e.g. "orcjit", "mcjit").
llvm_map_components_to_libnames(LLVM_LIBS
    core
    support
    irreader
    x86codegen
    x86asmparser
)

# OpenSSL
find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")

# libcurl
find_package(CURL REQUIRED)
message(STATUS "Found CURL ${CURL_VERSION_STRING}")

# SQLite3
find_package(SQLite3 REQUIRED)
message(STATUS "Found SQLite3 ${SQLite3_VERSION}")

# Target: jocky (placeholder executable)
add_executable(jocky
    src/main.cpp
)

target_include_directories(jocky PRIVATE
    ${LLVM_INCLUDE_DIRS}
)

target_link_libraries(jocky PRIVATE
    ${LLVM_LIBS}
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    SQLite::SQLite3
)

# Summary
message(STATUS "")
message(STATUS "jocky configure summary:")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ compiler:   ${CMAKE_CXX_COMPILER}")
message(STATUS "  LLVM version:   ${LLVM_PACKAGE_VERSION}")
message(STATUS "  OpenSSL:        ${OPENSSL_VERSION}")
message(STATUS "  CURL:           ${CURL_VERSION_STRING}")
message(STATUS "  SQLite3:        ${SQLite3_VERSION}")
message(STATUS "")