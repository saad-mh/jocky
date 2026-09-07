# Top-level build file for the JOCKY compiler.
#
# What happens here, in order:
#   1. Basic project settings (language, C++ standard, default build type).
#   2. Find the LLVM development SDK and set up an interface target for it
#      (see cmake/jocky_llvm.cmake). This also fixes the RTTI/exceptions/CRT
#      settings so our code matches how LLVM itself was built.
#   3. Set up the warning flags we want on our own code (cmake/jocky_warnings.cmake).
#   4. Build the compiler in src/ and the tests in test/.
#
# LLVM_DIR is normally provided by scripts/bootstrap.ps1 (or bootstrap.sh),
# which points it at the vendored SDK under .vendor/.

cmake_minimum_required(VERSION 3.20)

project(jocky
    VERSION 0.1.0
    DESCRIPTION "JOCKY compiler"
    LANGUAGES C CXX
)

# --- Project-wide settings -------------------------------------------------

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)              # use -std=c++20, not -std=gnu++20
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)      # writes compile_commands.json for editors/clangd

# Default to a Debug build when the generator is single-config and the user
# did not ask for something specific.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

# JOCKY is developed and tested with the Ninja generator. Other generators may
# work but are not exercised; warn so a surprising build failure is less puzzling.
if(DEFINED CMAKE_GENERATOR AND NOT CMAKE_GENERATOR MATCHES "Ninja")
    message(WARNING
        "JOCKY is developed with the Ninja generator (cmake -G Ninja). "
        "Generator '${CMAKE_GENERATOR}' is untested here.")
endif()

# --- Dependencies and toolchain setup ------------------------------------

# Sets up the `jocky::llvm` interface target and matching compile flags.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/jocky_llvm.cmake")

# Sets up the `jocky_warnings` interface target (our own warning flags only).
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/jocky_warnings.cmake")

# --- Build the compiler and its tests ----------------------------------

enable_testing()

add_subdirectory(src)
add_subdirectory(test)

# The forensic runtime shim (Part 2). Independent of LLVM and of src/.
add_subdirectory(runtime/jockyrt)

# --- Configure summary --------------------------------------------------

message(STATUS "")
message(STATUS "JOCKY configure summary:")
message(STATUS "  Version:       ${PROJECT_VERSION}")
message(STATUS "  Build type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  Generator:     ${CMAKE_GENERATOR}")
message(STATUS "  C++ compiler:  ${CMAKE_CXX_COMPILER}")
message(STATUS "  LLVM version:  ${LLVM_PACKAGE_VERSION}")
message(STATUS "  LLVM_DIR:      ${LLVM_DIR}")
message(STATUS "")
