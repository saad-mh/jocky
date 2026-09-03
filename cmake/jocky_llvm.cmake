# Find the LLVM development SDK and expose it to the rest of the build as a
# single interface target: `jocky::llvm`.
#
# Anything that needs LLVM headers or libraries just does:
#     target_link_libraries(<target> PRIVATE jocky::llvm)
#
# Why this file also touches compile flags:
#   The vendored LLVM was built as a Release library with RTTI OFF and C++
#   exceptions OFF. On Windows/MSVC especially, our code MUST be compiled with
#   matching settings or the link step fails with confusing errors about
#   "_ITERATOR_DEBUG_LEVEL", "RuntimeLibrary" mismatch, or missing type_info
#   symbols. `include(HandleLLVMOptions)` reads how LLVM was built (out of
#   LLVMConfig.cmake) and appends the flags that make our build match.

# Pin the major.minor version. The machine may also have a newer system-wide
# LLVM (e.g. installed by winget) that is NOT a full SDK; pinning makes sure we
# only ever accept the vendored 18.1.x SDK.
find_package(LLVM 18.1 REQUIRED CONFIG)

message(STATUS "JOCKY: found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "JOCKY: LLVMConfig.cmake from ${LLVM_DIR}")

# Let `include(HandleLLVMOptions)` / `include(AddLLVM)` find their helper files.
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

# Match LLVM's build settings for RTTI and exceptions (adds /GR- and /EHs-c- on
# MSVC when, as here, LLVM was built with them off).
include(HandleLLVMOptions)
include(AddLLVM)

# Match LLVM's C runtime choice.
#
# The vendored LLVM is a Release build, so its .lib files use the release,
# multi-threaded DLL runtime (/MD). A default Debug build of our code would use
# the debug runtime (/MDd) instead, and mixing the two fails to link with
# "mismatch detected for _ITERATOR_DEBUG_LEVEL / RuntimeLibrary". Force the
# release DLL runtime for every configuration so our objects and LLVM's agree.
# (Our own code is still built unoptimized with debug info in a Debug build -
# only the C runtime flavor is pinned.)
#
# Relies on CMake policy CMP0091 (NEW since 3.15) so this variable, rather than
# hard-coded /MD flags, drives runtime selection.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL" CACHE STRING
        "MSVC C runtime library (pinned to release DLL to match the LLVM SDK)" FORCE)
endif()

# LLVM_DEFINITIONS arrives as one space-separated string of "-D..." tokens.
# It must be split into a list before it can be used as compile definitions.
separate_arguments(JOCKY_LLVM_DEFS NATIVE_COMMAND "${LLVM_DEFINITIONS}")

# Map the LLVM "components" we use onto the actual static library names.
#   core support irreader   -> IR data structures, helpers, .ll/.bc reading
#   analysis passes         -> the (new) pass manager and analyses
#   target mc mcparser codegen -> lowering IR down to machine code
#   AllTargets*             -> every backend LLVM was built with (X86, AArch64):
#                              their codegen, asm parsers, descriptions, info and
#                              disassemblers. Broad on purpose during development
#                              so we can retarget freely; can be narrowed to just
#                              the host (component "native") later.
#
# Note: use the "AllTargets*" spellings here, not llvm-config's "all-targets" -
# only the former are understood by llvm_map_components_to_libnames().
llvm_map_components_to_libnames(JOCKY_LLVM_LIBS
    core
    support
    irreader
    analysis
    passes
    target
    mc
    mcparser
    codegen
    AllTargetsCodeGens
    AllTargetsAsmParsers
    AllTargetsDescs
    AllTargetsInfos
    AllTargetsDisassemblers
)

add_library(jocky_llvm INTERFACE)
add_library(jocky::llvm ALIAS jocky_llvm)

# SYSTEM so that our strict warning flags are not applied to LLVM's headers.
target_include_directories(jocky_llvm SYSTEM INTERFACE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(jocky_llvm INTERFACE ${JOCKY_LLVM_DEFS})
target_link_libraries(jocky_llvm INTERFACE ${JOCKY_LLVM_LIBS})
target_link_directories(jocky_llvm INTERFACE ${LLVM_LIBRARY_DIRS})

# Where the test tools (FileCheck, not, llvm-lit) live. They are NOT in the
# installed SDK's bin/ (it was built with tests disabled), but they are in the
# LLVM build tree that produced the SDK. test/CMakeLists.txt uses this.
set(JOCKY_LLVM_BUILD_TOOLS_DIR "${CMAKE_SOURCE_DIR}/.vendor/llvm-build/bin"
    CACHE PATH "Directory holding vendored FileCheck / not / llvm-lit.py for tests")
