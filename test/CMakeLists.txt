# Test wiring for JOCKY: LLVM's `lit` test runner plus `FileCheck`.
#
# The tools (llvm-lit.py, FileCheck, not) are NOT in the installed LLVM SDK's
# bin/ (it was built with tests disabled), so we take them from the LLVM build
# tree that produced the SDK - see JOCKY_LLVM_BUILD_TOOLS_DIR in
# cmake/jocky_llvm.cmake.
#
# Two ways to run the suite:
#   cmake --build build --target check     # the `check` custom target
#   ctest --test-dir build                 # via CTest (registered as test "lit")

find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(JOCKY_LIT       "${JOCKY_LLVM_BUILD_TOOLS_DIR}/llvm-lit.py")
set(JOCKY_FILECHECK "${JOCKY_LLVM_BUILD_TOOLS_DIR}/FileCheck.exe")
set(JOCKY_NOT       "${JOCKY_LLVM_BUILD_TOOLS_DIR}/not.exe")

foreach(_tool "${JOCKY_LIT}" "${JOCKY_FILECHECK}" "${JOCKY_NOT}")
    if(NOT EXISTS "${_tool}")
        message(FATAL_ERROR
            "JOCKY's tests need the LLVM build-tree tools, but this one is missing:\n"
            "  ${_tool}\n"
            "Set -DJOCKY_LLVM_BUILD_TOOLS_DIR=<dir containing FileCheck.exe and "
            "llvm-lit.py> to point at your LLVM build tree.")
    endif()
endforeach()

# The end-to-end tests link a real executable and need a `clang` for that step.
# Prefer the vendored v18 clang so it matches the SDK we generate code against.
find_program(JOCKY_CLANG NAMES clang clang.exe
    PATHS "${LLVM_TOOLS_BINARY_DIR}" NO_DEFAULT_PATH)
if(NOT JOCKY_CLANG)
    find_program(JOCKY_CLANG NAMES clang clang.exe)
endif()
if(JOCKY_CLANG)
    set(JOCKY_HAVE_LINKER 1)
    message(STATUS "JOCKY: end-to-end tests will use ${JOCKY_CLANG}")
else()
    set(JOCKY_HAVE_LINKER 0)
    message(WARNING "JOCKY: no 'clang' found for the link step; end-to-end tests will be skipped.")
endif()

# lit.site.cfg.py is built in two steps: configure_file expands the @VARS@,
# then file(GENERATE) resolves the $<TARGET_FILE:jocky> generator expression
# (which is not known until generation time).
set(JOCKY_TOOL "$<TARGET_FILE:jocky>")
set(JOCKY_TEST_EXEC_ROOT "${CMAKE_CURRENT_BINARY_DIR}")

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in"
    "${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py.configured"
    @ONLY)
file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py"
    INPUT  "${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py.configured")

add_custom_target(check
    COMMAND "${Python3_EXECUTABLE}" "${JOCKY_LIT}" -sv "${CMAKE_CURRENT_BINARY_DIR}"
    DEPENDS jocky
    USES_TERMINAL
    COMMENT "Running JOCKY lit tests")

add_test(NAME lit
    COMMAND "${Python3_EXECUTABLE}" "${JOCKY_LIT}" -sv "${CMAKE_CURRENT_BINARY_DIR}")
