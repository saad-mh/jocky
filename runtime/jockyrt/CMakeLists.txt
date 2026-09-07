# jockyrt - the JOCKY forensic runtime shim (requirement Part 2).
#
# A plain C11 static library. It is linked into forensic builds (Part 3); it
# does not depend on LLVM or on the compiler in src/. Source files are listed
# explicitly and grow one requirement at a time.

add_library(jockyrt STATIC
    src/error.c
    src/privilege.c
    src/process.c
)

target_include_directories(jockyrt
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
set_target_properties(jockyrt PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)

if(WIN32)
    # OpenProcessToken / LookupPrivilegeValue / AdjustTokenPrivileges live in
    # advapi32; the Toolhelp and process APIs are in kernel32 (linked by default).
    target_link_libraries(jockyrt PUBLIC advapi32)
else()
    message(WARNING
        "jockyrt targets Windows; on this platform every jkf_* call returns "
        "JKF_E_UNSUPPORTED.")
endif()

# --- smoke test ------------------------------------------------------------
# Registered with CTest. `ctest --test-dir build -R jockyrt` runs just this;
# the `check-jockyrt` target below is a convenience that also builds first.

add_executable(jockyrt_smoke test/smoke.c)
target_link_libraries(jockyrt_smoke PRIVATE jockyrt)
set_target_properties(jockyrt_smoke PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
)

add_test(NAME jockyrt_smoke COMMAND jockyrt_smoke)

add_custom_target(check-jockyrt
    COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -R "^jockyrt_"
    DEPENDS jockyrt_smoke
    USES_TERMINAL
    COMMENT "Running jockyrt tests")
