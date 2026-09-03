# Warning flags for JOCKY's own code, exposed as the interface target
# `jocky_warnings`. Link it PRIVATE on our targets:
#     target_link_libraries(<target> PRIVATE jocky_warnings)
#
# These are kept separate from cmake/jocky_llvm.cmake on purpose: LLVM's headers
# are included as SYSTEM headers elsewhere, so these flags do not apply to them,
# only to files we write.

add_library(jocky_warnings INTERFACE)

if(MSVC)
    target_compile_options(jocky_warnings INTERFACE
        /W4          # high warning level
        /permissive- # stricter standard conformance
        # We build with exceptions disabled to match the LLVM SDK. Some MSVC
        # standard headers (e.g. <chrono>, pulled in transitively by LLVM) then
        # warn C4530 "exception handler used, but unwind semantics are not
        # enabled". The code path is never taken; silence the noise.
        /wd4530
    )
else()
    target_compile_options(jocky_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()
