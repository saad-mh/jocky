# Builds the JOCKY compiler.
#
# Two targets:
#   jocky_core  - static library with all the compiler stages (lexer, parser,
#                 AST, codegen, driver logic). Tests can link this directly.
#   jocky       - the small command-line front-end that calls into jocky_core.
#
# The source list for jocky_core grows one pipeline stage at a time. Keep it an
# explicit list (no file globbing) so a fresh checkout always configures the
# same way.

add_library(jocky_core STATIC
    Support/Diagnostic.cpp
    Support/StringEscape.cpp
    lexer/Lexer.cpp
    ast/AST.cpp
    ast/ASTPrinter.cpp
    parser/Parser.cpp
    driver/Driver.cpp
)
add_library(jocky::core ALIAS jocky_core)

target_include_directories(jocky_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(jocky_core
    PUBLIC  jocky::llvm
    PRIVATE jocky_warnings
)
target_compile_features(jocky_core PUBLIC cxx_std_20)

# --- The `jocky` command-line tool ------------------------------------

add_executable(jocky driver/main.cpp)
target_link_libraries(jocky PRIVATE jocky::core jocky_warnings)
target_compile_definitions(jocky PRIVATE JOCKY_VERSION="${PROJECT_VERSION}")
set_target_properties(jocky PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
)

# Optional extra libraries carried by the front-end tool (not the compiler
# stages). These are here for a future "agent" side of the project; the v0
# compiler pipeline does not use them, but keeping them linked means the build
# and the bootstrap scripts stay exercised.
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
message(STATUS "JOCKY: OpenSSL ${OPENSSL_VERSION}, CURL ${CURL_VERSION_STRING}, SQLite3 ${SQLite3_VERSION}")

target_link_libraries(jocky PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    SQLite3::SQLite3
)
