// Parsed command-line options for the `jocky` tool.
//
// main.cpp turns argv into an Options value; Driver::run acts on it. Keeping
// this in a plain struct (rather than scattering flag parsing through the
// pipeline) means every stage can see the whole request at once.

#ifndef JOCKY_DRIVER_OPTIONS_H
#define JOCKY_DRIVER_OPTIONS_H

#include <cstdint>
#include <string>

namespace jocky::driver {

// Which sub-command the user asked for.
enum class Command {
    None,   // no sub-command (e.g. just `--help` or `--version`)
    Build,  // compile a .jk file all the way to a native executable
    Check,  // run the front end + semantic analysis only; report diagnostics
    Lex,    // debug: print the token stream
    Parse,  // debug: print the parsed syntax tree
};

struct Options {
    Command command = Command::None;

    // Input .jk file. Required for Build / Lex / Parse.
    std::string inputPath;

    // Output path for `build`. Empty means "derive it from inputPath".
    std::string outputPath;

    // false -> no optimization passes (-O0, the default).
    // true  -> LLVM's standard -O1 pipeline.
    bool optimize = false;

    // `build` stop-early switches.
    bool emitLlvm = false;  // --emit-llvm: print textual IR and stop
    bool emitObj = false;   // --emit-obj:  write an object file and stop

    // `build` behavior tweaks.
    bool keepTemps = false;    // --keep-temps: don't delete the intermediate .obj
    bool verifyModule = true;  // cleared by --no-verify (debugging only)

    // Obfuscation (build only). --obfuscate turns JOCKY's own IR obfuscation
    // passes on; --obfuscate=<a,b,...> restricts them to a named subset. These
    // run whether or not -O1 was asked for.
    bool obfuscate = false;
    std::string obfuscatePasses;  // empty => all passes, when `obfuscate` is set

    // --obf-seed <n>: seed the randomised parts of those passes so a build is
    // reproducible. 0 (the default) means "derive one at run time".
    std::uint64_t obfSeed = 0;

    // Debug dumps for the Lex / Parse sub-commands.
    bool dumpTokens = false;  // lex --dump-tokens
    bool dumpAst = false;     // parse --dump-ast

    bool verbose = false;  // -v / --verbose: print each stage as it runs
};

}  // namespace jocky::driver

#endif  // JOCKY_DRIVER_OPTIONS_H
