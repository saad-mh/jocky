// Parsed command-line options for the `jocky` tool.
//
// main.cpp turns argv into an Options value; Driver::run acts on it. Keeping
// this in a plain struct (rather than scattering flag parsing through the
// pipeline) means every stage can see the whole request at once.

#ifndef JOCKY_DRIVER_OPTIONS_H
#define JOCKY_DRIVER_OPTIONS_H

#include <string>

namespace jocky::driver {

// Which sub-command the user asked for.
enum class Command {
    None,   // no sub-command (e.g. just `--help` or `--version`)
    Build,  // compile a .jky file all the way to a native executable
    Lex,    // debug: print the token stream
    Parse,  // debug: print the parsed syntax tree
};

struct Options {
    Command command = Command::None;

    // Input .jky file. Required for Build / Lex / Parse.
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

    // Debug dumps for the Lex / Parse sub-commands.
    bool dumpTokens = false;  // lex --dump-tokens
    bool dumpAst = false;     // parse --dump-ast

    bool verbose = false;  // -v / --verbose: print each stage as it runs
};

}  // namespace jocky::driver

#endif  // JOCKY_DRIVER_OPTIONS_H
