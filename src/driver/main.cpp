// Command-line entry point for the JOCKY compiler.
//
// This file does one job: turn argv into a jocky::driver::Options value and
// hand it to the Driver. The argument parser is a small hand-written loop on
// purpose - it keeps the tool easy to read for someone who does not know
// LLVM's llvm::cl option library.

#include "jocky/driver/Driver.h"
#include "jocky/driver/Options.h"

#include <llvm/Config/llvm-config.h>      // LLVM_VERSION_STRING
#include <llvm/Support/Path.h>            // llvm::sys::path::extension
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Host.h>       // llvm::sys::getDefaultTargetTriple

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifndef JOCKY_VERSION
#define JOCKY_VERSION "0.0.0"  // real value comes from CMake; this is only a fallback
#endif

using namespace jocky::driver;

namespace {

const char *const kUsage =
    "jocky " JOCKY_VERSION " - the JOCKY compiler\n"
    "\n"
    "usage:\n"
    "  jocky build <in.jk> [-o <out>] [-O0|-O1] [--emit-llvm] [--emit-obj]\n"
    "                      [--keep-temps] [--no-verify] [-v]\n"
    "  jocky lex   --dump-tokens <in.jk>\n"
    "  jocky parse --dump-ast    <in.jk>\n"
    "  jocky --version\n"
    "  jocky --help\n"
    "\n"
    "Input files must have a '.jk' extension.\n";

void printUsage(llvm::raw_ostream &os) { os << kUsage; }

void printVersion() {
    llvm::outs() << "jocky " JOCKY_VERSION " (LLVM " LLVM_VERSION_STRING ")\n";
    llvm::outs() << "host: " << llvm::sys::getDefaultTargetTriple() << "\n";
}

// Parses argv into `opts`.
//
// Return value:
//   std::nullopt  -> parsing succeeded; the caller should run the Driver.
//   an int        -> the process should exit now with that code
//                    (0 for --help / --version, 2 for a bad command line).
std::optional<int> parseArgs(int argc, char **argv, Options &opts) {
    const std::vector<std::string_view> args(argv + 1, argv + argc);

    if (args.empty()) {
        printUsage(llvm::errs());
        return 2;
    }

    // Global flags that need no sub-command.
    if (args[0] == "--version") {
        printVersion();
        return 0;
    }
    if (args[0] == "--help" || args[0] == "-h") {
        printUsage(llvm::outs());
        return 0;
    }

    // Sub-command.
    if (args[0] == "build") {
        opts.command = Command::Build;
    } else if (args[0] == "lex") {
        opts.command = Command::Lex;
    } else if (args[0] == "parse") {
        opts.command = Command::Parse;
    } else {
        llvm::errs() << "jocky: unknown command '" << args[0] << "'\n";
        printUsage(llvm::errs());
        return 2;
    }

    // Everything after the sub-command: flags plus exactly one input path.
    for (std::size_t i = 1; i < args.size(); ++i) {
        const std::string_view a = args[i];

        if (a == "-o") {
            if (i + 1 >= args.size()) {
                llvm::errs() << "jocky: -o needs a value\n";
                return 2;
            }
            opts.outputPath = std::string(args[++i]);
        } else if (a == "-O0") {
            opts.optimize = false;
        } else if (a == "-O1") {
            opts.optimize = true;
        } else if (a == "--emit-llvm") {
            opts.emitLlvm = true;
        } else if (a == "--emit-obj") {
            opts.emitObj = true;
        } else if (a == "--keep-temps") {
            opts.keepTemps = true;
        } else if (a == "--no-verify") {
            opts.verifyModule = false;
        } else if (a == "--dump-tokens") {
            opts.dumpTokens = true;
        } else if (a == "--dump-ast") {
            opts.dumpAst = true;
        } else if (a == "-v" || a == "--verbose") {
            opts.verbose = true;
        } else if (!a.empty() && a.front() == '-') {
            llvm::errs() << "jocky: unknown option '" << a << "'\n";
            return 2;
        } else if (opts.inputPath.empty()) {
            opts.inputPath = std::string(a);
        } else {
            llvm::errs() << "jocky: more than one input file ('" << opts.inputPath
                         << "' and '" << a << "')\n";
            return 2;
        }
    }

    if (opts.inputPath.empty()) {
        llvm::errs() << "jocky: no input file given\n";
        return 2;
    }
    if (llvm::sys::path::extension(opts.inputPath) != ".jk") {
        llvm::errs() << "jocky: input file must have a '.jk' extension (got '"
                     << opts.inputPath << "')\n";
        return 2;
    }
    return std::nullopt;
}

}  // namespace

int main(int argc, char **argv) {
    Options opts;
    if (const std::optional<int> exitCode = parseArgs(argc, argv, opts)) {
        return *exitCode;
    }
    return Driver{}.run(opts);
}
