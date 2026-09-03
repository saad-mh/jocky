// Driver implementation.
//
// Right now this only knows how to say "not implemented yet". Each pipeline
// stage (lexer, parser, codegen, object emission, linking) is added in its own
// later commit and wired into run() here.

#include "jocky/driver/Driver.h"

#include <cstdio>

namespace jocky::driver {

int Driver::run(const Options &options) {
    switch (options.command) {
    case Command::Build:
    case Command::Lex:
    case Command::Parse:
        std::fprintf(stderr,
                     "jocky: this command is not implemented yet "
                     "(the compiler pipeline is still being built up)\n");
        return 1;

    case Command::None:
        // main.cpp handles --help / --version and never calls run() with None,
        // so reaching here means the argument parser let something through.
        std::fprintf(stderr, "jocky: no command given (try `jocky --help`)\n");
        return 2;
    }

    return 2;  // unreachable; keeps the compiler from warning about the switch
}

}  // namespace jocky::driver
