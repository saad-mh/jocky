// The Driver ties the compiler stages together for one run of the `jocky` tool.
//
// main.cpp parses the command line into an Options value and hands it to
// Driver::run. As each pipeline stage is implemented it gets wired in here:
//   read source -> lex -> parse -> lower to LLVM IR -> emit object -> link.

#ifndef JOCKY_DRIVER_DRIVER_H
#define JOCKY_DRIVER_DRIVER_H

#include "jocky/driver/Options.h"

namespace jocky::driver {

class Driver {
public:
    // Runs the requested command. Returns a process exit code:
    //   0   success
    //   1   the user's program or inputs were bad (reported as diagnostics)
    //   2   the command line itself was wrong
    //   70  an internal compiler error (a bug in jocky)
    int run(const Options &options);
};

}  // namespace jocky::driver

#endif  // JOCKY_DRIVER_DRIVER_H
