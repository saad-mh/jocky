// The link step: object file(s) in, a runnable native executable out.
//
// This is a seam. v0 shells out to `clang` (used purely as a linker driver,
// with -fuse-ld=lld) because clang already knows how to find the platform C
// runtime and startup files. A later version could call lld in-process or
// invoke a linker directly; callers would not change.

#ifndef JOCKY_DRIVER_LINKER_H
#define JOCKY_DRIVER_LINKER_H

#include <string>
#include <vector>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/StringRef.h>

namespace jocky::driver {

struct LinkOptions {
    bool verbose = false;
    // Explicit path to the linker driver. Empty means "find clang automatically".
    std::string linkerDriver;
    // Extra libraries and search paths, from `-l` / `-L` and `link "name";`.
    std::vector<std::string> libs;
    std::vector<std::string> libSearchPaths;
};

// Links `objectFiles` into an executable at `outputPath`. On failure the
// linker's own error output has already gone to stderr; returns false.
bool link(llvm::ArrayRef<std::string> objectFiles, llvm::StringRef outputPath,
          const LinkOptions &options);

}  // namespace jocky::driver

#endif  // JOCKY_DRIVER_LINKER_H
