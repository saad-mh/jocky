#include "jocky/driver/Linker.h"

#include <llvm/ADT/SmallString.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Process.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/raw_ostream.h>

#include <optional>
#include <string>

namespace jocky::driver {

namespace {

#ifdef _WIN32
constexpr const char *kClangName = "clang.exe";
#else
constexpr const char *kClangName = "clang";
#endif

std::string clangIn(llvm::StringRef dir) {
    if (dir.empty()) return {};
    llvm::SmallString<256> path(dir);
    llvm::sys::path::append(path, kClangName);
    return llvm::sys::fs::exists(path) ? std::string(path.str()) : std::string{};
}

// Finds a `clang` to link with. Prefers a clang that matches the LLVM version
// JOCKY was built against; only falls back to PATH (with a warning) because a
// different clang there might not agree on runtime details.
std::string findClang(const std::string &explicitPath) {
    if (!explicitPath.empty() && llvm::sys::fs::exists(explicitPath))
        return explicitPath;

    // 1. $LLVM_ROOT/bin/clang - set by scripts/bootstrap.* / .jocky-env.*
    if (std::optional<std::string> root =
            llvm::sys::Process::GetEnv("LLVM_ROOT")) {
        llvm::SmallString<256> binDir(*root);
        llvm::sys::path::append(binDir, "bin");
        if (std::string c = clangIn(binDir); !c.empty()) return c;
    }

#ifdef JOCKY_LLVM_TOOLS_DIR
    // 2. The LLVM tools directory recorded at build time.
    if (std::string c = clangIn(JOCKY_LLVM_TOOLS_DIR); !c.empty()) return c;
#endif

    // 3. PATH (last resort).
    if (llvm::ErrorOr<std::string> onPath =
            llvm::sys::findProgramByName("clang")) {
        llvm::errs() << "jocky: warning: linking with 'clang' from PATH ("
                     << *onPath
                     << "); it may not match the LLVM version JOCKY uses\n";
        return *onPath;
    }
    return {};
}

}  // namespace

bool link(llvm::ArrayRef<std::string> objectFiles, llvm::StringRef outputPath,
          const LinkOptions &options) {
    const std::string clang = findClang(options.linkerDriver);
    if (clang.empty()) {
        llvm::errs() << "jocky: cannot find 'clang' to link with. Set LLVM_ROOT "
                        "or put the matching LLVM bin/ directory on PATH.\n";
        return false;
    }

    // Backing storage for the `-L` / `-l` tokens (args below holds StringRefs).
    std::vector<std::string> flagStorage;
    flagStorage.reserve(options.libSearchPaths.size() + options.libs.size());
    for (const std::string &p : options.libSearchPaths)
        flagStorage.push_back("-L" + p);
    for (const std::string &l : options.libs) flagStorage.push_back("-l" + l);

    // clang <objs> -o <out> -fuse-ld=lld [-L...] [-l...]
    llvm::SmallVector<llvm::StringRef, 16> args;
    args.push_back(clang);
    for (const std::string &obj : objectFiles) args.push_back(obj);
    args.push_back("-o");
    args.push_back(outputPath);
    args.push_back("-fuse-ld=lld");
    for (const std::string &f : flagStorage) args.push_back(f);

    if (options.verbose) {
        llvm::errs() << "jocky: linking:";
        for (llvm::StringRef a : args) llvm::errs() << ' ' << a;
        llvm::errs() << '\n';
    }

    std::string errMsg;
    bool execFailed = false;
    const int rc = llvm::sys::ExecuteAndWait(
        clang, args, /*Env=*/std::nullopt, /*Redirects=*/{},
        /*SecondsToWait=*/0, /*MemoryLimit=*/0, &errMsg, &execFailed);

    if (execFailed) {
        llvm::errs() << "jocky: could not run the linker (" << clang
                     << "): " << errMsg << '\n';
        return false;
    }
    if (rc != 0) {
        llvm::errs() << "jocky: linking failed (clang exited with " << rc
                     << ")\n";
#ifdef _WIN32
        llvm::errs()
            << "jocky: note: on Windows the linker needs the MSVC and Windows "
               "SDK libraries. Run from a 'Developer PowerShell for VS 2022' "
               "(or an 'x64 Native Tools Command Prompt'), or make sure Visual "
               "Studio is installed so clang can find them itself.\n";
#endif
        return false;
    }
    return true;
}

}  // namespace jocky::driver
