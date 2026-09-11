// Driver implementation.
//
// The driver reads the input file once and then runs whichever pipeline the
// sub-command asks for. Stages are added here as they are implemented; right
// now `lex`, `parse`, and `build --emit-llvm` work. Object emission and
// linking come next.

#include "jocky/driver/Driver.h"

#include "jocky/Support/Diagnostic.h"
#include "jocky/Support/StringEscape.h"
#include "jocky/ast/AST.h"
#include "jocky/ast/ASTPrinter.h"
#include "jocky/codegen/CodeGen.h"
#include "jocky/codegen/JITRunner.h"
#include "jocky/codegen/ObjectEmitter.h"
#include "jocky/codegen/PassPipeline.h"
#include "jocky/driver/Linker.h"
#include "jocky/lexer/Lexer.h"
#include "jocky/lexer/Token.h"
#include "jocky/parser/Parser.h"
#include "jocky/sema/Sema.h"

#include <llvm/ADT/SmallString.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>

#include <memory>
#include <random>
#include <string>
#include <vector>

namespace jocky::driver {

namespace {

// Reads the whole input file. On failure prints a diagnostic-style message and
// returns nullptr.
std::unique_ptr<llvm::MemoryBuffer> readInput(const std::string &path) {
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> bufOr =
        llvm::MemoryBuffer::getFile(path);
    if (!bufOr) {
        llvm::errs() << path << ":0:0: error: cannot open file: "
                     << bufOr.getError().message() << '\n';
        return nullptr;
    }
    return std::move(*bufOr);
}

// The output path for `build`: the user's -o if given, otherwise the input
// path with its extension swapped for `extension` (e.g. ".obj").
std::string deriveOutputPath(const Options &options, llvm::StringRef extension) {
    if (!options.outputPath.empty()) return options.outputPath;
    llvm::SmallString<128> path(options.inputPath);
    llvm::sys::path::replace_extension(path, extension);
    return std::string(path);
}

// Where the final executable goes. Like deriveOutputPath, but on Windows makes
// sure the name ends in ".exe".
std::string executableOutputPath(const Options &options) {
#ifdef _WIN32
    if (!options.outputPath.empty()) {
        if (llvm::StringRef(options.outputPath).ends_with(".exe"))
            return options.outputPath;
        return options.outputPath + ".exe";
    }
    llvm::SmallString<128> path(options.inputPath);
    llvm::sys::path::replace_extension(path, ".exe");
    return std::string(path);
#else
    if (!options.outputPath.empty()) return options.outputPath;
    llvm::SmallString<128> path(options.inputPath);
    llvm::sys::path::replace_extension(path, "");
    return std::string(path);
#endif
}

// One line per token, for `jocky lex --dump-tokens`.
void printToken(llvm::raw_ostream &os, const Token &t) {
    os << t.location.line << ':' << t.location.column << ": "
       << tokenKindName(t.kind);
    if (t.kind != TokenKind::Eof) {
        os << " '" << t.spelling << '\'';
    }
    switch (t.kind) {
    case TokenKind::IntLiteral:
        os << " int=" << t.intValue;
        if (t.intSuffixBits != 0)
            os << " suffix=" << (t.intSuffixSigned ? 'i' : 'u') << t.intSuffixBits;
        break;
    case TokenKind::FloatLiteral:
        os << " float=" << t.floatValue << (t.floatIsF32 ? " f32" : "");
        break;
    case TokenKind::CharLiteral:
        os << " char=" << t.intValue;
        break;
    case TokenKind::StringLiteral:
        os << " str=" << encodeStringLiteral(t.stringValue);
        break;
    case TokenKind::Error:
        os << " (" << t.stringValue << ')';
        break;
    default:
        break;
    }
    os << '\n';
}

// Shared front end: read + lex + parse. Returns the parsed module, or nullptr
// if anything was reported (diagnostics are printed here).
std::unique_ptr<ast::Module> frontend(const Options &options,
                                      DiagnosticEngine &diags,
                                      std::unique_ptr<llvm::MemoryBuffer> &buffer) {
    buffer = readInput(options.inputPath);
    if (!buffer) return nullptr;

    Lexer lexer(buffer->getBuffer(), diags);
    const std::vector<Token> tokens = lexer.tokenize();
    if (diags.hasErrors()) {
        diags.printAll(llvm::errs());
        return nullptr;
    }

    Parser parser(tokens, diags);
    std::unique_ptr<ast::Module> module = parser.parseModule();
    if (diags.hasErrors()) {
        diags.printAll(llvm::errs());
        return nullptr;
    }
    return module;
}

int runLex(const Options &options) {
    std::unique_ptr<llvm::MemoryBuffer> buffer = readInput(options.inputPath);
    if (!buffer) return 1;

    DiagnosticEngine diags(options.inputPath);
    Lexer lexer(buffer->getBuffer(), diags);
    const std::vector<Token> tokens = lexer.tokenize();

    if (options.dumpTokens) {
        for (const Token &t : tokens) printToken(llvm::outs(), t);
    }

    diags.printAll(llvm::errs());
    return diags.hasErrors() ? 1 : 0;
}

int runParse(const Options &options) {
    DiagnosticEngine diags(options.inputPath);
    std::unique_ptr<llvm::MemoryBuffer> buffer;
    std::unique_ptr<ast::Module> module = frontend(options, diags, buffer);
    if (!module) return 1;

    // Run sema too, so `--dump-ast` shows each expression's resolved type. The
    // dump is still printed on a semantic error (best effort), but the exit
    // code reflects it.
    const bool ok = sema::analyze(*module, diags);
    if (options.dumpAst) ast::printAST(llvm::outs(), *module);
    if (!ok) diags.printAll(llvm::errs());
    return ok ? 0 : 1;
}

// `jocky check`: front end + semantic analysis, no codegen. Silent on success;
// prints diagnostics and exits non-zero on any error.
int runCheck(const Options &options) {
    DiagnosticEngine diags(options.inputPath);
    std::unique_ptr<llvm::MemoryBuffer> buffer;
    std::unique_ptr<ast::Module> module = frontend(options, diags, buffer);
    if (!module) return 1;

    if (!sema::analyze(*module, diags)) {
        diags.printAll(llvm::errs());
        return 1;
    }
    return 0;
}

int runBuild(Options options) {
    // Polymorphic mode: auto-enable the full polymorphic pass suite with a fresh
    // cryptographically random seed, guaranteeing a unique binary every build.
    if (options.polymorphic) {
        options.obfuscate = true;
        if (options.obfuscatePasses.empty())
            options.obfuscatePasses = "strenc,flatten,reorder,indirect,vjunk";
        if (options.obfSeed == 0) {
            std::random_device rd;
            options.obfSeed = (static_cast<std::uint64_t>(rd()) << 32) ^
                               static_cast<std::uint64_t>(rd());
        }
        llvm::errs() << "[polymorphic] seed=" << options.obfSeed << '\n';
    }

    DiagnosticEngine diags(options.inputPath);
    std::unique_ptr<llvm::MemoryBuffer> buffer;
    std::unique_ptr<ast::Module> ast = frontend(options, diags, buffer);
    if (!ast) return 1;

    if (!sema::analyze(*ast, diags)) {
        diags.printAll(llvm::errs());
        return 1;
    }

    auto ctx = std::make_unique<llvm::LLVMContext>();
    const llvm::StringRef moduleName =
        llvm::sys::path::filename(options.inputPath);
    codegen::CodeGen codegen(*ctx, moduleName, diags);
    std::unique_ptr<llvm::Module> module = codegen.lowerModule(*ast);
    if (diags.hasErrors()) {
        diags.printAll(llvm::errs());
        return 1;
    }

    if (options.verifyModule) {
        std::string err;
        llvm::raw_string_ostream os(err);
        if (llvm::verifyModule(*module, &os)) {
            llvm::errs() << "jocky: internal error: the generated IR is invalid:\n"
                         << os.str();
            return 70;
        }
    }

    // --run: JIT-compile and execute without touching disk.
    if (options.runInMemory) {
        const codegen::OptLevel runOpt =
            options.optimize ? codegen::OptLevel::O1 : codegen::OptLevel::O0;
        codegen::ObfuscationOptions runObf;
        runObf.enabled = options.obfuscate;
        runObf.passes = options.obfuscatePasses;
        runObf.seed = options.obfSeed;
        runObf.verbose = options.verbose;

        // initializeNativeTarget + createHostTargetMachine sets the module's
        // triple and data layout, which LLJIT requires before taking ownership.
        codegen::initializeNativeTarget();
        std::unique_ptr<llvm::TargetMachine> runMachine =
            codegen::createHostTargetMachine(*module, runOpt, diags);
        if (!runMachine) {
            diags.printAll(llvm::errs());
            return 70;
        }
        codegen::runTransformPipeline(*module, runMachine.get(), runOpt, runObf);
        return codegen::runInMemory(std::move(module), std::move(ctx), options);
    }

    const codegen::OptLevel opt =
        options.optimize ? codegen::OptLevel::O1 : codegen::OptLevel::O0;

    codegen::ObfuscationOptions obf;
    obf.enabled = options.obfuscate;
    obf.passes = options.obfuscatePasses;
    obf.seed = options.obfSeed;
    obf.verbose = options.verbose;

    if (options.emitLlvm) {
        // Print pre-transform IR unless the user asked for optimization or
        // obfuscation - either of which is a transform they want to see.
        if (options.optimize || obf.enabled)
            codegen::runTransformPipeline(*module, /*machine=*/nullptr, opt, obf);
        module->print(llvm::outs(), nullptr);
        return 0;
    }

    // backend: IR -> object file

    codegen::initializeNativeTarget();
    std::unique_ptr<llvm::TargetMachine> machine =
        codegen::createHostTargetMachine(*module, opt, diags);
    if (!machine) {
        diags.printAll(llvm::errs());
        return 70;
    }

    codegen::runTransformPipeline(*module, machine.get(), opt, obf);

    if (options.emitObj) {
        const std::string objectPath = deriveOutputPath(options, ".obj");
        if (!codegen::emitObjectFile(*module, *machine, objectPath, diags)) {
            diags.printAll(llvm::errs());
            return 1;
        }
        if (options.verbose)
            llvm::errs() << "jocky: wrote " << objectPath << '\n';
        return 0;
    }

    // full build: object file -> linked executable

    const std::string exePath = executableOutputPath(options);

    llvm::SmallString<128> objectPath(exePath);
    llvm::sys::path::replace_extension(objectPath, ".obj");

    if (!codegen::emitObjectFile(*module, *machine, objectPath, diags)) {
        diags.printAll(llvm::errs());
        return 1;
    }

    LinkOptions linkOptions;
    linkOptions.verbose = options.verbose;
    linkOptions.libSearchPaths = options.libSearchPaths;
    linkOptions.libs = options.extraLibs;
    linkOptions.libs.insert(linkOptions.libs.end(), ast->linkLibs.begin(),
                            ast->linkLibs.end());
    const std::string objectPathStr(objectPath.str());
    const bool linked = link({objectPathStr}, exePath, linkOptions);

    if (!options.keepTemps)
        llvm::sys::fs::remove(objectPath);

    if (!linked) return 1;

    if (options.verbose) llvm::errs() << "jocky: wrote " << exePath << '\n';
    return 0;
}

}  // namespace

int Driver::run(const Options &options) {
    switch (options.command) {
    case Command::Lex:
        return runLex(options);
    case Command::Parse:
        return runParse(options);
    case Command::Check:
        return runCheck(options);
    case Command::Build:
        return runBuild(options);
    case Command::None:
        llvm::errs() << "jocky: no command given (try `jocky --help`)\n";
        return 2;
    }
    return 2;  // unreachable
}

}  // namespace jocky::driver
