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
#include "jocky/codegen/ObjectEmitter.h"
#include "jocky/codegen/PassPipeline.h"
#include "jocky/lexer/Lexer.h"
#include "jocky/lexer/Token.h"
#include "jocky/parser/Parser.h"

#include <llvm/ADT/SmallString.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>

#include <memory>
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

    if (options.dumpAst) ast::printAST(llvm::outs(), *module);
    return 0;
}

int runBuild(const Options &options) {
    DiagnosticEngine diags(options.inputPath);
    std::unique_ptr<llvm::MemoryBuffer> buffer;
    std::unique_ptr<ast::Module> ast = frontend(options, diags, buffer);
    if (!ast) return 1;

    llvm::LLVMContext context;
    const llvm::StringRef moduleName =
        llvm::sys::path::filename(options.inputPath);
    codegen::CodeGen codegen(context, moduleName, diags);
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

    const codegen::OptLevel opt =
        options.optimize ? codegen::OptLevel::O1 : codegen::OptLevel::O0;

    if (options.emitLlvm) {
        // Print pre-transform IR unless the user also asked for optimization.
        if (options.optimize)
            codegen::runTransformPipeline(*module, /*machine=*/nullptr, opt);
        module->print(llvm::outs(), nullptr);
        return 0;
    }

    // --- backend: IR -> object file -------------------------------------

    codegen::initializeNativeTarget();
    std::unique_ptr<llvm::TargetMachine> machine =
        codegen::createHostTargetMachine(*module, opt, diags);
    if (!machine) {
        diags.printAll(llvm::errs());
        return 70;
    }

    codegen::runTransformPipeline(*module, machine.get(), opt);

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

    llvm::errs() << "jocky: linking is not implemented yet; "
                    "pass --emit-obj to stop at the object file\n";
    return 1;
}

}  // namespace

int Driver::run(const Options &options) {
    switch (options.command) {
    case Command::Lex:
        return runLex(options);
    case Command::Parse:
        return runParse(options);
    case Command::Build:
        return runBuild(options);
    case Command::None:
        llvm::errs() << "jocky: no command given (try `jocky --help`)\n";
        return 2;
    }
    return 2;  // unreachable
}

}  // namespace jocky::driver
