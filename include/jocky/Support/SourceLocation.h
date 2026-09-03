// A place in a source file. Every token and AST node carries one so error
// messages can point at the right spot.

#ifndef JOCKY_SUPPORT_SOURCELOCATION_H
#define JOCKY_SUPPORT_SOURCELOCATION_H

#include <cstdint>

namespace jocky {

struct SourceLocation {
    std::uint32_t line = 0;    // 1-based line number; 0 means "unknown"
    std::uint32_t column = 0;  // 1-based column number
};

}  // namespace jocky

#endif  // JOCKY_SUPPORT_SOURCELOCATION_H
