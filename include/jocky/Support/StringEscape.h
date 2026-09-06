// Turning the text of a string literal into the bytes it stands for, and back.
//
// Shared so the lexer and any tooling/tests agree on exactly which escape
// sequences JOCKY understands: \n \t \r \\ \" \' \0

#ifndef JOCKY_SUPPORT_STRINGESCAPE_H
#define JOCKY_SUPPORT_STRINGESCAPE_H

#include <cstddef>
#include <string>

#include <llvm/ADT/StringRef.h>

namespace jocky {

// Decodes escape sequences in `body` (the text between the quotes) into `out`.
// On success returns true. On an unknown or truncated escape returns false and,
// if `errorOffset` is non-null, stores the byte offset of the backslash in `body`.
bool decodeStringEscapes(llvm::StringRef body, std::string &out,
                         std::size_t *errorOffset);

// The inverse: wraps `bytes` in double quotes and turns the special characters
// back into escape sequences. Used for readable, single-line debug output.
std::string encodeStringLiteral(llvm::StringRef bytes);

}  // namespace jocky

#endif  // JOCKY_SUPPORT_STRINGESCAPE_H
