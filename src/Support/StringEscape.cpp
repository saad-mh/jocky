#include "jocky/Support/StringEscape.h"

namespace jocky {

bool decodeStringEscapes(llvm::StringRef body, std::string &out,
                         std::size_t *errorOffset) {
    out.clear();
    out.reserve(body.size());

    for (std::size_t i = 0; i < body.size(); ++i) {
        const char c = body[i];
        if (c != '\\') {
            out.push_back(c);
            continue;
        }

        // c is a backslash; it must be followed by one escape character.
        if (i + 1 >= body.size()) {
            if (errorOffset) *errorOffset = i;
            return false;
        }

        const char e = body[++i];
        switch (e) {
        case 'n': out.push_back('\n'); break;
        case 't': out.push_back('\t'); break;
        case 'r': out.push_back('\r'); break;
        case '\\': out.push_back('\\'); break;
        case '"': out.push_back('"'); break;
        case '\'': out.push_back('\''); break;
        case '0': out.push_back('\0'); break;
        default:
            if (errorOffset) *errorOffset = i - 1;  // point at the backslash
            return false;
        }
    }
    return true;
}

std::string encodeStringLiteral(llvm::StringRef bytes) {
    std::string out;
    out.reserve(bytes.size() + 2);
    out.push_back('"');
    for (const char c : bytes) {
        switch (c) {
        case '\n': out += "\\n"; break;
        case '\t': out += "\\t"; break;
        case '\r': out += "\\r"; break;
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\0': out += "\\0"; break;
        default: out.push_back(c); break;
        }
    }
    out.push_back('"');
    return out;
}

}  // namespace jocky
