#include "SecureMem.h"

#include <openssl/crypto.h> // OPENSSL_cleanse
#include <cctype>

void secureClear(std::vector<unsigned char>& v) {
    if (!v.empty()) {
        // Overwrite the buffer to avoid leaving sensitive data in memory.
        OPENSSL_cleanse(v.data(), v.size());
        v.clear();
        v.shrink_to_fit();
    }
}

static inline int hexCharToVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);

    // Parse characters, ignoring whitespace
    std::string cleaned;
    cleaned.reserve(hex.size());
    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) cleaned.push_back(c);
    }

    // Allow optional leading 0x/0X
    if (cleaned.size() >= 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
        cleaned = cleaned.substr(2);
    }

    if (cleaned.size() % 2 != 0) return {}; // invalid hex length

    for (size_t i = 0; i < cleaned.size(); i += 2) {
        int hi = hexCharToVal(cleaned[i]);
        int lo = hexCharToVal(cleaned[i+1]);
        if (hi < 0 || lo < 0) return {}; // invalid character
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }

    return out;
}
