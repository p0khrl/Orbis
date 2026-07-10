// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - base64 decode (data-encoding utility, not cryptography)
#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace orbis::util {

/// Decodes standard base64 (RFC 4648) into exactly `N` bytes, failing if
/// the input doesn't decode to precisely that length. Used to turn
/// WireGuard's base64 key text into raw 32-byte keys for the kernel API.
template <std::size_t N>
std::optional<std::array<std::uint8_t, N>> base64DecodeFixed(std::string_view text) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::array<std::uint8_t, N> out{};
    std::size_t outPos = 0;
    int bits = 0;
    int nbits = 0;

    std::size_t len = text.size();
    while (len > 0 && text[len - 1] == '=') --len;

    for (std::size_t i = 0; i < len; ++i) {
        int v = value(text[i]);
        if (v < 0) return std::nullopt;
        bits = (bits << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (outPos >= N) return std::nullopt; // too long
            out[outPos++] = static_cast<std::uint8_t>((bits >> nbits) & 0xFF);
        }
    }
    if (outPos != N) return std::nullopt;
    return out;
}

} // namespace orbis::util
