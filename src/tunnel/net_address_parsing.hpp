// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - shared WireGuard config parsing helpers
//
// Pure parsing/resolution utilities with no platform-specific tunnel
// logic. Both the Linux netlink backend and the Windows wireguard-nt
// backend use these to avoid duplicating CIDR/endpoint parsing.
#pragma once

#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

namespace orbis::net_parse {

struct ParsedCidr {
    int family = 0;                    // AF_INET or AF_INET6
    std::array<std::uint8_t, 16> addr{};
    std::uint8_t prefix = 0;
};

/// Parses "10.0.0.0/24" or "::/0" style CIDR strings.
inline std::optional<ParsedCidr> parseCidr(const std::string& cidr) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) return std::nullopt;
    std::string addrPart = cidr.substr(0, slash);
    std::string prefixPart = cidr.substr(slash + 1);

    std::uint8_t prefix = 0;
    auto res = std::from_chars(prefixPart.data(), prefixPart.data() + prefixPart.size(), prefix);
    if (res.ec != std::errc{}) return std::nullopt;

    ParsedCidr out{};
    out.prefix = prefix;
    if (addrPart.find(':') != std::string::npos) {
        out.family = AF_INET6;
        if (inet_pton(AF_INET6, addrPart.c_str(), out.addr.data()) != 1) return std::nullopt;
    } else {
        out.family = AF_INET;
        if (inet_pton(AF_INET, addrPart.c_str(), out.addr.data()) != 1) return std::nullopt;
    }
    return out;
}

/// Splits "host:port" ("[::1]:51820" for IPv6 literals) into parts.
inline std::optional<std::pair<std::string, std::uint16_t>> splitHostPort(const std::string& endpoint) {
    std::string host;
    std::string portStr;
    if (!endpoint.empty() && endpoint.front() == '[') {
        auto close = endpoint.find(']');
        if (close == std::string::npos) return std::nullopt;
        host = endpoint.substr(1, close - 1);
        if (close + 1 >= endpoint.size() || endpoint[close + 1] != ':') return std::nullopt;
        portStr = endpoint.substr(close + 2);
    } else {
        auto colon = endpoint.rfind(':');
        if (colon == std::string::npos) return std::nullopt;
        host = endpoint.substr(0, colon);
        portStr = endpoint.substr(colon + 1);
    }
    std::uint16_t port = 0;
    auto res = std::from_chars(portStr.data(), portStr.data() + portStr.size(), port);
    if (res.ec != std::errc{}) return std::nullopt;
    return std::make_pair(host, port);
}

/// Resolves "host:port" to a sockaddr_storage via getaddrinfo. Plain DNS
/// resolution, performed once at configure time (matching wg-quick),
/// not part of the WireGuard protocol itself.
inline bool resolveEndpoint(const std::string& endpoint, sockaddr_storage& out, std::size_t& outLen) {
    auto parts = splitHostPort(endpoint);
    if (!parts) return false;
    auto& [host, port] = *parts;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* result = nullptr;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result) != 0 || !result) {
        return false;
    }
    std::memcpy(&out, result->ai_addr, result->ai_addrlen);
    outLen = static_cast<std::size_t>(result->ai_addrlen);
    freeaddrinfo(result);
    return true;
}

} // namespace orbis::net_parse
