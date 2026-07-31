// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - WireGuard configuration model
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace orbis::wireguard {

/// A single peer entry, mirroring the fields of a standard WireGuard
/// [Peer] section. Keys are base64-encoded 32-byte Curve25519 keys,
/// exactly as produced by `wg genkey` / `wg pubkey`.
struct PeerConfig {
    std::string publicKey;
    std::optional<std::string> presharedKey;
    std::string endpoint;                 // "host:port"
    std::vector<std::string> allowedIps;  // CIDR notation
    std::uint16_t persistentKeepalive = 0; // seconds; 0 = disabled
};

/// Mirrors a standard WireGuard [Interface] section plus the peer list.
/// Validation (key length/format, CIDR syntax, etc.) happens in
/// WireGuardAdapter::configure(), not here — this is a plain data holder.
struct InterfaceConfig {
    std::string privateKey;
    std::vector<std::string> addresses;   // interface IPs, CIDR notation
    std::uint16_t listenPort = 0;         // 0 = OS-assigned
    std::optional<std::uint16_t> mtu;
    std::optional<std::uint32_t> fwmark;  // firewall mark for policy routing; 0/unset = disabled
    std::vector<std::string> dns;
    std::vector<PeerConfig> peers;
};

} // namespace orbis::wireguard
