// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - Tunnel plugin interface
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace orbis {

/// Result of a tunnel operation. Kept simple and explicit rather than
/// throwing, so plugin authors don't need exception-safety guarantees.
enum class TunnelResult {
    Success,
    InvalidConfig,
    ConnectFailed,
    AlreadyConnected,
    NotConnected,
    IoError
};

/// Snapshot of tunnel-level traffic counters. Aggregated by Engine into
/// the public Statistics type.
struct TunnelStats {
    std::uint64_t bytesSent = 0;
    std::uint64_t bytesReceived = 0;
    std::uint64_t handshakes = 0;
};

/// ITunnelPlugin is the extension point protocols implement to plug into
/// ORBIS Engine without modifying core code.
///
/// Implementations MUST:
///  - delegate all cryptographic operations to a vetted library
///    (e.g. a WireGuard userspace implementation, OpenSSL) — never
///    implement cryptographic primitives directly.
///  - be safe to destroy from any state (destructor tears down cleanly).
///
/// Threading: the Engine invokes these methods serially; implementations
/// are responsible for their own internal thread-safety if they spawn
/// background I/O threads.
class ITunnelPlugin {
public:
    virtual ~ITunnelPlugin() = default;

    /// Short, stable identifier used for plugin registration (e.g. "wireguard").
    virtual std::string_view protocolName() const = 0;

    /// Parses and validates a protocol-specific configuration blob
    /// (already extracted from the engine's Configuration object).
    /// Returns InvalidConfig without side effects if malformed.
    virtual TunnelResult configure(std::string_view protocolConfig) = 0;

    /// Brings the tunnel up. Blocking call; Engine runs it off the
    /// caller's thread if async behavior is desired.
    virtual TunnelResult open() = 0;

    /// Tears the tunnel down. Idempotent — safe to call when not connected.
    virtual TunnelResult close() = 0;

    /// True if the underlying tunnel interface is currently up.
    virtual bool isOpen() const = 0;

    virtual TunnelStats statistics() const = 0;
};

/// Factory signature registered plugins must provide.
using TunnelPluginFactory = std::unique_ptr<ITunnelPlugin> (*)();

} // namespace orbis
