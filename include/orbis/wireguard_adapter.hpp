// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - WireGuard tunnel adapter
#pragma once

#include "orbis/tunnel_plugin.hpp"
#include "orbis/wireguard_config.hpp"
#include <atomic>
#include <mutex>

namespace orbis::wireguard {

/// Binding seam to an actual WireGuard implementation. ORBIS Engine does
/// not implement the WireGuard protocol or its cryptography itself;
/// production builds must supply a backend that wraps a vetted
/// implementation such as BoringTun (Rust, via FFI) or wireguard-go
/// (via cgo bindings), both of which use standard, audited Noise/Curve25519
/// primitives. See docs/SECURITY.md for the backend integration contract.
class IBackend {
public:
    virtual ~IBackend() = default;
    virtual bool start(const InterfaceConfig& config) = 0;
    virtual void stop() = 0;
    virtual bool isRunning() const = 0;
    virtual TunnelStats statistics() const = 0;
};

/// Adapts a WireGuard IBackend to the engine-wide ITunnelPlugin interface.
/// This class contains no cryptography and no protocol logic of its own —
/// it validates configuration shape and delegates lifecycle calls to the
/// injected backend.
class WireGuardAdapter final : public ITunnelPlugin {
public:
    /// Constructs with a specific backend (dependency injection; used by
    /// tests). The zero-arg constructor required by PluginRegistrar uses
    /// a backend resolved via defaultBackend().
    explicit WireGuardAdapter(std::unique_ptr<IBackend> backend = nullptr);
    ~WireGuardAdapter() override;

    std::string_view protocolName() const override;
    TunnelResult configure(std::string_view protocolConfig) override;
    TunnelResult open() override;
    TunnelResult close() override;
    bool isOpen() const override;
    TunnelStats statistics() const override;

private:
    static std::unique_ptr<IBackend> defaultBackend();

    mutable std::mutex mutex_;
    std::unique_ptr<IBackend> backend_;
    InterfaceConfig config_;
    bool configured_ = false;
};

} // namespace orbis::wireguard
