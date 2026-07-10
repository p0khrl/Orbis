// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - Tunnel plugin registry
#pragma once

#include "orbis/tunnel_plugin.hpp"
#include <optional>

namespace orbis {

/// Process-wide registry mapping protocol names to plugin factories.
/// Built-in protocols (WireGuard, OpenVPN) register themselves at
/// static-init time; external plugins call registerPlugin() explicitly.
///
/// Thread-safe: registration and lookup may happen concurrently.
class TunnelPluginRegistry {
public:
    static TunnelPluginRegistry& instance();

    /// Registers a factory under `name`. Re-registering the same name
    /// overwrites the previous factory (last one wins), which allows
    /// applications to override built-ins for testing.
    void registerPlugin(std::string_view name, TunnelPluginFactory factory);

    /// Instantiates a plugin by protocol name, or nullopt if unknown.
    std::unique_ptr<ITunnelPlugin> create(std::string_view name) const;

    /// True if a factory is registered for `name`.
    bool has(std::string_view name) const;

private:
    TunnelPluginRegistry();
    ~TunnelPluginRegistry();
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

/// RAII helper: construct as a static/global to self-register a plugin
/// at load time, e.g.:
///   static PluginRegistrar<WireGuardAdapter> registrar("wireguard");
template <typename PluginT>
struct PluginRegistrar {
    explicit PluginRegistrar(std::string_view name) {
        TunnelPluginRegistry::instance().registerPlugin(
            name, +[]() -> std::unique_ptr<ITunnelPlugin> {
                return std::make_unique<PluginT>();
            });
    }
};

} // namespace orbis
