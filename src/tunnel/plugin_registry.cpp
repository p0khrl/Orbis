// SPDX-License-Identifier: Apache-2.0
#include "orbis/plugin_registry.hpp"
#include <mutex>
#include <unordered_map>
#include <string>

namespace orbis {

struct TunnelPluginRegistry::Impl {
    mutable std::mutex mutex;
    std::unordered_map<std::string, TunnelPluginFactory> factories;
};

TunnelPluginRegistry::TunnelPluginRegistry() : pImpl(std::make_unique<Impl>()) {}
TunnelPluginRegistry::~TunnelPluginRegistry() = default;

TunnelPluginRegistry& TunnelPluginRegistry::instance() {
    static TunnelPluginRegistry registry;
    return registry;
}

void TunnelPluginRegistry::registerPlugin(std::string_view name, TunnelPluginFactory factory) {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    pImpl->factories[std::string(name)] = factory;
}

std::unique_ptr<ITunnelPlugin> TunnelPluginRegistry::create(std::string_view name) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    auto it = pImpl->factories.find(std::string(name));
    if (it == pImpl->factories.end()) return nullptr;
    return it->second();
}

bool TunnelPluginRegistry::has(std::string_view name) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    return pImpl->factories.contains(std::string(name));
}

} // namespace orbis
