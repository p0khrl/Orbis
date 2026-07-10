// SPDX-License-Identifier: Apache-2.0
// Registers WireGuardAdapter under the "wireguard" protocol name.
#include "orbis/plugin_registry.hpp"
#include "orbis/wireguard_adapter.hpp"

namespace orbis::wireguard {
namespace {
PluginRegistrar<WireGuardAdapter> registrar("wireguard");
} // namespace
} // namespace orbis::wireguard
