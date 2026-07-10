// SPDX-License-Identifier: Apache-2.0
// Example: bring up a real WireGuard tunnel via ORBIS Engine's plugin
// registry. On Linux with root/CAP_NET_ADMIN and a WireGuard-capable
// kernel, this creates an actual network interface. Elsewhere (or
// without privileges) it reports a clear error rather than pretending
// to succeed.
#include "orbis/plugin_registry.hpp"
#include "orbis/wireguard_adapter.hpp"
#include <cstdio>

int main() {
    auto plugin = orbis::TunnelPluginRegistry::instance().create("wireguard");
    if (!plugin) {
        std::fprintf(stderr, "wireguard plugin not registered\n");
        return 1;
    }

    // Replace with a real private key and peer public key generated via
    // `wg genkey` / `wg pubkey`. These placeholders will be rejected by
    // the kernel as invalid Curve25519 keys.
    constexpr std::string_view config =
        "[Interface]\n"
        "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 10.0.0.2/32\n"
        "\n"
        "[Peer]\n"
        "PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "Endpoint = vpn.example.com:51820\n"
        "PersistentKeepalive = 25\n";

    if (plugin->configure(config) != orbis::TunnelResult::Success) {
        std::fprintf(stderr, "invalid configuration\n");
        return 1;
    }

    auto result = plugin->open();
    if (result != orbis::TunnelResult::Success) {
        std::fprintf(stderr,
            "failed to open tunnel (code %d) — see log output above; "
            "common causes: not root, kernel lacks CONFIG_WIREGUARD, "
            "or invalid keys\n", static_cast<int>(result));
        return 1;
    }

    std::printf("tunnel is up\n");
    auto stats = plugin->statistics();
    std::printf("rx=%llu tx=%llu\n",
        static_cast<unsigned long long>(stats.bytesReceived),
        static_cast<unsigned long long>(stats.bytesSent));

    plugin->close();
    return 0;
}

