// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - Linux kernel WireGuard backend
#pragma once
#ifdef __linux__

#include "orbis/wireguard_adapter.hpp"
#include <string>

namespace orbis::linux_detail {

/// Real WireGuard backend for Linux, targeting the kernel's in-tree
/// WireGuard implementation (mainline since Linux 5.6). This class
/// contains no cryptography: it configures the kernel module over
/// netlink exactly as the official `wg`/`wg-quick` tools do, and the
/// kernel performs all handshakes and packet encryption/decryption.
///
/// Requires:
///  - a kernel with CONFIG_WIREGUARD (module or built-in)
///  - CAP_NET_ADMIN (typically root)
///
/// This backend creates a real network interface, assigns addresses,
/// configures the kernel WireGuard device, and brings the link up. It
/// deliberately does NOT install default/catch-all routes automatically
/// (that policy decision belongs to a higher-level split-tunneling /
/// kill-switch component in src/network, not the tunnel adapter).
class KernelWireGuardBackend final : public orbis::wireguard::IBackend {
public:
    explicit KernelWireGuardBackend(std::string interfaceName = "orbis0");
    ~KernelWireGuardBackend() override;

    bool start(const orbis::wireguard::InterfaceConfig& config) override;
    void stop() override;
    bool isRunning() const override;
    orbis::TunnelStats statistics() const override;

private:
    bool createLink();
    bool deleteLink();
    bool configureDevice(const orbis::wireguard::InterfaceConfig& config);
    bool assignAddresses(const orbis::wireguard::InterfaceConfig& config);
    bool setLinkUp();

    std::string ifname_;
    bool running_ = false;
};

} // namespace orbis::linux_detail

#endif // __linux__
