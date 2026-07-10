// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>
#include "orbis/plugin_registry.hpp"
#include "orbis/wireguard_adapter.hpp"

using namespace orbis;
using namespace orbis::wireguard;

TEST(PluginRegistryTest, WireGuardIsRegisteredByDefault) {
    EXPECT_TRUE(TunnelPluginRegistry::instance().has("wireguard"));
}

TEST(PluginRegistryTest, UnknownProtocolReturnsNull) {
    EXPECT_EQ(TunnelPluginRegistry::instance().create("not-a-real-protocol"), nullptr);
}

TEST(PluginRegistryTest, CreateReturnsWireGuardAdapter) {
    auto plugin = TunnelPluginRegistry::instance().create("wireguard");
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->protocolName(), "wireguard");
}

namespace {
constexpr std::string_view kValidConfig =
    "[Interface]\n"
    "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    "Address = 10.0.0.2/32\n"
    "\n"
    "[Peer]\n"
    "PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
    "AllowedIPs = 0.0.0.0/0\n"
    "Endpoint = vpn.example.com:51820\n";

// Note: keys above are illustrative placeholders sized to 44 chars to
// satisfy format validation; they are not real WireGuard keys.
} // namespace

TEST(WireGuardAdapterTest, RejectsMalformedConfig) {
    WireGuardAdapter adapter;
    EXPECT_EQ(adapter.configure("not a valid config"), TunnelResult::InvalidConfig);
}

TEST(WireGuardAdapterTest, RejectsConfigWithoutPeers) {
    WireGuardAdapter adapter;
    constexpr std::string_view noPeers =
        "[Interface]\n"
        "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 10.0.0.2/32\n";
    EXPECT_EQ(adapter.configure(noPeers), TunnelResult::InvalidConfig);
}

TEST(WireGuardAdapterTest, OpenFailsWithoutConfigure) {
    WireGuardAdapter adapter;
    EXPECT_EQ(adapter.open(), TunnelResult::InvalidConfig);
}

namespace {
/// Fake backend for unit-testing WireGuardAdapter's lifecycle logic in
/// isolation from any real OS networking. Unlike the platform default
/// backend (real kernel WireGuard on Linux), this never touches the
/// network and always succeeds, so these tests run identically on any
/// machine/CI runner regardless of privileges or kernel support.
class FakeBackend final : public IBackend {
public:
    bool start(const InterfaceConfig&) override { running_ = true; return true; }
    void stop() override { running_ = false; }
    bool isRunning() const override { return running_; }
    TunnelStats statistics() const override { return {}; }

private:
    bool running_ = false;
};
} // namespace

TEST(WireGuardAdapterTest, ValidConfigThenOpenCloseSucceeds) {
    WireGuardAdapter adapter(std::make_unique<FakeBackend>());
    ASSERT_EQ(adapter.configure(kValidConfig), TunnelResult::Success);
    EXPECT_EQ(adapter.open(), TunnelResult::Success);
    EXPECT_TRUE(adapter.isOpen());
    EXPECT_EQ(adapter.open(), TunnelResult::AlreadyConnected);
    EXPECT_EQ(adapter.close(), TunnelResult::Success);
    EXPECT_FALSE(adapter.isOpen());
    EXPECT_EQ(adapter.close(), TunnelResult::NotConnected);
}

// --- Real kernel backend integration test (Linux only, opt-in) ---------
//
// Exercises the actual netlink path against the running kernel. Disabled
// by default (GTest "DISABLED_" prefix) because it requires root/
// CAP_NET_ADMIN and a kernel with CONFIG_WIREGUARD, neither of which are
// guaranteed on a CI runner or in this sandbox. Run explicitly with:
//   orbis_tests --gtest_also_run_disabled_tests
//       --gtest_filter=WireGuardKernelIntegration.*
#ifdef __linux__
TEST(WireGuardKernelIntegration, DISABLED_RealInterfaceLifecycle) {
    WireGuardAdapter adapter; // uses the real KernelWireGuardBackend on Linux
    ASSERT_EQ(adapter.configure(kValidConfig), TunnelResult::Success);
    EXPECT_EQ(adapter.open(), TunnelResult::Success);
    EXPECT_TRUE(adapter.isOpen());
    EXPECT_EQ(adapter.close(), TunnelResult::Success);
}
#endif

// Windows: exercises the real WireGuardNtBackend (wireguard.dll). Disabled
// by default because it requires wireguard.dll to be present next to the
// test binary and Administrator privileges. Run explicitly with:
//   orbis_tests.exe --gtest_also_run_disabled_tests
//       --gtest_filter=WireGuardNtIntegration.*
#ifdef _WIN32
TEST(WireGuardNtIntegration, DISABLED_RealInterfaceLifecycle) {
    WireGuardAdapter adapter; // uses the real WireGuardNtBackend on Windows
    ASSERT_EQ(adapter.configure(kValidConfig), TunnelResult::Success);
    EXPECT_EQ(adapter.open(), TunnelResult::Success);
    EXPECT_TRUE(adapter.isOpen());
    EXPECT_EQ(adapter.close(), TunnelResult::Success);
}
#endif
