// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - Windows WireGuardNT backend
#pragma once
#ifdef _WIN32

#include "orbis/wireguard_adapter.hpp"
#include "wireguard_nt_api.h"
#include <string>

namespace orbis::windows_detail {

/// Real WireGuard backend for Windows, embedding WireGuardNT via
/// wireguard.dll — the officially supported way for third-party
/// applications to bake WireGuard into a Windows program (see
/// WireGuard/wireguard-nt's README: "the embeddable DLL service
/// project"). This class contains no cryptography: it loads
/// wireguard.dll at runtime, creates a kernel adapter, and pushes
/// configuration through WireGuardSetConfiguration exactly as the
/// official WireGuard for Windows app does internally.
///
/// Requires:
///  - wireguard.dll present next to the executable (or on PATH),
///    downloaded from the wireguard-nt download server — ORBIS Engine
///    does not vendor or redistribute the DLL itself.
///  - Administrator privileges (driver/adapter installation).
///
/// IP address assignment is handled separately via the IP Helper API
/// (CreateUnicastIpAddressEntry) keyed off the adapter's LUID, since
/// WireGuardNT's own API only configures WireGuard protocol state
/// (keys/peers/listen port), not IP addressing.
class WireGuardNtBackend final : public orbis::wireguard::IBackend {
public:
    explicit WireGuardNtBackend(std::wstring adapterName = L"ORBIS");
    ~WireGuardNtBackend() override;

    bool start(const orbis::wireguard::InterfaceConfig& config) override;
    void stop() override;
    bool isRunning() const override;
    orbis::TunnelStats statistics() const override;

private:
    bool loadLibraryAndResolveSymbols();
    bool assignAddresses(const orbis::wireguard::InterfaceConfig& config);

    std::wstring adapterName_;
    HMODULE dll_ = nullptr;
    WIREGUARD_ADAPTER_HANDLE adapter_ = nullptr;
    bool running_ = false;

    WIREGUARD_CREATE_ADAPTER_FUNC createAdapter_ = nullptr;
    WIREGUARD_CLOSE_ADAPTER_FUNC closeAdapter_ = nullptr;
    WIREGUARD_SET_ADAPTER_STATE_FUNC setAdapterState_ = nullptr;
    WIREGUARD_SET_CONFIGURATION_FUNC setConfiguration_ = nullptr;
    WIREGUARD_GET_CONFIGURATION_FUNC getConfiguration_ = nullptr;
    WIREGUARD_GET_ADAPTER_LUID_FUNC getAdapterLuid_ = nullptr;
};

} // namespace orbis::windows_detail

#endif // _WIN32
