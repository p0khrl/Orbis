// SPDX-License-Identifier: Apache-2.0
#ifdef _WIN32
#include "wireguard_nt_backend.hpp"
#include "../../tunnel/net_address_parsing.hpp"
#include "orbis/base64.hpp"
#include "orbis/logger.hpp"

#include <iphlpapi.h>
#include <mutex>
#include <vector>

#if defined(_MSC_VER)
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

using orbis::wireguard::InterfaceConfig;
using orbis::wireguard::PeerConfig;
using orbis::net_parse::parseCidr;
using orbis::net_parse::resolveEndpoint;

namespace orbis::windows_detail {

namespace {

/// WireGuardNT (like any Winsock consumer) needs WSAStartup called once
/// per process before getaddrinfo() is usable; this has nothing to do
/// with the VPN protocol itself.
void ensureWinsockInitialized() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    });
}

} // namespace

WireGuardNtBackend::WireGuardNtBackend(std::wstring adapterName)
    : adapterName_(std::move(adapterName)) {
    ensureWinsockInitialized();
}

WireGuardNtBackend::~WireGuardNtBackend() {
    if (running_) stop();
    if (dll_) FreeLibrary(dll_);
}

bool WireGuardNtBackend::loadLibraryAndResolveSymbols() {
    // wireguard.dll is intentionally not vendored/redistributed by ORBIS
    // Engine — applications must ship it alongside their executable per
    // WireGuard LLC's distribution terms (download from the wireguard-nt
    // download server).
    dll_ = LoadLibraryExW(L"wireguard.dll", nullptr,
                           LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!dll_) {
        Logger::log(LogLevel::Error,
            "WireGuardNT: failed to load wireguard.dll (place it next to the "
            "executable — see docs/PLATFORM_STATUS.md)");
        return false;
    }

    auto resolve = [&](const char* name) -> FARPROC {
        FARPROC proc = GetProcAddress(dll_, name);
        if (!proc) {
            Logger::log(LogLevel::Error, std::string("WireGuardNT: missing export ") + name);
        }
        return proc;
    };

    // GetProcAddress returns a bare FARPROC; casting it to a specific
    // function pointer type is the standard (and only) way to use it in
    // C++, and unavoidably trips -Wcast-function-type. Scoped narrowly
    // here rather than disabled for the whole file/project.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4191) // 'reinterpret_cast': unsafe conversion between function pointer types
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
    createAdapter_ = reinterpret_cast<WIREGUARD_CREATE_ADAPTER_FUNC>(resolve("WireGuardCreateAdapter"));
    closeAdapter_ = reinterpret_cast<WIREGUARD_CLOSE_ADAPTER_FUNC>(resolve("WireGuardCloseAdapter"));
    setAdapterState_ = reinterpret_cast<WIREGUARD_SET_ADAPTER_STATE_FUNC>(resolve("WireGuardSetAdapterState"));
    setConfiguration_ = reinterpret_cast<WIREGUARD_SET_CONFIGURATION_FUNC>(resolve("WireGuardSetConfiguration"));
    getConfiguration_ = reinterpret_cast<WIREGUARD_GET_CONFIGURATION_FUNC>(resolve("WireGuardGetConfiguration"));
    getAdapterLuid_ = reinterpret_cast<WIREGUARD_GET_ADAPTER_LUID_FUNC>(resolve("WireGuardGetAdapterLUID"));
#if defined(_MSC_VER)
#pragma warning(pop)
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    return createAdapter_ && closeAdapter_ && setAdapterState_ && setConfiguration_
        && getConfiguration_ && getAdapterLuid_;
}

bool WireGuardNtBackend::assignAddresses(const InterfaceConfig& config) {
    NET_LUID luid{};
    getAdapterLuid_(adapter_, &luid);

    for (const auto& addrCidr : config.addresses) {
        auto cidr = parseCidr(addrCidr);
        if (!cidr) {
            Logger::log(LogLevel::Error, "WireGuardNT: invalid interface Address entry");
            return false;
        }

        MIB_UNICASTIPADDRESS_ROW row;
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = luid;
        row.OnLinkPrefixLength = cidr->prefix;

        if (cidr->family == AF_INET) {
            row.Address.Ipv4.sin_family = AF_INET;
            std::memcpy(&row.Address.Ipv4.sin_addr, cidr->addr.data(), 4);
        } else {
            row.Address.Ipv6.sin6_family = AF_INET6;
            std::memcpy(&row.Address.Ipv6.sin6_addr, cidr->addr.data(), 16);
        }

        DWORD result = CreateUnicastIpAddressEntry(&row);
        if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
            Logger::log(LogLevel::Error, "WireGuardNT: CreateUnicastIpAddressEntry failed");
            return false;
        }
    }
    return true;
}

bool WireGuardNtBackend::start(const InterfaceConfig& config) {
    if (running_) return true;

    if (!dll_ && !loadLibraryAndResolveSymbols()) return false;

    adapter_ = createAdapter_(adapterName_.c_str(), L"WireGuard", nullptr);
    if (!adapter_) {
        Logger::log(LogLevel::Error,
            "WireGuardNT: WireGuardCreateAdapter failed (need Administrator?)");
        return false;
    }

    auto privKey = util::base64DecodeFixed<WIREGUARD_KEY_LENGTH>(config.privateKey);
    if (!privKey) {
        Logger::log(LogLevel::Error, "WireGuardNT: private key failed to decode to 32 bytes");
        closeAdapter_(adapter_);
        adapter_ = nullptr;
        return false;
    }

    // Build the variable-length WIREGUARD_INTERFACE + peers + allowed-ips
    // buffer exactly as WireGuardSetConfiguration requires: one
    // WIREGUARD_INTERFACE, followed by PeersCount WIREGUARD_PEER structs,
    // each immediately followed by that peer's AllowedIPsCount
    // WIREGUARD_ALLOWED_IP structs, all contiguous.
    std::vector<std::uint8_t> buf(sizeof(WIREGUARD_INTERFACE));
    auto* iface = reinterpret_cast<WIREGUARD_INTERFACE*>(buf.data());
    std::memset(iface, 0, sizeof(*iface));
    iface->Flags = static_cast<WIREGUARD_INTERFACE_FLAG>(
        WIREGUARD_INTERFACE_HAS_PRIVATE_KEY | WIREGUARD_INTERFACE_REPLACE_PEERS);
    std::memcpy(iface->PrivateKey, privKey->data(), WIREGUARD_KEY_LENGTH);
    if (config.listenPort != 0) {
        iface->Flags = static_cast<WIREGUARD_INTERFACE_FLAG>(iface->Flags | WIREGUARD_INTERFACE_HAS_LISTEN_PORT);
        iface->ListenPort = config.listenPort;
    }
    iface->PeersCount = static_cast<DWORD>(config.peers.size());

    for (const auto& peer : config.peers) {
        auto pubKey = util::base64DecodeFixed<WIREGUARD_KEY_LENGTH>(peer.publicKey);
        if (!pubKey) {
            Logger::log(LogLevel::Error, "WireGuardNT: peer public key failed to decode to 32 bytes");
            closeAdapter_(adapter_);
            adapter_ = nullptr;
            return false;
        }

        std::size_t peerOffset = buf.size();
        buf.resize(buf.size() + sizeof(WIREGUARD_PEER));
        // Re-fetch iface pointer: buf may have reallocated.
        iface = reinterpret_cast<WIREGUARD_INTERFACE*>(buf.data());
        auto* peerStruct = reinterpret_cast<WIREGUARD_PEER*>(buf.data() + peerOffset);
        std::memset(peerStruct, 0, sizeof(*peerStruct));
        peerStruct->Flags = static_cast<WIREGUARD_PEER_FLAG>(
            WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_REPLACE_ALLOWED_IPS);
        std::memcpy(peerStruct->PublicKey, pubKey->data(), WIREGUARD_KEY_LENGTH);

        if (peer.presharedKey) {
            auto psk = util::base64DecodeFixed<WIREGUARD_KEY_LENGTH>(*peer.presharedKey);
            if (!psk) {
                Logger::log(LogLevel::Error, "WireGuardNT: preshared key failed to decode to 32 bytes");
                closeAdapter_(adapter_);
                adapter_ = nullptr;
                return false;
            }
            peerStruct->Flags = static_cast<WIREGUARD_PEER_FLAG>(peerStruct->Flags | WIREGUARD_PEER_HAS_PRESHARED_KEY);
            std::memcpy(peerStruct->PresharedKey, psk->data(), WIREGUARD_KEY_LENGTH);
        }

        if (!peer.endpoint.empty()) {
            sockaddr_storage ss{};
            std::size_t sl = 0;
            if (!resolveEndpoint(peer.endpoint, ss, sl)) {
                Logger::log(LogLevel::Error, "WireGuardNT: failed to resolve peer endpoint");
                closeAdapter_(adapter_);
                adapter_ = nullptr;
                return false;
            }
            peerStruct->Flags = static_cast<WIREGUARD_PEER_FLAG>(peerStruct->Flags | WIREGUARD_PEER_HAS_ENDPOINT);
            std::memcpy(&peerStruct->Endpoint, &ss, sizeof(peerStruct->Endpoint) < sl ? sizeof(peerStruct->Endpoint) : sl);
        }

        if (peer.persistentKeepalive != 0) {
            peerStruct->Flags = static_cast<WIREGUARD_PEER_FLAG>(peerStruct->Flags | WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE);
            peerStruct->PersistentKeepalive = peer.persistentKeepalive;
        }

        peerStruct->AllowedIPsCount = static_cast<DWORD>(peer.allowedIps.size());

        for (const auto& cidrStr : peer.allowedIps) {
            auto cidr = parseCidr(cidrStr);
            if (!cidr) {
                Logger::log(LogLevel::Error, "WireGuardNT: invalid AllowedIPs entry");
                closeAdapter_(adapter_);
                adapter_ = nullptr;
                return false;
            }
            std::size_t aipOffset = buf.size();
            buf.resize(buf.size() + sizeof(WIREGUARD_ALLOWED_IP));
            iface = reinterpret_cast<WIREGUARD_INTERFACE*>(buf.data());
            auto* aip = reinterpret_cast<WIREGUARD_ALLOWED_IP*>(buf.data() + aipOffset);
            std::memset(aip, 0, sizeof(*aip));
            aip->AddressFamily = static_cast<ADDRESS_FAMILY>(cidr->family);
            aip->Cidr = cidr->prefix;
            if (cidr->family == AF_INET) std::memcpy(&aip->Address.V4, cidr->addr.data(), 4);
            else std::memcpy(&aip->Address.V6, cidr->addr.data(), 16);
        }
    }

    if (!setConfiguration_(adapter_, iface, static_cast<DWORD>(buf.size()))) {
        Logger::log(LogLevel::Error, "WireGuardNT: WireGuardSetConfiguration failed");
        closeAdapter_(adapter_);
        adapter_ = nullptr;
        return false;
    }

    if (!assignAddresses(config)) {
        closeAdapter_(adapter_);
        adapter_ = nullptr;
        return false;
    }

    if (!setAdapterState_(adapter_, WIREGUARD_ADAPTER_STATE_UP)) {
        Logger::log(LogLevel::Error, "WireGuardNT: WireGuardSetAdapterState(UP) failed");
        closeAdapter_(adapter_);
        adapter_ = nullptr;
        return false;
    }

    running_ = true;
    Logger::log(LogLevel::Info, "WireGuardNT: tunnel is up");
    return true;
}

void WireGuardNtBackend::stop() {
    if (!running_) return;
    if (adapter_) {
        setAdapterState_(adapter_, WIREGUARD_ADAPTER_STATE_DOWN);
        closeAdapter_(adapter_);
        adapter_ = nullptr;
    }
    running_ = false;
    Logger::log(LogLevel::Info, "WireGuardNT: tunnel torn down");
}

bool WireGuardNtBackend::isRunning() const { return running_; }

TunnelStats WireGuardNtBackend::statistics() const {
    TunnelStats stats{};
    if (!running_ || !adapter_) return stats;

    DWORD bytes = 0;
    getConfiguration_(adapter_, nullptr, &bytes); // discover required size
    if (bytes == 0) return stats;

    std::vector<std::uint8_t> buf(bytes);
    auto* iface = reinterpret_cast<WIREGUARD_INTERFACE*>(buf.data());
    if (!getConfiguration_(adapter_, iface, &bytes)) return stats;

    const auto* p = buf.data() + sizeof(WIREGUARD_INTERFACE);
    for (DWORD i = 0; i < iface->PeersCount; ++i) {
        const auto* peer = reinterpret_cast<const WIREGUARD_PEER*>(p);
        stats.bytesSent += peer->TxBytes;
        stats.bytesReceived += peer->RxBytes;
        if (peer->LastHandshake != 0) stats.handshakes += 1;
        p += sizeof(WIREGUARD_PEER) + static_cast<std::size_t>(peer->AllowedIPsCount) * sizeof(WIREGUARD_ALLOWED_IP);
    }
    return stats;
}

} // namespace orbis::windows_detail
#endif // _WIN32
