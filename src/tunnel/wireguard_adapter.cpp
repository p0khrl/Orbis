// SPDX-License-Identifier: Apache-2.0
#include "orbis/wireguard_adapter.hpp"
#include "orbis/logger.hpp"
#include <algorithm>
#include <sstream>

#ifdef __linux__
#include "../platform/linux/kernel_wireguard_backend.hpp"
#endif
#ifdef _WIN32
#include "../platform/windows/wireguard_nt_backend.hpp"
#endif


namespace orbis::wireguard {

namespace {

/// Base64-encoded Curve25519 keys are always 44 characters (32 bytes),
/// with the last character constrained to a small alphabet — but we only
/// check length/charset here. Actual key validity is enforced by the
/// crypto backend when it loads the key.
bool looksLikeBase64Key(std::string_view s) {
    if (s.size() != 44) return false;
    return std::all_of(s.begin(), s.end() - 1, [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/';
    });
}

std::string trim(std::string_view s) {
    const auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return "";
    const auto end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(begin, end - begin + 1));
}

std::vector<std::string> splitCsv(std::string_view s) {
    std::vector<std::string> out;
    std::stringstream ss{std::string(s)};
    std::string item;
    while (std::getline(ss, item, ',')) {
        auto t = trim(item);
        if (!t.empty()) out.push_back(t);
    }
    return out;
}

/// Parses a wg-quick-style config: [Interface]/[Peer] sections of
/// key = value lines. This is a deliberately small, dependency-free
/// parser; a JSON-based Configuration path (Phase 2) can produce this
/// same string as an intermediate form.
std::optional<InterfaceConfig> parseWgQuick(std::string_view text) {
    InterfaceConfig cfg;
    PeerConfig* currentPeer = nullptr;
    enum class Section { None, Interface, Peer } section = Section::None;

    std::stringstream ss{std::string(text)};
    std::string rawLine;
    while (std::getline(ss, rawLine, '\n')) {
        auto line = trim(rawLine);
        if (line.empty() || line[0] == '#') continue;

        if (line == "[Interface]") { section = Section::Interface; continue; }
        if (line == "[Peer]") {
            cfg.peers.emplace_back();
            currentPeer = &cfg.peers.back();
            section = Section::Peer;
            continue;
        }

        const auto eq = line.find('=');
        if (eq == std::string::npos) return std::nullopt; // malformed line
        auto key = trim(line.substr(0, eq));
        auto value = trim(line.substr(eq + 1));

        if (section == Section::Interface) {
            if (key == "PrivateKey") cfg.privateKey = value;
            else if (key == "Address") cfg.addresses = splitCsv(value);
            else if (key == "ListenPort") cfg.listenPort = static_cast<std::uint16_t>(std::stoul(value));
            else if (key == "MTU") cfg.mtu = static_cast<std::uint16_t>(std::stoul(value));
            else if (key == "DNS") cfg.dns = splitCsv(value);
            else return std::nullopt; // unknown key
        } else if (section == Section::Peer && currentPeer) {
            if (key == "PublicKey") currentPeer->publicKey = value;
            else if (key == "PresharedKey") currentPeer->presharedKey = value;
            else if (key == "Endpoint") currentPeer->endpoint = value;
            else if (key == "AllowedIPs") currentPeer->allowedIps = splitCsv(value);
            else if (key == "PersistentKeepalive") currentPeer->persistentKeepalive = static_cast<std::uint16_t>(std::stoul(value));
            else return std::nullopt;
        } else {
            return std::nullopt; // key-value line outside any section
        }
    }
    return cfg;
}

bool validate(const InterfaceConfig& cfg) {
    if (!looksLikeBase64Key(cfg.privateKey)) return false;
    if (cfg.addresses.empty()) return false;
    if (cfg.peers.empty()) return false;
    for (const auto& peer : cfg.peers) {
        if (!looksLikeBase64Key(peer.publicKey)) return false;
        if (peer.presharedKey && !looksLikeBase64Key(*peer.presharedKey)) return false;
        if (peer.allowedIps.empty()) return false;
    }
    return true;
}

/// Fallback placeholder backend used on platforms without a real backend
/// wired up yet (Windows/macOS/Android — see docs/PLATFORM_STATUS.md).
/// It performs no networking and no cryptography.
class NullBackend final : public IBackend {
public:
    bool start(const InterfaceConfig&) override {
        Logger::log(LogLevel::Warning,
            "WireGuard: no platform backend is implemented for this OS yet; "
            "this is a placeholder and moves no traffic (see docs/PLATFORM_STATUS.md)");
        running_ = true;
        return true;
    }
    void stop() override { running_ = false; }
    bool isRunning() const override { return running_; }
    TunnelStats statistics() const override { return {}; }

private:
    std::atomic<bool> running_{false};
};

} // namespace

std::unique_ptr<IBackend> WireGuardAdapter::defaultBackend() {
#if defined(__linux__)
    return std::make_unique<orbis::linux_detail::KernelWireGuardBackend>();
#elif defined(_WIN32)
    return std::make_unique<orbis::windows_detail::WireGuardNtBackend>();
#else
    return std::make_unique<NullBackend>();
#endif
}

WireGuardAdapter::WireGuardAdapter(std::unique_ptr<IBackend> backend)
    : backend_(backend ? std::move(backend) : defaultBackend()) {}

WireGuardAdapter::~WireGuardAdapter() {
    if (backend_ && backend_->isRunning()) backend_->stop();
}

std::string_view WireGuardAdapter::protocolName() const { return "wireguard"; }

TunnelResult WireGuardAdapter::configure(std::string_view protocolConfig) {
    auto parsed = parseWgQuick(protocolConfig);
    if (!parsed || !validate(*parsed)) {
        Logger::log(LogLevel::Error, "WireGuardAdapter: invalid configuration");
        return TunnelResult::InvalidConfig;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = std::move(*parsed);
    configured_ = true;
    return TunnelResult::Success;
}

TunnelResult WireGuardAdapter::open() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!configured_) return TunnelResult::InvalidConfig;
    if (backend_->isRunning()) return TunnelResult::AlreadyConnected;
    return backend_->start(config_) ? TunnelResult::Success : TunnelResult::ConnectFailed;
}

TunnelResult WireGuardAdapter::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!backend_->isRunning()) return TunnelResult::NotConnected;
    backend_->stop();
    return TunnelResult::Success;
}

bool WireGuardAdapter::isOpen() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return backend_->isRunning();
}

TunnelStats WireGuardAdapter::statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return backend_->statistics();
}

} // namespace orbis::wireguard
