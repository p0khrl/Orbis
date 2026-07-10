// SPDX-License-Identifier: Apache-2.0
#ifdef __linux__
#include "kernel_wireguard_backend.hpp"
#include "netlink_util.hpp"
#include "../../tunnel/net_address_parsing.hpp"
#include "orbis/base64.hpp"
#include "orbis/logger.hpp"

#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/wireguard.h>

using orbis::wireguard::InterfaceConfig;
using orbis::wireguard::PeerConfig;
using orbis::net_parse::parseCidr;
using orbis::net_parse::resolveEndpoint;

namespace orbis::linux_detail {

namespace {
} // namespace

KernelWireGuardBackend::KernelWireGuardBackend(std::string interfaceName)
    : ifname_(std::move(interfaceName)) {}

KernelWireGuardBackend::~KernelWireGuardBackend() {
    if (running_) stop();
}

bool KernelWireGuardBackend::createLink() {
    NlSocket sock;
    if (!sock.valid()) {
        Logger::log(LogLevel::Error, "netlink: failed to open rtnetlink socket (need root/CAP_NET_ADMIN?)");
        return false;
    }

    NlMessage msg(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);
    ifinfomsg ifi{};
    ifi.ifi_family = AF_UNSPEC;
    msg.appendHeader(ifi);
    msg.putStr(IFLA_IFNAME, ifname_);
    {
        auto li = msg.beginNested(IFLA_LINKINFO);
        msg.putStr(IFLA_INFO_KIND, "wireguard");
        msg.endNested(li);
    }

    int rc = sock.sendAndAck(msg);
    if (rc != 0) {
        Logger::log(LogLevel::Error,
            rc == -EOPNOTSUPP
                ? "netlink: kernel WireGuard module is not available (CONFIG_WIREGUARD missing or module not loaded)"
                : rc == -EPERM
                ? "netlink: permission denied creating WireGuard interface (need CAP_NET_ADMIN)"
                : "netlink: failed to create WireGuard interface");
        return false;
    }
    return true;
}

bool KernelWireGuardBackend::deleteLink() {
    NlSocket sock;
    if (!sock.valid()) return false;

    NlMessage msg(RTM_DELLINK, NLM_F_REQUEST);
    ifinfomsg ifi{};
    ifi.ifi_family = AF_UNSPEC;
    msg.appendHeader(ifi);
    msg.putStr(IFLA_IFNAME, ifname_);

    return sock.sendAndAck(msg) == 0;
}

bool KernelWireGuardBackend::configureDevice(const InterfaceConfig& config) {
    NlSocket sock;
    if (!sock.valid()) return false;

    auto family = sock.resolveGenlFamily(WG_GENL_NAME);
    if (!family) {
        Logger::log(LogLevel::Error, "netlink: could not resolve 'wireguard' generic netlink family");
        return false;
    }

    auto privKey = util::base64DecodeFixed<WG_KEY_LEN>(config.privateKey);
    if (!privKey) {
        Logger::log(LogLevel::Error, "WireGuard: private key failed to decode to 32 bytes");
        return false;
    }

    NlMessage msg(*family, NLM_F_REQUEST);
    genlmsghdr genl{};
    genl.cmd = WG_CMD_SET_DEVICE;
    genl.version = 1;
    msg.appendHeader(genl);

    msg.putStr(WGDEVICE_A_IFNAME, ifname_);
    msg.putAttr(WGDEVICE_A_PRIVATE_KEY, privKey->data(), privKey->size());
    if (config.listenPort != 0) msg.putU16(WGDEVICE_A_LISTEN_PORT, config.listenPort);
    // WGDEVICE_F_REPLACE_PEERS ensures re-configuration fully replaces the peer set.
    msg.putU32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);

    if (!config.peers.empty()) {
        auto peersAttr = msg.beginNested(WGDEVICE_A_PEERS);
        int idx = 0;
        for (const auto& peer : config.peers) {
            auto pubKey = util::base64DecodeFixed<WG_KEY_LEN>(peer.publicKey);
            if (!pubKey) {
                Logger::log(LogLevel::Error, "WireGuard: peer public key failed to decode to 32 bytes");
                return false;
            }
            auto peerAttr = msg.beginNested(static_cast<unsigned short>(idx++));
            msg.putAttr(WGPEER_A_PUBLIC_KEY, pubKey->data(), pubKey->size());
            msg.putU32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);

            if (peer.presharedKey) {
                auto psk = util::base64DecodeFixed<WG_KEY_LEN>(*peer.presharedKey);
                if (!psk) {
                    Logger::log(LogLevel::Error, "WireGuard: preshared key failed to decode to 32 bytes");
                    return false;
                }
                msg.putAttr(WGPEER_A_PRESHARED_KEY, psk->data(), psk->size());
            }

            if (!peer.endpoint.empty()) {
                sockaddr_storage ss{};
                std::size_t sl = 0;
                if (!resolveEndpoint(peer.endpoint, ss, sl)) {
                    Logger::log(LogLevel::Error, "WireGuard: failed to resolve peer endpoint");
                    return false;
                }
                msg.putAttr(WGPEER_A_ENDPOINT, &ss, sl);
            }

            if (peer.persistentKeepalive != 0) {
                msg.putU16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, peer.persistentKeepalive);
            }

            if (!peer.allowedIps.empty()) {
                auto allowedAttr = msg.beginNested(WGPEER_A_ALLOWEDIPS);
                int aidx = 0;
                for (const auto& cidrStr : peer.allowedIps) {
                    auto cidr = parseCidr(cidrStr);
                    if (!cidr) {
                        Logger::log(LogLevel::Error, "WireGuard: invalid AllowedIPs entry");
                        return false;
                    }
                    auto oneAttr = msg.beginNested(static_cast<unsigned short>(aidx++));
                    msg.putU16(WGALLOWEDIP_A_FAMILY, static_cast<std::uint16_t>(cidr->family));
                    std::size_t addrLen = cidr->family == AF_INET ? 4 : 16;
                    msg.putAttr(WGALLOWEDIP_A_IPADDR, cidr->addr.data(), addrLen);
                    msg.putU8(WGALLOWEDIP_A_CIDR_MASK, cidr->prefix);
                    msg.endNested(oneAttr);
                }
                msg.endNested(allowedAttr);
            }

            msg.endNested(peerAttr);
        }
        msg.endNested(peersAttr);
    }

    int rc = sock.sendAndAck(msg);
    if (rc != 0) {
        Logger::log(LogLevel::Error, "netlink: WG_CMD_SET_DEVICE failed");
        return false;
    }
    return true;
}

bool KernelWireGuardBackend::assignAddresses(const InterfaceConfig& config) {
    for (const auto& addrCidr : config.addresses) {
        auto cidr = parseCidr(addrCidr);
        if (!cidr) {
            Logger::log(LogLevel::Error, "WireGuard: invalid interface Address entry");
            return false;
        }

        NlSocket sock;
        if (!sock.valid()) return false;

        NlMessage msg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE);
        ifaddrmsg ifa{};
        ifa.ifa_family = static_cast<unsigned char>(cidr->family);
        ifa.ifa_prefixlen = cidr->prefix;
        ifa.ifa_flags = 0;
        ifa.ifa_scope = 0;
        // ifa_index is resolved by name via IFA_LABEL on some kernels, but
        // rtnetlink requires the numeric ifindex; resolve it with if_nametoindex.
        ifa.ifa_index = if_nametoindex(ifname_.c_str());
        if (ifa.ifa_index == 0) {
            Logger::log(LogLevel::Error, "WireGuard: interface not found when assigning address");
            return false;
        }
        msg.appendHeader(ifa);

        std::size_t addrLen = cidr->family == AF_INET ? 4 : 16;
        msg.putAttr(IFA_LOCAL, cidr->addr.data(), addrLen);
        msg.putAttr(IFA_ADDRESS, cidr->addr.data(), addrLen);

        int rc = sock.sendAndAck(msg);
        if (rc != 0) {
            Logger::log(LogLevel::Error, "netlink: failed to assign address to interface");
            return false;
        }
    }
    return true;
}

bool KernelWireGuardBackend::setLinkUp() {
    NlSocket sock;
    if (!sock.valid()) return false;

    NlMessage msg(RTM_NEWLINK, NLM_F_REQUEST);
    ifinfomsg ifi{};
    ifi.ifi_family = AF_UNSPEC;
    ifi.ifi_index = static_cast<int>(if_nametoindex(ifname_.c_str()));
    ifi.ifi_change = IFF_UP;
    ifi.ifi_flags = IFF_UP;
    msg.appendHeader(ifi);

    int rc = sock.sendAndAck(msg);
    if (rc != 0) {
        Logger::log(LogLevel::Error, "netlink: failed to bring WireGuard interface up");
        return false;
    }
    return true;
}

bool KernelWireGuardBackend::start(const InterfaceConfig& config) {
    if (running_) return true;

    if (!createLink()) return false;
    if (!configureDevice(config) || !assignAddresses(config) || !setLinkUp()) {
        deleteLink();
        return false;
    }

    running_ = true;
    Logger::log(LogLevel::Info, "WireGuard: kernel tunnel '" + ifname_ + "' is up");
    return true;
}

void KernelWireGuardBackend::stop() {
    if (!running_) return;
    deleteLink();
    running_ = false;
    Logger::log(LogLevel::Info, "WireGuard: kernel tunnel '" + ifname_ + "' torn down");
}

bool KernelWireGuardBackend::isRunning() const { return running_; }

TunnelStats KernelWireGuardBackend::statistics() const {
    TunnelStats stats{};
    if (!running_) return stats;

    NlSocket sock;
    if (!sock.valid()) return stats;

    auto family = sock.resolveGenlFamily(WG_GENL_NAME);
    if (!family) return stats;

    NlMessage msg(*family, NLM_F_REQUEST | NLM_F_DUMP);
    genlmsghdr genl{};
    genl.cmd = WG_CMD_GET_DEVICE;
    genl.version = 1;
    msg.appendHeader(genl);
    msg.putStr(WGDEVICE_A_IFNAME, ifname_);

    auto resp = sock.sendAndCollect(msg);
    if (!resp) return stats;

    std::size_t offset = 0;
    while (offset + sizeof(nlmsghdr) <= resp->size()) {
        const auto* h = reinterpret_cast<const nlmsghdr*>(resp->data() + offset);
        if (!NLMSG_OK(h, resp->size() - offset)) break;
        const auto* g = static_cast<const genlmsghdr*>(NLMSG_DATA(h));
        const auto* attrStart = reinterpret_cast<const std::uint8_t*>(g) + GENL_HDRLEN;
        std::size_t attrLen = h->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

        forEachAttr(attrStart, attrLen, [&](const rtattr* rta) {
            if (rta->rta_type != WGDEVICE_A_PEERS) return;
            forEachAttr(RTA_DATA(rta), RTA_PAYLOAD(rta), [&](const rtattr* peerRta) {
                forEachAttr(RTA_DATA(peerRta), RTA_PAYLOAD(peerRta), [&](const rtattr* f) {
                    if (f->rta_type == WGPEER_A_RX_BYTES) {
                        std::uint64_t v; std::memcpy(&v, RTA_DATA(f), sizeof(v));
                        stats.bytesReceived += v;
                    } else if (f->rta_type == WGPEER_A_TX_BYTES) {
                        std::uint64_t v; std::memcpy(&v, RTA_DATA(f), sizeof(v));
                        stats.bytesSent += v;
                    } else if (f->rta_type == WGPEER_A_LAST_HANDSHAKE_TIME) {
                        stats.handshakes += 1;
                    }
                });
            });
        });

        offset += NLMSG_ALIGN(h->nlmsg_len);
    }
    return stats;
}

} // namespace orbis::linux_detail
#endif // __linux__
