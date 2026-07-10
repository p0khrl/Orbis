// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - Minimal netlink helper (Linux only)
//
// A small, dependency-free wrapper around AF_NETLINK sockets used to
// talk to the kernel's rtnetlink (link/address/route) and generic
// netlink (WireGuard device) APIs. This intentionally avoids linking
// libnl so the engine has no mandatory system package dependency beyond
// glibc/kernel headers — this is the same approach wireguard-tools
// itself takes.
//
// This file implements NO cryptography and NO VPN protocol logic; it is
// purely a transport for kernel configuration messages.
#pragma once
#ifdef __linux__

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

namespace orbis::linux_detail {

/// Growable, alignment-correct buffer for building a single netlink
/// message (header + payload + nested attributes).
class NlMessage {
public:
    explicit NlMessage(std::uint16_t type, std::uint16_t flags) {
        nlmsghdr hdr{};
        hdr.nlmsg_type = type;
        hdr.nlmsg_flags = flags;
        appendRaw(&hdr, sizeof(hdr));
    }

    /// Appends a fixed-size struct payload immediately after the header
    /// (e.g. ifinfomsg, genlmsghdr). Must be called at most once, right
    /// after construction.
    template <typename T>
    void appendHeader(const T& value) {
        appendRaw(&value, sizeof(value));
    }

    /// Appends a plain (non-nested) attribute.
    void putAttr(unsigned short type, const void* data, std::size_t len) {
        rtattr rta{};
        rta.rta_type = type;
        rta.rta_len = static_cast<unsigned short>(RTA_LENGTH(len));
        std::size_t attrStart = buf_.size();
        appendRaw(&rta, sizeof(rta));
        appendRaw(data, len);
        padTo4();
        std::memcpy(buf_.data() + attrStart, &rta, sizeof(rta)); // rta_len already set
    }

    void putU8(unsigned short type, std::uint8_t v) { putAttr(type, &v, sizeof(v)); }
    void putU16(unsigned short type, std::uint16_t v) { putAttr(type, &v, sizeof(v)); }
    void putU32(unsigned short type, std::uint32_t v) { putAttr(type, &v, sizeof(v)); }
    void putStr(unsigned short type, const std::string& s) { putAttr(type, s.c_str(), s.size() + 1); }

    /// Begins a nested attribute; returns an offset token to close it with endNested().
    std::size_t beginNested(unsigned short type) {
        rtattr rta{};
        rta.rta_type = static_cast<unsigned short>(type | kNlaFNested);
        std::size_t start = buf_.size();
        appendRaw(&rta, sizeof(rta));
        return start;
    }

    void endNested(std::size_t start) {
        auto len = static_cast<unsigned short>(buf_.size() - start);
        rtattr rta{};
        std::memcpy(&rta, buf_.data() + start, sizeof(rta));
        rta.rta_len = len;
        std::memcpy(buf_.data() + start, &rta, sizeof(rta));
    }

    void finalize() {
        auto* hdr = reinterpret_cast<nlmsghdr*>(buf_.data());
        hdr->nlmsg_len = static_cast<std::uint32_t>(buf_.size());
    }

    const std::uint8_t* data() const { return buf_.data(); }
    std::size_t size() const { return buf_.size(); }
    nlmsghdr* header() { return reinterpret_cast<nlmsghdr*>(buf_.data()); }

private:
    // Standard netlink attribute flag marking an attribute as containing
    // nested sub-attributes (see <linux/netlink.h> NLA_F_NESTED).
    static constexpr unsigned short kNlaFNested = 0x8000;

    void appendRaw(const void* data, std::size_t len) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        buf_.insert(buf_.end(), bytes, bytes + len);
    }

    void padTo4() {
        while (buf_.size() % 4 != 0) buf_.push_back(0);
    }

    std::vector<std::uint8_t> buf_;
};

/// A single netlink socket bound to the kernel, used for one request/response
/// exchange at a time. Not intended to be shared across threads.
class NlSocket {
public:
    NlSocket();
    ~NlSocket();
    NlSocket(const NlSocket&) = delete;
    NlSocket& operator=(const NlSocket&) = delete;

    bool valid() const { return fd_ >= 0; }

    /// Sends a request and waits for a single NLMSG_ERROR ack.
    /// Returns 0 on success, or the negative errno reported by the kernel.
    int sendAndAck(NlMessage& msg);

    /// Sends a request and returns all raw response bytes (used for
    /// multi-part dump replies, e.g. WG_CMD_GET_DEVICE).
    std::optional<std::vector<std::uint8_t>> sendAndCollect(NlMessage& msg);

    /// Resolves a generic-netlink family name (e.g. "wireguard") to its
    /// numeric family ID, via the standard genl controller.
    std::optional<std::uint16_t> resolveGenlFamily(const std::string& name);

private:
    int fd_ = -1;
    std::uint32_t seq_ = 1;
};

/// Iterates top-level rtattr/nlattr entries in a buffer, invoking `fn`
/// for each. Used to walk kernel responses without pulling in libnl.
template <typename Fn>
void forEachAttr(const void* base, std::size_t len, Fn&& fn) {
    const auto* p = static_cast<const std::uint8_t*>(base);
    std::size_t offset = 0;
    while (offset + sizeof(rtattr) <= len) {
        const auto* rta = reinterpret_cast<const rtattr*>(p + offset);
        if (rta->rta_len < sizeof(rtattr) || offset + rta->rta_len > len) break;
        fn(rta);
        offset += RTA_ALIGN(rta->rta_len);
    }
}

} // namespace orbis::linux_detail

#endif // __linux__
