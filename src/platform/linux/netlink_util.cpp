// SPDX-License-Identifier: Apache-2.0
#ifdef __linux__
#include "netlink_util.hpp"

#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

namespace orbis::linux_detail {

NlSocket::NlSocket() {
    fd_ = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd_ < 0) return;
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

NlSocket::~NlSocket() {
    if (fd_ >= 0) ::close(fd_);
}

int NlSocket::sendAndAck(NlMessage& msg) {
    if (!valid()) return -ENOTCONN;

    auto* hdr = msg.header();
    hdr->nlmsg_seq = seq_++;
    hdr->nlmsg_pid = 0;
    hdr->nlmsg_flags |= NLM_F_ACK;
    msg.finalize();

    sockaddr_nl dst{};
    dst.nl_family = AF_NETLINK;
    ssize_t sent = ::sendto(fd_, msg.data(), msg.size(), 0,
                             reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (sent < 0) return -errno;

    std::uint8_t buf[8192];
    ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
    if (n < 0) return -errno;

    const auto* resp = reinterpret_cast<const nlmsghdr*>(buf);
    if (static_cast<std::size_t>(n) < sizeof(nlmsghdr) || !NLMSG_OK(resp, static_cast<std::size_t>(n)))
        return -EBADMSG;
    if (resp->nlmsg_type != NLMSG_ERROR) return -EBADMSG;

    const auto* err = static_cast<const nlmsgerr*>(NLMSG_DATA(resp));
    return err->error; // 0 on success, negative errno otherwise
}

std::optional<std::vector<std::uint8_t>> NlSocket::sendAndCollect(NlMessage& msg) {
    if (!valid()) return std::nullopt;

    auto* hdr = msg.header();
    hdr->nlmsg_seq = seq_++;
    hdr->nlmsg_pid = 0;
    msg.finalize();

    sockaddr_nl dst{};
    dst.nl_family = AF_NETLINK;
    if (::sendto(fd_, msg.data(), msg.size(), 0,
                 reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> out;
    std::uint8_t buf[16384];
    for (;;) {
        ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n < 0) return std::nullopt;

        std::size_t offset = 0;
        bool done = false;
        while (offset + sizeof(nlmsghdr) <= static_cast<std::size_t>(n)) {
            const auto* h = reinterpret_cast<const nlmsghdr*>(buf + offset);
            if (!NLMSG_OK(h, static_cast<std::size_t>(n) - offset)) break;
            if (h->nlmsg_type == NLMSG_ERROR) {
                const auto* err = static_cast<const nlmsgerr*>(NLMSG_DATA(h));
                if (err->error != 0) return std::nullopt;
                done = true;
                break;
            }
            if (h->nlmsg_type == NLMSG_DONE) { done = true; break; }
            out.insert(out.end(), reinterpret_cast<const std::uint8_t*>(h), reinterpret_cast<const std::uint8_t*>(h) + h->nlmsg_len);
            if (!(h->nlmsg_flags & NLM_F_MULTI)) done = true;
            offset += NLMSG_ALIGN(h->nlmsg_len);
        }
        if (done) break;
    }
    return out;
}

std::optional<std::uint16_t> NlSocket::resolveGenlFamily(const std::string& name) {
    NlMessage msg(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);
    genlmsghdr genl{};
    genl.cmd = CTRL_CMD_GETFAMILY;
    genl.version = 1;
    msg.appendHeader(genl);
    msg.putStr(CTRL_ATTR_FAMILY_NAME, name);

    // Reuses sendAndCollect's single-response path by temporarily
    // treating this as a non-dump request; the controller replies with
    // one message containing the family ID.
    auto resp = sendAndCollect(msg);
    if (!resp || resp->empty()) return std::nullopt;

    const auto* h = reinterpret_cast<const nlmsghdr*>(resp->data());
    if (h->nlmsg_type == NLMSG_ERROR) return std::nullopt;

    const auto* g = static_cast<const genlmsghdr*>(NLMSG_DATA(h));
    const auto* attrStart = reinterpret_cast<const std::uint8_t*>(g) + GENL_HDRLEN;
    std::size_t attrLen = h->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

    std::optional<std::uint16_t> familyId;
    forEachAttr(attrStart, attrLen, [&](const rtattr* rta) {
        if (rta->rta_type == CTRL_ATTR_FAMILY_ID) {
            std::uint16_t id;
            std::memcpy(&id, RTA_DATA(rta), sizeof(id));
            familyId = id;
        }
    });
    return familyId;
}

} // namespace orbis::linux_detail
#endif // __linux__
