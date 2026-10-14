// SPDX-License-Identifier: GPL-2.0-or-later
//
// Source-based Eden/yuzu "Room" protocol peer for the switch_ldn interop test.
//
// This is a plain-UDP member that talks to the bridge's room.c transport on
// 127.0.0.1:24872 (override with argv[1]). It serializes exactly the packets
// RoomMember::SendJoinRequest/SendGameInfo/SendProxyPacket/SendLdnPacket
// produce, using the copied Eden Packet serializer.
//
// It is deliberately dependency-free apart from packet.cpp and libstdc++ so
// that `make interop` can build and run it on demand. No binary is checked in.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "packet.h"

using namespace Network;

namespace {

constexpr const char* kHost = "127.0.0.1";
constexpr uint16_t kDefaultPort = 24872;

// Eden's Network::RoomMessageTypes.
constexpr uint8_t IdJoinRequest = 1;
constexpr uint8_t IdJoinSuccess = 2;
constexpr uint8_t IdRoomInformation = 3;
constexpr uint8_t IdSetGameInfo = 4;
constexpr uint8_t IdProxyPacket = 5;
constexpr uint8_t IdLdnPacket = 6;

// Eden's Network::LDNPacketType.
constexpr uint8_t LDNPacketTypeScan = 0;

int g_failures = 0;

void stage(const char* name, bool ok, const char* detail = nullptr) {
    std::printf("[%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail ? " - " : "",
                detail ? detail : "");
    std::fflush(stdout);
    if (!ok) {
        ++g_failures;
    }
}

class UdpPeer {
public:
    bool Connect(uint16_t port) {
        fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd_ < 0) {
            return false;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, kHost, &addr.sin_addr) != 1) {
            return false;
        }
        return connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    }

    void Close() {
        if (fd_ >= 0) {
            close(fd_);
            fd_ = -1;
        }
    }

    bool Send(const Packet& p) {
        const ssize_t n = send(fd_, p.GetData(), p.GetDataSize(), 0);
        return n == static_cast<ssize_t>(p.GetDataSize());
    }

    // Waits up to timeout_ms for one datagram. Decodes the leading message id
    // and reports it. Returns true if a datagram carrying `expected_id`
    // arrived; returns false on timeout or a different id.
    bool RecvExpect(uint8_t expected_id, int timeout_ms, uint8_t* got_id) {
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        std::vector<char> buf(65536);
        const ssize_t n = recv(fd_, buf.data(), buf.size(), 0);
        if (n <= 0) {
            if (got_id) {
                *got_id = 0;
            }
            return false;
        }

        Packet p;
        p.Append(buf.data(), static_cast<std::size_t>(n));
        uint8_t id = 0;
        p.Read(id);
        if (got_id) {
            *got_id = id;
        }
        return id == expected_id;
    }

    int fd_{-1};
};

std::array<u8, 4> IPv4(u8 a, u8 b, u8 c, u8 d) {
    return {a, b, c, d};
}

} // namespace

int main(int argc, char** argv) {
    uint16_t port = kDefaultPort;
    if (argc > 1) {
        port = static_cast<uint16_t>(std::atoi(argv[1]));
    }

    UdpPeer peer;
    if (!peer.Connect(port)) {
        stage("socket.connect", false, "could not connect to room UDP port");
        return 1;
    }
    std::printf("room_peer: connected to %s:%u\n", kHost, port);

    // ---- Stage 1: IdJoinRequest (exactly RoomMemberImpl::SendJoinRequest) --
    {
        Packet p;
        p.Write(static_cast<u8>(IdJoinRequest));
        p.Write(std::string("switch_ldn_peer"));
        p.Write(IPv4(0xFF, 0xFF, 0xFF, 0xFF)); // preferred fake ip, 4 raw bytes
        p.Write(static_cast<u32>(1));          // network_version
        p.Write(std::string(""));              // room password
        p.Write(std::string(""));              // token
        if (!peer.Send(p)) {
            stage("join.send", false, "send failed");
            peer.Close();
            return 1;
        }
        uint8_t id = 0;
        const bool ok = peer.RecvExpect(IdJoinSuccess, 1500, &id);
        char detail[64];
        std::snprintf(detail, sizeof(detail), "reply id=%u (want %u)", id,
                      static_cast<unsigned>(IdJoinSuccess));
        stage("join.success", ok, detail);
        if (!ok) {
            // Without a join there is no point continuing; the remaining
            // packets would just be dropped.
            peer.Close();
            return 1;
        }
    }

    // ---- Stage 2: IdSetGameInfo (RoomMember::SendGameInfo) ----------------
    {
        Packet p;
        p.Write(static_cast<u8>(IdSetGameInfo));
        p.Write(std::string("Pokemon Scarlet"));
        p.Write(static_cast<u64>(0x01006F8002320000ULL)); // game id is a u64
        p.Write(std::string("2.0.0"));
        const bool sent = peer.Send(p);
        // The server answers with IdRoomInformation broadcasts; drain whatever
        // is queued without treating it as a failure.
        uint8_t id = 0;
        peer.RecvExpect(IdRoomInformation, 300, &id);
        stage("game_info.send", sent, sent ? "name='Pokemon Scarlet' id=01006F8002320000" : "send failed");
    }

    // ---- Stage 3: IdProxyPacket (RoomMember::SendProxyPacket) -------------
    {
        Packet p;
        p.Write(static_cast<u8>(IdProxyPacket));
        p.Write(static_cast<u8>(2)); // local_endpoint.family (INET), no raw ip
        p.Write(IPv4(0, 0, 0, 0));
        p.Write(static_cast<u16>(0)); // local_endpoint.portno
        p.Write(static_cast<u8>(2));  // remote_endpoint.family
        p.Write(IPv4(0, 0, 0, 0));
        p.Write(static_cast<u16>(0)); // remote_endpoint.portno
        p.Write(static_cast<u8>(17)); // protocol (UDP)
        p.Write(true);                // broadcast
        const std::vector<u8> payload{'P', 'I', 'A', '!', 'h', 'i', '!'};
        p.Write(payload);
        const bool sent = peer.Send(p);
        uint8_t id = 0;
        peer.RecvExpect(IdRoomInformation, 300, &id);
        stage("proxy_packet.send", sent, sent ? "7-byte payload" : "send failed");
    }

    // ---- Stage 4: IdLdnPacket{Scan} plus trailing passphrase --------------
    {
        Packet p;
        p.Write(static_cast<u8>(IdLdnPacket));
        p.Write(static_cast<u8>(LDNPacketTypeScan));
        p.Write(IPv4(0, 0, 0, 0)); // local_ip
        p.Write(IPv4(0, 0, 0, 0)); // remote_ip
        p.Write(true);             // broadcast
        const std::vector<u8> scan{0x01, 0x00, 0x00, 0x00}; // scan request body
        p.Write(scan);
        const std::vector<u8> passphrase{'L', 'D', 'N', '_', 'P', 'A', 'S', 'S',
                                         '!', '!', '!', '!', '!', '!', '!'};
        p.Write(passphrase); // optional length-prefixed trailing blob
        const bool sent = peer.Send(p);
        uint8_t id = 0;
        peer.RecvExpect(IdRoomInformation, 300, &id);
        stage("ldn_scan.send", sent, sent ? "scan + 15-byte passphrase" : "send failed");
    }

    peer.Close();

    if (g_failures != 0) {
        std::printf("room_peer: %d stage(s) failed\n", g_failures);
        return 1;
    }
    std::printf("room_peer: all stages passed\n");
    return 0;
}
