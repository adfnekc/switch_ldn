#ifndef SWITCH_LDN_ROOM_H
#define SWITCH_LDN_ROOM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ldn.h"

/*
 * Room protocol transport (Eden / yuzu lineage: Eden, Citron, Sudachi).
 *
 * Reverse-engineered from Eden's src/network/{room,room_member,packet}.cpp and
 * common/announce_multiplayer_room.h. This is a **dumb relay**: the server
 * reads a destination "fake IP" out of the packet and forwards the whole thing
 * to whichever member owns it, verbatim. It contains no LDN knowledge at all -
 * the LDN semantics live in the payload, which is a raw NetworkInfo or
 * NodeInfo (the very same Ryujinx-format structs RyuLdn uses).
 *
 * Transport: ENet over UDP (default port 24872, 1 channel, "reliable"). We use
 * plain UDP, which is sufficient because this is a private relay and every
 * packet is a single datagram.
 *
 * Wire format - Eden's Packet class: big-endian multi-byte scalars,
 * std::string and std::vector<u8> as (u32 length)(bytes), IPv4Address as 4
 * raw bytes, bool as 1 byte.
 *
 * Only the messages the bridge needs are implemented; the moderation family
 * (ModKick/ModBan/ModGetBanList/...) is deliberately omitted.
 */

#define ROOM_DEFAULT_PORT 24872u
#define ROOM_NETWORK_VERSION 1u
#define ROOM_MAX_MEMBERS 16
/*
 * NOTE: Network::MaxMessageSize in Eden is 500, but it is only ever applied to
 * chat message text (room.cpp clamps the string before writing it). It is not a
 * datagram limit: Eden's own BroadcastRoomInformation() serialises every member
 * with no size check at all, and a full room does not fit in 500 bytes. So the
 * bridge sizes its serialiser for the real worst case (see Packet in room.c)
 * instead of enforcing 500 here.
 */

typedef enum RoomMessageTypes : uint8_t {
    IdJoinRequest = 1,
    IdJoinSuccess,
    IdRoomInformation,
    IdSetGameInfo,
    IdProxyPacket,
    IdLdnPacket,
    /*
     * Eden has no generic "error" packet: each rejection has its own message,
     * all of them carrying no payload except IdWrongPassword. They are listed
     * because a silent drop makes the emulator hang on a spinner instead.
     */
    IdWrongPassword = 11,
    IdVersionMismatch = 13,
    IdRoomIsFull = 15,
    IdNameCollision = 7,
    IdIpCollision = 8,
    IdCloseRoom = 16,
} RoomMessageType;

/* Rejections we know how to send. */
typedef enum RoomRejectReason : uint8_t {
    RoomRejectNone = 0,
    RoomRejectWrongPassword,
    RoomRejectVersionMismatch,
    RoomRejectRoomIsFull,
    RoomRejectNameCollision,
    RoomRejectIpCollision,
    RoomRejectCloseRoom,
} RoomRejectReason;

/* Eden's Network::LDNPacketType - carried inside IdLdnPacket's payload header. */
typedef enum LDNPacketType : uint8_t {
    LDNPacketTypeScan = 0,
    LDNPacketTypeScanResp,
    LDNPacketTypeConnect,
    LDNPacketTypeSyncNetwork,
    LDNPacketTypeDisconnect,
    LDNPacketTypeDestroyNetwork,
} LDNPacketType;

/* AnnounceMultiplayerRoom::GameInfo. */
typedef struct {
    char name[200];
    uint64_t id;
    char version[16];
} RoomGameInfo;

/* AnnounceMultiplayerRoom::RoomInformation. */
typedef struct {
    char name[128];
    char description[128];
    uint32_t member_slots;
    uint16_t port;
    RoomGameInfo preferred_game;
    char host_username[128];
} RoomInformation;

/* One connected member. */
typedef struct {
    bool in_use;
    int id;
    char nickname[128];
    uint8_t fake_ip[4];
    char username[64];
    char display_name[64];
    char avatar_url[200];
    RoomGameInfo game;
    bool moderator;
} RoomMemberInfo;

typedef struct RoomServer RoomServer;

/* What arrived on the wire, already decoded. */
typedef struct {
    uint8_t type;
    /* IdSetGameInfo */
    char game_name[200];
    uint64_t game_id;
    char game_version[16];
    /* IdProxyPacket */
    uint8_t local_family, remote_family, protocol;
    uint8_t local_ip[4], remote_ip[4];
    uint16_t local_port, remote_port;
    /*
     * The wire carries a broadcast byte here, but it is not decoded: Eden sets
     * it as `broadcast && remote_endpoint.ip[3] == 255`
     * (socket_proxy.cpp, ProxySocket::SendTo), so remote_ip[3] alone already
     * carries the same information and the relay reads that instead. One
     * source of truth rather than two that can disagree.
     */
    /* IdLdnPacket */
    uint8_t ldn_packet_type;
    uint8_t ldn_local_ip[4], ldn_remote_ip[4];
    const uint8_t *data;
    uint32_t data_len;
    /*
     * The LDN crypto passphrase, if the patched Eden sent one.
     *
     * Stock Eden drops it: LANDiscovery::CreateNetwork() uses
     * security_config.security_mode and throws the passphrase away. With
     * patches/eden-room-passphrase.patch applied, Eden appends it after `data`
     * as a length-prefixed blob. Because the Room server relays datagrams
     * verbatim, and HandleLdnPackets ignores trailing bytes, this is
     * backward-compatible in both directions - an unpatched Eden simply sends
     * nothing extra and passphrase_len stays 0.
     */
    uint8_t passphrase[64];
    uint32_t passphrase_len;
} RoomPacketIn;

typedef struct {
    /* A member joined; the server has already assigned it a fake IP. */
    void (*on_join)(RoomServer *s, const RoomMemberInfo *member, void *user);
    /* A member left (or timed out). */
    void (*on_leave)(RoomServer *s, int member_id, void *user);
    /* IdLdnPacket / IdProxyPacket from a member; payload already decoded. */
    void (*on_packet)(RoomServer *s, int member_id, const RoomPacketIn *pkt, void *user);
} RoomHandlers;

/* `handlers` may be NULL (nothing will be reported). */
RoomServer *room_server_create(const char *bind_addr, uint16_t port,
                               const RoomHandlers *handlers, void *user,
                               const char *room_name, const char *room_description,
                               const char *host_username, uint32_t member_slots);
void room_server_set_idle_timeout_ms(RoomServer *server, uint64_t ms);

void room_server_destroy(RoomServer *server);
/*
 * Service the socket: read every pending datagram, not just one. A room
 * broadcasts IdRoomInformation and IdLdnPacket to all members, so reading a
 * single datagram per call silently drops traffic whenever more than one
 * member is present.
 */
void room_server_poll(RoomServer *server, int timeout_ms);

/* Accessors used by the bridge. */
size_t room_server_members(const RoomServer *server, RoomMemberInfo *out, size_t cap);int room_server_find_by_fake_ip(const RoomServer *server, const uint8_t fake_ip[4]);

/* Outgoing. */
void room_send_join_success(RoomServer *server, int member_id);
/*
 * Send the rejection that matches `reason`. Eden has no generic error packet,
 * so an unmapped reason falls back to IdCloseRoom, which at least unblocks the
 * emulator instead of leaving it waiting forever.
 */
void room_send_reject(RoomServer *server, int member_id, RoomRejectReason reason);
void room_broadcast_information(RoomServer *server);

/*
 * IdLdnPacket / IdProxyPacket relay, used to echo real-console traffic back
 * into the room. `to_sender` controls direction (false = to everyone else).
 */
void room_send_ldn_packet(RoomServer *server, int member_id, LDNPacketType type,
                          const uint8_t local_ip[4], const uint8_t remote_ip[4],
                          bool broadcast, const void *data, uint32_t data_len);

/*
 * Network::Domain and Network::Protocol in Eden / yuzu.
 *
 * These are NOT the values used on the wire elsewhere: Domain::INET is 1, and
 * Protocol::UDP is 4, not the IP header's protocol number 17. Getting this
 * wrong makes Eden reject the packet silently in ProxySocket::HandleProxyPacket,
 * which compares packet.protocol against its own socket's protocol.
 */
#define ROOM_DOMAIN_INET 1
#define ROOM_PROTOCOL_UDP 4

/*
 * Relay real-console game traffic into the room as an IdProxyPacket.
 *
 * local_* is the sender (the console's LDN address), remote_* the recipient
 * (the emulator's game socket). The payload is ZSTD-compressed because
 * ProxySocket::SendPacket compresses before transmitting and
 * ProxySocket::HandleProxyPacket decompresses on receipt, so the room member
 * will not accept anything else.
 *
 * Returns 0 on success, -1 if the datagram could not be built or sent.
 */
int room_send_proxy_packet(RoomServer *server, int member_id,
                          const uint8_t local_ip[4], uint16_t local_port,
                          const uint8_t remote_ip[4], uint16_t remote_port,
                          bool broadcast, const void *data, uint32_t data_len);

/*
 * Decompress the ZSTD payload carried in an IdProxyPacket.
 *
 * Needed because the bridge is the relay, not the final consumer: Eden
 * compresses in ProxySocket::SendPacket and only the receiving game socket
 * decompresses, so without this the console would be handed compressed bytes.
 *
 * Returns the number of bytes written, or -1 if the input is not a valid ZSTD
 * frame.
 */
int room_proxy_decompress(const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t out_cap);

#endif /* SWITCH_LDN_ROOM_H */
