/*
 * Room protocol (Eden / yuzu lineage) wire-format tests.
 *
 * Every expected byte string below is transcribed from Eden's own
 * src/network/{room,room_member,packet}.cpp and common/announce_multiplayer_room.h,
 * so a mistake in our encoding shows up as a byte mismatch here rather than as
 * "the emulator silently does nothing" on a user's machine.
 */
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "room.h"
#include "common.h"
#include "ryuldn.h"

static const uint16_t PORT = 47913;

/*
 * Bounds-checked walk of a big-endian, u32-length-prefixed string field.
 * The serialiser used to truncate silently, so a walk that trusts the lengths
 * on the wire would read past the end of the datagram; assert instead.
 */
static size_t walk_str(const uint8_t *buf, size_t total, size_t *off)
{
    assert(*off + 4 <= total);
    size_t n = rd_be32(buf + *off);
    *off += 4;
    assert(*off + n <= total);
    *off += n;
    return n;
}

static uint32_t g_joins = 0;
static uint32_t g_packets = 0;
static uint8_t g_first_fake_ip[4] = {0xFF, 0xFF, 0xFF, 0xFF};

/* Decoded IdSetGameInfo, for verifying the u64 title id byte order. */
static uint8_t g_passphrase[64];
static uint32_t g_passphrase_len;
static bool g_scan_decoded;
static uint8_t g_scan_type;
static uint64_t g_game_id;
static char g_game_name[200];
static char g_game_version[16];

static void on_join(RoomServer *server, const RoomMemberInfo *member, void *user)
{
    (void)server;
    (void)user;
    if (g_joins == 0) {
        memcpy(g_first_fake_ip, member->fake_ip, 4);
    }
    g_joins++;
}

static void on_leave(RoomServer *server, int member_id, void *user)
{
    (void)server;
    (void)member_id;
    (void)user;
}

static void on_packet(RoomServer *server, int member_id, const RoomPacketIn *pkt,
                     void *user)
{
    (void)server;
    (void)member_id;
    (void)user;
    g_packets++;

    if (pkt->type == IdSetGameInfo) {
        g_game_id = pkt->game_id;
        snprintf(g_game_name, sizeof(g_game_name), "%s", pkt->game_name);
        snprintf(g_game_version, sizeof(g_game_version), "%s", pkt->game_version);
    } else if (pkt->type == IdLdnPacket) {
        g_scan_decoded = true;
        g_scan_type = pkt->ldn_packet_type;
        g_passphrase_len = pkt->passphrase_len;
        if (pkt->passphrase_len) {
            memcpy(g_passphrase, pkt->passphrase,
                   pkt->passphrase_len < sizeof(g_passphrase) ? pkt->passphrase_len
                                                              : sizeof(g_passphrase));
        }
    }
}

/* ---- encoding helpers matching Eden's Packet class ------------------- */

static void exp_u8(uint8_t *buf, size_t *len, uint8_t v)
{
    buf[(*len)++] = v;
}

static void exp_u16(uint8_t *buf, size_t *len, uint16_t v)
{
    wr_be16(buf + *len, v);
    *len += 2;
}

static void exp_u32(uint8_t *buf, size_t *len, uint32_t v)
{
    wr_be32(buf + *len, v);
    *len += 4;
}

static void exp_str(uint8_t *buf, size_t *len, const char *s)
{
    wr_be32(buf + *len, (uint32_t)strlen(s));
    *len += 4;
    memcpy(buf + *len, s, strlen(s));
    *len += strlen(s);
}

static void exp_ip(uint8_t *buf, size_t *len, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    buf[(*len)++] = a;
    buf[(*len)++] = b;
    buf[(*len)++] = c;
    buf[(*len)++] = d;
}

/* Build an IdJoinRequest for the given nickname. */
static size_t build_join_request(uint8_t *buf, const char *nickname)
{
    size_t len = 0;
    exp_u8(buf, &len, IdJoinRequest);
    exp_str(buf, &len, nickname);
    exp_ip(buf, &len, 0xFF, 0xFF, 0xFF, 0xFF); /* NoPreferredIP */
    exp_u32(buf, &len, ROOM_NETWORK_VERSION);
    exp_str(buf, &len, ""); /* password */
    exp_str(buf, &len, "tok");
    return len;
}

/* The test socket is unconnected, so datagrams must use sendto(). */
static struct sockaddr_in SERVER_ADDR;

static int sendto_server(int udp, const void *buf, size_t len)
{
    return sendto(udp, buf, len, 0, (struct sockaddr *)&SERVER_ADDR, sizeof(SERVER_ADDR));
}

static ssize_t drain(int udp, RoomServer *server, uint8_t *resp, size_t cap)
{
    for (int i = 0; i < 60; i++) {
        ssize_t n = recv(udp, resp, cap, MSG_DONTWAIT);
        if (n > 0) {
            return n;
        }
        room_server_poll(server, 0);
        usleep(3 * 1000);
    }
    return -1;
}

int main(void)
{
    /* assert() aborts, which would swallow buffered stdout. */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* ---- constants that must match Eden exactly ---- */
    assert(ROOM_NETWORK_VERSION == 1);
    assert(ROOM_DEFAULT_PORT == 24872);
    /*
     * NOTE: Network::MaxMessageSize == 500 in Eden, but it is *not* asserted
     * here because it is a chat-message limit, not a datagram limit. Eden's own
     * BroadcastRoomInformation() writes a full member list with no size check
     * at all; see the "full room" section below.
     */
    assert(IdJoinRequest == 1 && IdJoinSuccess == 2 && IdRoomInformation == 3 &&
           IdSetGameInfo == 4 && IdProxyPacket == 5 && IdLdnPacket == 6);
    assert(LDNPacketTypeScan == 0 && LDNPacketTypeScanResp == 1 &&
           LDNPacketTypeConnect == 2 && LDNPacketTypeSyncNetwork == 3 &&
           LDNPacketTypeDisconnect == 4 && LDNPacketTypeDestroyNetwork == 5);

    /* ---- fake IP space must be 192.168.x.y with no 0.0 address ---- */
    {
        RoomServer *probe = room_server_create("127.0.0.1", 47914, NULL, NULL, "p", "", "",
                                               8);
        assert(probe != NULL);
        RoomMemberInfo list[ROOM_MAX_MEMBERS];
        assert(room_server_members(probe, list, ROOM_MAX_MEMBERS) == 0);
        room_server_destroy(probe);
        printf("empty room reports no members\n");
    }

    /* ---- live session ---- */
    RoomHandlers handlers = {on_join, on_leave, on_packet};
    RoomServer *server =
        room_server_create("127.0.0.1", PORT, &handlers, NULL, "TestRoom", "desc", "host",
                           LDN_NODE_MAX);
    if (!server) {
        fprintf(stderr, "room_server_create failed\n");
        return 1;
    }

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) {
        fprintf(stderr, "socket failed\n");
        return 1;
    }
    memset(&SERVER_ADDR, 0, sizeof(SERVER_ADDR));
    SERVER_ADDR.sin_family = AF_INET;
    SERVER_ADDR.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &SERVER_ADDR.sin_addr);

    uint8_t req[512];
    size_t req_len = build_join_request(req, "TestPlayer");
    assert(sizeof(req) >= req_len);
    /* 1 + (4+10) + 4 + 4 + (4+0) + (4+3) */
    assert(req_len == 34);
    if (sendto_server(udp, req, req_len) < 0) {
        return 1;
    }
    room_server_poll(server, 0);

    uint8_t resp[16384];
    ssize_t n = drain(udp, server, resp, sizeof(resp));
    if (n < 0) {
        fprintf(stderr, "no reply to IdJoinRequest\n");
        return 1;
    }
    /* Eden's SendJoinSuccess writes exactly: u8 type + u8[4] fake_ip */
    assert(resp[0] == IdJoinSuccess);
    assert(n == 5);
    assert(g_joins == 1);
    printf("IdJoinSuccess: %u.%u.%u.%u (%zd bytes)\n", resp[1], resp[2], resp[3],
           resp[4], n);

    /* fake IP must be inside 192.168.x.y and non-zero */
    assert(resp[1] == 192 && resp[2] == 168);
    assert(resp[3] >= 1 && resp[4] >= 1);
    assert(room_server_find_by_fake_ip(server, resp + 1) == 1);

    /* ---- a second member must get a different IP ---- */
    /* A second UDP socket models a second ENet peer, which is how Eden
     * distinguishes members. */
    int udp2 = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp2 < 0) {
        return 1;
    }
    size_t len2 = build_join_request(req, "SecondPlayer");
    if (sendto(udp2, req, len2, 0, (struct sockaddr *)&SERVER_ADDR,
               sizeof(SERVER_ADDR)) < 0) {
        return 1;
    }
    room_server_poll(server, 0);

    uint8_t resp2[2048];
    bool got_second = false;
    for (int i = 0; i < 60; i++) {
        n = recv(udp2, resp2, sizeof(resp2), MSG_DONTWAIT);
        if (n == 5 && resp2[0] == IdJoinSuccess) {
            if (resp2[1] == 192 && resp2[2] == 168 && resp2[3] >= 1 && resp2[4] >= 1) {
                assert(room_server_find_by_fake_ip(server, resp2 + 1) == 2);
                assert(memcmp(resp2 + 1, g_first_fake_ip, 4) != 0);
                printf("second member: %u.%u.%u.%u (no collision)\n", resp2[1], resp2[2],
                       resp2[3], resp2[4]);
                got_second = true;
                break;
            }
        }
        room_server_poll(server, 0);
        usleep(3 * 1000);
    }
    assert(got_second);
    assert(g_joins == 2);

    /* ================================================================ */
    /* IdLdnPacket{Scan} in Eden's encoding                                */
    /* ================================================================ */
    for (int with_passphrase = 0; with_passphrase < 2; with_passphrase++) {
    printf("--- run %s the trailing passphrase ---\n",
           with_passphrase ? "WITH" : "WITHOUT");
    uint8_t scan[256];
    size_t scan_len = 0;
    g_passphrase_len = 0;
    g_scan_decoded = false;
    g_scan_type = 0xFF;
    exp_u8(scan, &scan_len, IdLdnPacket);
    exp_u8(scan, &scan_len, LDNPacketTypeScan);
    exp_ip(scan, &scan_len, 192, 168, 0, 1); /* local_ip  */
    exp_ip(scan, &scan_len, 0, 0, 0, 0);     /* remote_ip */
    exp_u8(scan, &scan_len, 1);              /* broadcast = true */
    exp_u32(scan, &scan_len, 0);             /* empty data vector */
    assert(scan_len == 15); /* 1+1+4+4+1+4 */

    /* Stock Eden stops here. The patched build appends the passphrase as one
     * more length-prefixed blob; a stock parser reads past it. */
    if (with_passphrase) {
        exp_u32(scan, &scan_len, 4);
        memcpy(scan + scan_len, "PIA!", 4);
        scan_len += 4;
        assert(scan_len == 23);
    }

    uint32_t before = g_packets;
    if (sendto_server(udp, scan, scan_len) < 0) {
        return 1;
    }
    room_server_poll(server, 0);
    for (int i = 0; i < 40; i++) {
        if (g_packets > before) {
            break;
        }
        room_server_poll(server, 0);
        usleep(3 * 1000);
    }
    assert(g_packets == before + 1);

    /* The packet must actually reach the handler as a Scan, and the trailing
     * passphrase - the whole point of patches/eden-room-passphrase.patch -
     * must be surfaced (or correctly absent) rather than silently dropped. */
    assert(g_scan_decoded);
    assert(g_scan_type == LDNPacketTypeScan);
    if (with_passphrase) {
        assert(g_passphrase_len == 4);
        assert(memcmp(g_passphrase, "PIA!", 4) == 0);
    } else {
        assert(g_passphrase_len == 0);
    }
    printf("IdLdnPacket{Scan} decoded (%zu bytes, passphrase=%u)\n", scan_len,
           g_passphrase_len);

    /* ================================================================ */
    /* IdProxyPacket in Eden's encoding: 4 endpoint fields + payload       */
    /* ================================================================ */
    uint8_t proxy[256];
    size_t proxy_len = 0;
    exp_u8(proxy, &proxy_len, IdProxyPacket);
    exp_u8(proxy, &proxy_len, 2);                  /* local family   */
    exp_ip(proxy, &proxy_len, 192, 168, 0, 1);      /* local ip       */
    exp_u16(proxy, &proxy_len, 1234);               /* local port     */
    exp_u8(proxy, &proxy_len, 2);                  /* remote family  */
    exp_ip(proxy, &proxy_len, 0, 0, 0, 0);          /* remote ip      */
    exp_u16(proxy, &proxy_len, 0);                 /* remote port    */
    exp_u8(proxy, &proxy_len, 17);                 /* protocol = UDP */
    exp_u8(proxy, &proxy_len, 0);                  /* broadcast = false */
    exp_u32(proxy, &proxy_len, 4);                 /* data vector */
    memcpy(proxy + proxy_len, "PIA!", 4);
    proxy_len += 4;
    assert(proxy_len == 25); /* 1+1+4+2+1+4+2+1+1+4+4 */

    before = g_packets;
    if (sendto_server(udp, proxy, proxy_len) < 0) {
        return 1;
    }
    room_server_poll(server, 0);
    for (int i = 0; i < 40; i++) {
        if (g_packets > before) {
            break;
        }
        room_server_poll(server, 0);
        usleep(3 * 1000);
    }
    assert(g_packets == before + 1);
    printf("IdProxyPacket decoded (%zu bytes, payload 'PIA!')\n", proxy_len);

    /* ================================================================ */
    /* IdRoomInformation: our encoder must produce a walkable packet      */
    /* ================================================================ */
    /*
     * IdRoomInformation layout, as Eden's BroadcastRoomInformation writes it
     * and HandleRoomInformationPacket reads it back:
     *   u8 type, string name, string description, u32 member_slots, u16 port,
     *   string preferred_game.name, string host_username, u32 num_members
     */
    room_broadcast_information(server);

    /*
     * Every join broadcasts a fresh IdRoomInformation, so several are queued.
     * Keep reading until the socket goes quiet and decode the LAST one.
     */
    ssize_t last_len = -1;
    uint8_t last[2048];
    for (int attempt = 0; attempt < 40; attempt++) {
        room_server_poll(server, 0);
        ssize_t got = recv(udp, resp, sizeof(resp), MSG_DONTWAIT);
        if (got > 0) {
            if (resp[0] == IdRoomInformation) {
                memcpy(last, resp, (size_t)got);
                last_len = got;
            }
        } else {
            if (last_len >= 0) {
                break;
            }
            usleep(3 * 1000);
        }
    }
    if (last_len < 0) {
        fprintf(stderr, "no IdRoomInformation received\n");
        return 1;
    }
    memcpy(resp, last, (size_t)last_len);
    n = last_len;

    if (n < 1 + 4 + 8 + 4 + 4 + 2 + 4 + 4 + 4) {
        fprintf(stderr, "IdRoomInformation too short (%zd)\n", n);
        return 1;
    }
    assert(resp[0] == IdRoomInformation);

    size_t off = 1;
    assert(walk_str(resp, (size_t)n, &off) == strlen("TestRoom"));
    assert(memcmp(resp + off - strlen("TestRoom"), "TestRoom", strlen("TestRoom")) == 0);

    size_t desc_len = walk_str(resp, (size_t)n, &off);
    (void)desc_len;

    uint32_t slots = 0;
    uint16_t port = 0;
    uint32_t members = 0;
    assert(off + 4 <= (size_t)n);
    slots = rd_be32(resp + off);
    off += 4;
    assert(off + 2 <= (size_t)n);
    port = rd_be16(resp + off);
    off += 2;

    walk_str(resp, (size_t)n, &off); /* preferred_game.name */
    walk_str(resp, (size_t)n, &off); /* host_username */

    assert(off + 4 <= (size_t)n);
    members = rd_be32(resp + off);
    off += 4;
    assert(members == 2);
    printf("IdRoomInformation: name='%s' slots=%u port=%u members=%u\n", "TestRoom",
           slots, port, members);

    /*
     * Walk the members field by field. If the serialiser dropped or
     * duplicated anything the walk will not land exactly on the end of the
     * datagram, so this is the truncation tripwire.
     */
    for (uint32_t i = 0; i < members; i++) {
        walk_str(resp, (size_t)n, &off); /* nickname */
        assert(off + 4 <= (size_t)n);
        off += 4; /* fake_ip */
        walk_str(resp, (size_t)n, &off); /* game name */
        assert(off + 8 <= (size_t)n);
        off += 8; /* game id */
        walk_str(resp, (size_t)n, &off); /* game version */
        walk_str(resp, (size_t)n, &off); /* username */
        walk_str(resp, (size_t)n, &off); /* display_name */
        walk_str(resp, (size_t)n, &off); /* avatar_url */
    }
    assert(off == (size_t)n);
    printf("  walked all %u members, %zd bytes, ended exactly at EOF\n", members, n);

    close(udp2);

    /* ================================================================ */
    /* IdSetGameInfo must trigger the passphrase gate                     */
    /* (Room carries no LDN crypto passphrase, unlike RyuLdn)            */
    /* ================================================================ */
    uint8_t gi[512];
    size_t gi_len = 0;
    exp_u8(gi, &gi_len, IdSetGameInfo);
    exp_str(gi, &gi_len, "Diablo III: Eternal Collection");
    /* u64 written as two big-endian u32 halves: 01001B300B9BE000 */
    exp_u32(gi, &gi_len, 0x01001B30u);
    exp_u32(gi, &gi_len, 0x0B9BE000u);
    exp_str(gi, &gi_len, "2.7.7.92380");

    if (sendto_server(udp, gi, gi_len) < 0) {
        return 1;
    }
    for (int i = 0; i < 40 && g_game_id == 0; i++) {
        room_server_poll(server, 0);
        usleep(3 * 1000);
    }
    /* The u64 is written big-endian by Eden's Packet, and our two u32 halves
     * must put it back together in the same order. */
    assert(g_game_id == 0x01001B300B9BE000ull);
    assert(!strcmp(g_game_name, "Diablo III: Eternal Collection"));
    assert(!strcmp(g_game_version, "2.7.7.92380"));
    printf("IdSetGameInfo decoded: '%s' id=%016llx version='%s'\n", g_game_name,
           (unsigned long long)g_game_id, g_game_version);

    }

    /* ================================================================ */
    /* A FULL room must arrive in ONE datagram - never truncated         */
    /* ================================================================ */
    /*
     * This is the case that used to fail silently. Every member carrying
     * maximal-length fields is ~377 bytes, and a full room of them needs
     * ~3.2 KB - well past the 2048-byte buffer the serialiser used to have.
     * pk_* stopped growing the buffer and set ok=false, so the member list
     * went out cut off with nothing logged. Rebuild that worst case.
     */
    {
        static const uint16_t BIG_PORT = (uint16_t)(PORT + 2);
        /* The room identifies a member by its sockaddr, so each member needs
         * its own socket bound to its own port - one socket would just
         * re-join the same member over and over. */
        static const int NMEM = LDN_NODE_MAX - 1;
        RoomServer *big =
            room_server_create("127.0.0.1", BIG_PORT, NULL, NULL, "BigRoom", "d", "h",
                               LDN_NODE_MAX);
        assert(big != NULL);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(BIG_PORT);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);

        int socks[LDN_NODE_MAX];
        for (int i = 0; i < NMEM; i++) {
            int s = socket(AF_INET, SOCK_DGRAM, 0);
            assert(s >= 0);
            struct sockaddr_in self;
            memset(&self, 0, sizeof(self));
            self.sin_family = AF_INET;
            self.sin_addr.s_addr = htonl(INADDR_ANY);
            self.sin_port = htons((uint16_t)(31000 + i));
            assert(bind(s, (struct sockaddr *)&self, sizeof(self)) == 0);
            assert(connect(s, (struct sockaddr *)&a, sizeof(a)) == 0);
            socks[i] = s;
        }

        char nick[128];
        char game[200];
        memset(nick, 'N', sizeof(nick) - 1);
        memset(game, 'G', sizeof(game) - 1);
        nick[sizeof(nick) - 1] = '\0';
        game[sizeof(game) - 1] = '\0';

        uint8_t pkt[1024];
        uint8_t r[8];
        for (int i = 0; i < NMEM; i++) {
            /* distinct nicknames, otherwise the room is not realistic */
            snprintf(nick + sizeof(nick) - 5, 5, "%04d", i);
            size_t l = build_join_request(pkt, nick);
            assert(send(socks[i], pkt, l, 0) == (ssize_t)l);
            room_server_poll(big, 0);
            assert(recv(socks[i], r, sizeof(r), 0) == 5 && r[0] == IdJoinSuccess);

            l = 0;
            exp_u8(pkt, &l, IdSetGameInfo);
            exp_str(pkt, &l, game);
            exp_u32(pkt, &l, 0x0000ABCDu);
            exp_u32(pkt, &l, 0x0000EF01u);
            exp_str(pkt, &l, "1.2.3");
            assert(send(socks[i], pkt, l, 0) == (ssize_t)l);
            room_server_poll(big, 0);
            /* every join and game-info triggers a broadcast; drain them */
            for (int k = 0; k < 16; k++) {
                if (recv(socks[i], r, sizeof(r), MSG_DONTWAIT) <= 0) {
                    break;
                }
                room_server_poll(big, 0);
            }
        }

        /*
         * A broadcast goes to every member, so the backlog is spread over all
         * sockets. Drain them all or the next read picks up a stale snapshot
         * from an earlier stage of the fill.
         */
        for (int round = 0; round < 4; round++) {
            for (int i = 0; i < NMEM; i++) {
                while (recv(socks[i], r, sizeof(r), MSG_DONTWAIT) > 0) {
                }
            }
            room_server_poll(big, 0);
        }

        static uint8_t info[16384];
        room_broadcast_information(big);
        ssize_t got = -1;
        for (int attempt = 0; attempt < 100; attempt++) {
            room_server_poll(big, 0);
            got = recv(socks[0], info, sizeof(info), MSG_DONTWAIT);
            if (got > 0 && info[0] == IdRoomInformation) {
                break;
            }
            usleep(3 * 1000);
        }
        assert(got > 0);
        assert(info[0] == IdRoomInformation);

        size_t o = 1;
        walk_str(info, (size_t)got, &o); /* name */
        walk_str(info, (size_t)got, &o); /* description */
        assert(o + 4 + 2 <= (size_t)got);
        o += 4; /* member_slots */
        o += 2; /* port */
        walk_str(info, (size_t)got, &o); /* preferred_game.name */
        walk_str(info, (size_t)got, &o); /* host_username */
        assert(o + 4 <= (size_t)got);
        uint32_t total = rd_be32(info + o);
        o += 4;
        assert(total == (uint32_t)NMEM);
        for (uint32_t i = 0; i < total; i++) {
            walk_str(info, (size_t)got, &o); /* nickname */
            assert(o + 4 <= (size_t)got);
            o += 4; /* fake_ip */
            walk_str(info, (size_t)got, &o); /* game name */
            assert(o + 8 <= (size_t)got);
            o += 8; /* game id */
            walk_str(info, (size_t)got, &o); /* game version */
            walk_str(info, (size_t)got, &o); /* username */
            walk_str(info, (size_t)got, &o); /* display_name */
            walk_str(info, (size_t)got, &o); /* avatar_url */
        }
        assert(o == (size_t)got);
        assert(got > 2048); /* the old serialiser buffer could not hold this */
        printf("full-room RoomInformation: %u members in %zd bytes, walk ends at "
               "EOF\n",
               total, got);

        for (int i = 0; i < NMEM; i++) {
            close(socks[i]);
        }
        room_server_destroy(big);
    }

    /* ================================================================ */
    /* A full room must reject the next join with IdRoomIsFull           */
    /* ================================================================ */
    /*
     * Eden's HandleJoinRequest returns IdRoomIsFull as soon as
     * members.size() >= room_information.member_slots. The bridge used to stop
     * only at its own table size, so a ninth member was accepted into a room
     * the game opened for eight.
     */
    {
        static const uint16_t FULL_PORT = (uint16_t)(PORT + 4);
        static const uint32_t SLOTS = 2;
        RoomServer *small = room_server_create("127.0.0.1", FULL_PORT, NULL, NULL,
                                              "Small", "d", "h", SLOTS);
        assert(small != NULL);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(FULL_PORT);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);

        uint8_t r[64];
        /* SLOTS members join normally. */
        for (uint32_t i = 0; i < SLOTS; i++) {
            int s = socket(AF_INET, SOCK_DGRAM, 0);
            assert(s >= 0);
            struct sockaddr_in self;
            memset(&self, 0, sizeof(self));
            self.sin_family = AF_INET;
            self.sin_addr.s_addr = htonl(INADDR_ANY);
            self.sin_port = htons((uint16_t)(32000 + i));
            assert(bind(s, (struct sockaddr *)&self, sizeof(self)) == 0);
            assert(connect(s, (struct sockaddr *)&a, sizeof(a)) == 0);
            char nm[16];
            snprintf(nm, sizeof(nm), "player%u", i);
            uint8_t jr[256];
            size_t jl = build_join_request(jr, nm);
            assert(send(s, jr, jl, 0) == (ssize_t)jl);
            room_server_poll(small, 0);
            assert(recv(s, r, sizeof(r), 0) == 5 && r[0] == IdJoinSuccess);
            close(s);
        }

        /* The member list must report the real members, not a padded count. */
        {
            RoomMemberInfo list[ROOM_MAX_MEMBERS];
            size_t got = room_server_members(small, list, ROOM_MAX_MEMBERS);
            assert(got == SLOTS);
            assert(!strcmp(list[0].nickname, "player0"));
            assert(!strcmp(list[SLOTS - 1].nickname, "player1"));
            RoomMemberInfo tiny[1];
            assert(room_server_members(small, tiny, 1) == 1); /* respects cap */
            printf("member list reports %zu of %u members\n", got, SLOTS);
        }

        /* The next one is told the room is full, not silently accepted. */
        int late = socket(AF_INET, SOCK_DGRAM, 0);
        assert(late >= 0);
        struct sockaddr_in lself;
        memset(&lself, 0, sizeof(lself));
        lself.sin_family = AF_INET;
        lself.sin_addr.s_addr = htonl(INADDR_ANY);
        lself.sin_port = htons(32990);
        assert(bind(late, (struct sockaddr *)&lself, sizeof(lself)) == 0);
        assert(connect(late, (struct sockaddr *)&a, sizeof(a)) == 0);
        uint8_t jr[256];
        size_t jl = build_join_request(jr, "latecomer");
        assert(send(late, jr, jl, 0) == (ssize_t)jl);
        room_server_poll(small, 0);
        ssize_t got = recv(late, r, sizeof(r), 0);
        assert(got == 1); /* IdRoomIsFull carries no payload */
        assert(r[0] == IdRoomIsFull);
        printf("room is full after %u members: IdRoomIsFull\n", SLOTS);

        /* An existing member still gets through when the room is full. */
        int again = socket(AF_INET, SOCK_DGRAM, 0);
        assert(again >= 0);
        struct sockaddr_in aself;
        memset(&aself, 0, sizeof(aself));
        aself.sin_family = AF_INET;
        aself.sin_addr.s_addr = htonl(INADDR_ANY);
        aself.sin_port = htons(32000); /* same address as player0 */
        assert(bind(again, (struct sockaddr *)&aself, sizeof(aself)) == 0);
        assert(connect(again, (struct sockaddr *)&a, sizeof(a)) == 0);
        size_t al = build_join_request(jr, "player0");
        assert(send(again, jr, al, 0) == (ssize_t)al);
        room_server_poll(small, 0);
        assert(recv(again, r, sizeof(r), 0) == 5 && r[0] == IdJoinSuccess);
        printf("re-sync from an existing member still succeeds when full\n");

        /*
         * But the room must not fill up for good. Both members are about to
         * go quiet, so with a 1 ms idle timeout the next join is allowed to
         * reclaim a slot instead of being refused - otherwise a member that
         * closed its socket would hold the room hostage permanently.
         */
        room_server_set_idle_timeout_ms(small, 1);
        close(again);
        usleep(5 * 1000);

        int next = socket(AF_INET, SOCK_DGRAM, 0);
        assert(next >= 0);
        struct sockaddr_in nself;
        memset(&nself, 0, sizeof(nself));
        nself.sin_family = AF_INET;
        nself.sin_addr.s_addr = htonl(INADDR_ANY);
        nself.sin_port = htons(33001);
        assert(bind(next, (struct sockaddr *)&nself, sizeof(nself)) == 0);
        assert(connect(next, (struct sockaddr *)&a, sizeof(a)) == 0);
        size_t nl = build_join_request(jr, "reclaimer");
        assert(send(next, jr, nl, 0) == (ssize_t)nl);
        room_server_poll(small, 0);
        assert(recv(next, r, sizeof(r), 0) == 5 && r[0] == IdJoinSuccess);
        printf("idle members are reclaimed, so a full room is not permanent\n");

        close(late);
        close(next);

        /* A bad protocol version must also reach the peer, instead of being
         * dropped and leaving it waiting for a JoinSuccess forever. */
        int bad = socket(AF_INET, SOCK_DGRAM, 0);
        assert(bad >= 0);
        struct sockaddr_in bself;
        memset(&bself, 0, sizeof(bself));
        bself.sin_family = AF_INET;
        bself.sin_addr.s_addr = htonl(INADDR_ANY);
        bself.sin_port = htons(32991);
        assert(bind(bad, (struct sockaddr *)&bself, sizeof(bself)) == 0);
        assert(connect(bad, (struct sockaddr *)&a, sizeof(a)) == 0);
        uint8_t bv[128];
        size_t bvl = 0;
        exp_u8(bv, &bvl, IdJoinRequest);
        exp_str(bv, &bvl, "wrongversion");
        exp_ip(bv, &bvl, 0xFF, 0xFF, 0xFF, 0xFF);
        exp_u32(bv, &bvl, ROOM_NETWORK_VERSION + 1u);
        exp_str(bv, &bvl, "");
        exp_str(bv, &bvl, "tok");
        assert(send(bad, bv, bvl, 0) == (ssize_t)bvl);
        room_server_poll(small, 0);
        assert(recv(bad, r, sizeof(r), 0) == 1 && r[0] == IdVersionMismatch);
        printf("version mismatch: IdVersionMismatch (not swallowed)\n");
        close(bad);

        room_server_destroy(small);
    }

    /* ---- one poll() must drain more than one queued datagram ---- */
    /* Two members are connected, so a broadcast reaches both. Send a burst of
     * scans and confirm the bridge consumes all of them in a single poll. */
    /* Build a fresh scan burst: several datagrams queued at once. */
    uint8_t burst[128];
    size_t burst_len = 0;
    exp_u8(burst, &burst_len, IdLdnPacket);
    exp_u8(burst, &burst_len, LDNPacketTypeScan);
    exp_ip(burst, &burst_len, 192, 168, 0, 1);
    exp_ip(burst, &burst_len, 0, 0, 0, 0);
    exp_u8(burst, &burst_len, 1);
    exp_u32(burst, &burst_len, 0);
    assert(burst_len == 15);

    /* Drain anything still queued so the burst count starts clean. */
    for (int i = 0; i < 8; i++) {
        room_server_poll(server, 0);
    }
    uint32_t seen_before = g_packets;
    for (int i = 0; i < 8; i++) {
        if (sendto_server(udp, burst, burst_len) < 0) {
            return 1;
        }
        usleep(2 * 1000);
    }
    room_server_poll(server, 0);
    uint32_t drained = g_packets - seen_before;
    if (drained < 8) {
        printf("drain: only %u of 8 datagrams read in one poll\n", drained);
        return 1;
    }
    printf("drain: %u datagrams in a single poll (expected 8)\n", drained);

    /* ================================================================ */
    /* IdProxyPacket in the console -> room direction                    */
    /* ================================================================ */
    /*
     * This is the real-console game-traffic uplink. It is laid out exactly as
     * Eden's RoomMember::SendProxyPacket writes it, so it must parse back the
     * same way Eden's ProxySocket::HandleProxyPacket expects: the two Domain
     * values are INET (1), the protocol is Eden's Protocol::UDP (4, not the IP
     * header's 17), and the payload is a zstd frame because only the receiving
     * game socket decompresses.
     */
    {
        static const uint16_t PROXY_PORT = (uint16_t)(PORT + 6);
        RoomServer *px = room_server_create("127.0.0.1", PROXY_PORT, NULL, NULL, "px",
                                            "d", "h", LDN_NODE_MAX);
        assert(px != NULL);
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        assert(s >= 0);
        struct sockaddr_in a2;
        memset(&a2, 0, sizeof(a2));
        a2.sin_family = AF_INET;
        a2.sin_port = htons(PROXY_PORT);
        inet_pton(AF_INET, "127.0.0.1", &a2.sin_addr);
        assert(connect(s, (struct sockaddr *)&a2, sizeof(a2)) == 0);

        uint8_t jr[256];
        size_t jl = build_join_request(jr, "console0");
        assert(send(s, jr, jl, 0) == (ssize_t)jl);
        room_server_poll(px, 0);
        uint8_t rr[8];
        assert(recv(s, rr, sizeof(rr), 0) == 5 && rr[0] == IdJoinSuccess);
        int who = room_server_find_by_fake_ip(px, rr + 1);
        assert(who > 0);
        /* the fake IP we assigned is the room member's identity */
        uint8_t myip[4];
        memcpy(myip, rr + 1, 4);
        uint8_t guestip[4] = {10, 114, 0, 1};

        /* a join broadcasts IdRoomInformation; consume it first */
        for (int k = 0; k < 8; k++) {
            if (recv(s, rr, sizeof(rr), MSG_DONTWAIT) <= 0) {
                break;
            }
            room_server_poll(px, 0);
        }

        static const char payload[] = "LDN_PASS!hello from the console";
        assert(room_send_proxy_packet(px, who, myip, 40000, guestip, 30000, false,
                                      payload, (uint32_t)sizeof(payload) - 1) == 0);

        uint8_t buf[4096];
        ssize_t got = recv(s, buf, sizeof(buf), 0);
        assert(got > 0);
        assert(buf[0] == IdProxyPacket);

        size_t o = 1;
        assert(buf[o] == ROOM_DOMAIN_INET);
        o += 1;
        assert(o + 4 <= (size_t)got && memcmp(buf + o, myip, 4) == 0);
        o += 4;
        assert(o + 2 <= (size_t)got && rd_be16(buf + o) == 40000);
        o += 2;
        assert(buf[o] == ROOM_DOMAIN_INET);
        o += 1;
        assert(o + 4 <= (size_t)got && memcmp(buf + o, guestip, 4) == 0);
        o += 4;
        assert(o + 2 <= (size_t)got && rd_be16(buf + o) == 30000);
        o += 2;
        assert(buf[o] == ROOM_PROTOCOL_UDP);
        o += 1;
        assert(buf[o] == 0); /* broadcast */
        o += 1;

        uint32_t dlen = rd_be32(buf + o);
        o += 4;
        assert(o + dlen == (size_t)got); /* nothing dropped, nothing trailing */

        /* and the payload must round-trip through the same zstd step */
        uint8_t plain[2304];
        int plen = room_proxy_decompress(buf + o, dlen, plain, sizeof(plain));
        assert(plen == (int)(sizeof(payload) - 1));
        assert(memcmp(plain, payload, (size_t)plen) == 0);
        printf("IdProxyPacket: %zd bytes, domain=INET proto=UDP, payload round-trips"
               " (%d bytes)\n",
               got, plen);

        /* a non-zstd payload must be rejected, not relayed as garbage */
        assert(room_proxy_decompress((const uint8_t *)payload, sizeof(payload) - 1,
                                     plain, sizeof(plain)) == -1);

        close(s);
        room_server_destroy(px);
    }

    printf("room wire format matches Eden\n");
    close(udp);
    room_server_destroy(server);
    return 0;
}
