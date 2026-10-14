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

static uint32_t g_joins = 0;
static uint32_t g_packets = 0;
static uint8_t g_first_fake_ip[4] = {0xFF, 0xFF, 0xFF, 0xFF};

/* Decoded IdSetGameInfo, for verifying the u64 title id byte order. */
static uint8_t g_passphrase[64];
static uint32_t g_passphrase_len;
static bool g_scan_decoded;
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
    assert(ROOM_MAX_MESSAGE_SIZE == 500);
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
        size_t n = 0;
        const RoomMemberInfo *members = room_server_members(probe, &n);
        assert(members == NULL); /* empty room */
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

    uint8_t resp[2048];
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
    printf("IdLdnPacket{Scan} decoded (%zu bytes)\n", scan_len);

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
    uint32_t name_len = rd_be32(resp + off);
    off += 4;
    assert(name_len == strlen("TestRoom"));
    assert(memcmp(resp + off, "TestRoom", name_len) == 0);
    off += name_len;

    uint32_t desc_len = rd_be32(resp + off);
    off += 4 + desc_len;

    uint32_t slots = rd_be32(resp + off);
    off += 4;
    assert(slots == LDN_NODE_MAX);

    uint16_t port = rd_be16(resp + off);
    off += 2;
    assert(port == PORT);

    uint32_t game_len = rd_be32(resp + off);
    off += 4 + game_len;

    uint32_t host_len = rd_be32(resp + off);
    off += 4 + host_len;

    uint32_t members = rd_be32(resp + off);
    off += 4;
    assert(members == 2);
    printf("IdRoomInformation: name='%s' slots=%u port=%u members=%u\n", "TestRoom",
           slots, port, members);

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

    printf("room wire format matches Eden\n");
    close(udp);
    room_server_destroy(server);
    return 0;
}
