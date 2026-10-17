#include "room.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <zstd.h>

#include "common.h"

/* ------------------------------------------------------------------ */
/* Members                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    RoomMemberInfo info;
    struct sockaddr_in addr;
    socklen_t addr_len;
    /* Monotonic ms of the last datagram from this peer. */
    uint64_t last_seen_ms;
} MemberSlot;

/*
 * A Room member that goes quiet for this long is treated as gone and its slot
 * reclaimed when the room needs the space.
 *
 * The Room protocol has no disconnect and no heartbeat - a plain-UDP member
 * that closes its socket just stops talking, and Eden never learns about it
 * either. Without this the room would fill up permanently: once the bridge
 * enforces member_slots, a member that closed its socket would keep its slot
 * forever and the emulator could never rejoin.
 */
#define ROOM_MEMBER_IDLE_TIMEOUT_MS 60000u

struct RoomServer {
    int fd;
    uint16_t port;
    RoomInformation information;
    RoomHandlers handlers;
    void *user;

    MemberSlot members[ROOM_MAX_MEMBERS];
    int member_count; /* successfully joined members */
    int next_id;      /* monotonically increasing member id */
    int next_fake_ip; /* walks 192.168.i.j */
    uint64_t member_idle_timeout_ms;
};

/* ------------------------------------------------------------------ */
/* Eden's Packet class: big-endian scalars, u32-length-prefixed blobs  */
/* ------------------------------------------------------------------ */

typedef struct {
    /*
     * Sized for a full 16-member RoomInformation broadcast, not for one
     * message: every member carries nickname + fake IP + game name/id/version +
     * username + display name + avatar url, which is ~708 bytes with those
     * fields at their maximum length (see RoomMemberInfo / RoomGameInfo in
     * room.h). A 16-member room needs ~11.9 KB, so anything smaller than this
     * silently truncates the member list - see room_broadcast_information().
     */
    uint8_t buf[12288];
    size_t len;
    size_t pos;
    bool ok;
} Packet;

#define PACKET_BUFSIZE sizeof(((Packet *)0)->buf)

static void pk_begin(Packet *p)
{
    memset(p, 0, sizeof(*p));
    p->ok = true;
}

/* Forward declarations: room_server_poll drains several datagrams per call. */
static int room_more_pending(RoomServer *server);
static void room_service_one(RoomServer *server);
static void pk_u8(Packet *p, uint8_t v)
{
    if (p->len + 1 > sizeof(p->buf)) {
        p->ok = false;
        return;
    }
    p->buf[p->len++] = v;
}

static void pk_u16(Packet *p, uint16_t v)
{
    if (p->len + 2 > sizeof(p->buf)) {
        p->ok = false;
        return;
    }
    wr_be16(p->buf + p->len, v);
    p->len += 2;
}

static void pk_u32(Packet *p, uint32_t v)
{
    if (p->len + 4 > sizeof(p->buf)) {
        p->ok = false;
        return;
    }
    wr_be32(p->buf + p->len, v);
    p->len += 4;
}

static void pk_u64(Packet *p, uint64_t v)
{
    if (p->len + 8 > sizeof(p->buf)) {
        p->ok = false;
        return;
    }
    wr_be64(p->buf + p->len, v);
    p->len += 8;
}

/* IPv4Address / bool / raw byte arrays are written verbatim. */
static void pk_raw(Packet *p, const void *data, size_t n)
{
    if (p->len + n > sizeof(p->buf)) {
        p->ok = false;
        return;
    }
    memcpy(p->buf + p->len, data, n);
    p->len += n;
}

/* std::string and std::vector<u8> share the (u32 length)(bytes) encoding. */
static void pk_str(Packet *p, const char *s)
{
    pk_u32(p, (uint32_t)strlen(s));
    pk_raw(p, s, strlen(s));
}

static uint8_t rd_u8(Packet *p)
{
    if (p->pos + 1 > p->len) {
        p->ok = false;
        return 0;
    }
    return p->buf[p->pos++];
}

static uint16_t rd_u16(Packet *p)
{
    if (p->pos + 2 > p->len) {
        p->ok = false;
        return 0;
    }
    uint16_t v = rd_be16(p->buf + p->pos);
    p->pos += 2;
    return v;
}

static uint32_t rd_u32(Packet *p)
{
    if (p->pos + 4 > p->len) {
        p->ok = false;
        return 0;
    }
    uint32_t v = rd_be32(p->buf + p->pos);
    p->pos += 4;
    return v;
}

static uint64_t rd_u64(Packet *p)
{
    if (p->pos + 8 > p->len) {
        p->ok = false;
        return 0;
    }
    uint64_t v = rd_be64(p->buf + p->pos);
    p->pos += 8;
    return v;
}

static bool rd_raw(Packet *p, void *out, size_t n)
{
    if (p->pos + n > p->len) {
        p->ok = false;
        return false;
    }
    memcpy(out, p->buf + p->pos, n);
    p->pos += n;
    return true;
}

static void rd_str(Packet *p, char *out, size_t out_len)
{
    uint32_t n = rd_u32(p);
    if (!p->ok || n >= out_len) {
        out[0] = '\0';
        p->ok = false;
        return;
    }
    if (!rd_raw(p, out, n)) {
        out[0] = '\0';
        return;
    }
    out[n] = '\0';
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static MemberSlot *find_by_addr(RoomServer *s, const struct sockaddr_in *addr)
{
    for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
        if (s->members[i].info.in_use &&
            s->members[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            s->members[i].addr.sin_port == addr->sin_port) {
            return &s->members[i];
        }
    }
    return NULL;
}

static MemberSlot *find_by_id(RoomServer *s, int member_id)
{
    for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
        if (s->members[i].info.in_use && s->members[i].info.id == member_id) {
            return &s->members[i];
        }
    }
    return NULL;
}

/*
 * Drop every joined member that has been quiet for longer than
 * ROOM_MEMBER_IDLE_TIMEOUT_MS. Active members are never touched.
 */
static void reclaim_idle_members(RoomServer *server, uint64_t now)
{
    if (!server->member_idle_timeout_ms) {
        return; /* eviction disabled */
    }
    for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
        MemberSlot *m = &server->members[i];
        if (!m->info.in_use || !m->last_seen_ms) {
            continue;
        }
        if (now - m->last_seen_ms <= server->member_idle_timeout_ms) {
            continue;
        }
        LOG_W("room: member %d ('%s') idle for %llums, dropping it", m->info.id,
              m->info.nickname,
              (unsigned long long)(now - m->last_seen_ms));
        if (server->handlers.on_leave) {
            server->handlers.on_leave(server, m->info.id, server->user);
        }
        memset(m, 0, sizeof(*m));
        server->member_count--;
    }
}

/* Same, but also matches a slot that is only *reserved* for a peer that has
 * not completed its join yet.
 *
 * Rejections are precisely the messages that must reach such a peer: the
 * version mismatch, name collision and room-is-full rejects all fire before
 * in_use is set. Looking the slot up the joined-only way makes find_by_id
 * return NULL, the reject is never sent, and the emulator waits forever on a
 * spinner - the exact failure this reject family exists to prevent.
 *
 * A free slot is all-zero, so it has id 0 and addr_len 0; member ids start at
 * 1, which is what makes this lookup unambiguous.
 */
static MemberSlot *find_by_id_any(RoomServer *s, int member_id)
{
    for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
        if (s->members[i].info.id == member_id && s->members[i].addr_len != 0) {
            return &s->members[i];
        }
    }
    return NULL;
}

/* Mirrors Eden's GenerateFakeIPAddress: first free 192.168.i.j. */
static void generate_fake_ip(RoomServer *s, uint8_t out[4])
{
    int start = s->next_fake_ip;
    for (int n = 0; n < 255 * 255; n++) {
        int idx = (start + n) % (255 * 255);
        int i = 1 + idx / 255;
        int j = 1 + idx % 255;
        uint8_t candidate[4] = {192, 168, (uint8_t)i, (uint8_t)j};

        bool taken = false;
        for (int m = 0; m < ROOM_MAX_MEMBERS; m++) {
            if (s->members[m].info.in_use &&
                memcmp(s->members[m].info.fake_ip, candidate, 4) == 0) {
                taken = true;
                break;
            }
        }
        if (!taken) {
            memcpy(out, candidate, 4);
            s->next_fake_ip = (idx + 1) % (255 * 255);
            return;
        }
    }
    LOG_E("room: all 192.168.x.y addresses are taken");
    memcpy(out, (uint8_t[]){192, 168, 0, 0}, 4);
}

int room_server_find_by_fake_ip(const RoomServer *server, const uint8_t fake_ip[4])
{
    for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
        if (server->members[i].info.in_use &&
            memcmp(server->members[i].info.fake_ip, fake_ip, 4) == 0) {
            return server->members[i].info.id;
        }
    }
    return -1;
}

/*
 * Copy the joined members into the caller's buffer.
 *
 * Returns how many were written. The previous shape of this API returned a
 * pointer into the server while reporting count=ROOM_MAX_MEMBERS, which only
 * ever held one member - any caller that believed the count would walk straight
 * past the end of the data it was handed. A buffer the caller owns cannot lie
 * about its own size.
 */
size_t room_server_members(const RoomServer *server, RoomMemberInfo *out, size_t cap)
{
    size_t n = 0;
    if (!server || !out) {
        return 0;
    }
    for (int i = 0; i < ROOM_MAX_MEMBERS && n < cap; i++) {
        if (server->members[i].info.in_use) {
            out[n++] = server->members[i].info;
        }
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Outgoing                                                           */
/* ------------------------------------------------------------------ */

static void send_to(RoomServer *s, MemberSlot *m, const uint8_t *buf, size_t len)
{
    if (sendto(s->fd, buf, len, 0, (const struct sockaddr *)&m->addr, m->addr_len) < 0) {
        LOG_E("room: sendto member %d failed: %s", m->info.id, strerror(errno));
    }
}

void room_send_join_success(RoomServer *server, int member_id)
{
    MemberSlot *m = find_by_id(server, member_id);
    if (!m) {
        return;
    }
    Packet p;
    pk_begin(&p);
    pk_u8(&p, IdJoinSuccess);
    pk_raw(&p, m->info.fake_ip, 4); /* IPv4Address: 4 raw bytes */

    send_to(server, m, p.buf, p.len);
    LOG_I("room: member %d ('%s') joined as %u.%u.%u.%u", m->info.id, m->info.nickname,
          m->info.fake_ip[0], m->info.fake_ip[1], m->info.fake_ip[2], m->info.fake_ip[3]);
}

static uint8_t reject_message_type(RoomRejectReason reason)
{
    switch (reason) {
    case RoomRejectWrongPassword: return IdWrongPassword;
    case RoomRejectVersionMismatch: return IdVersionMismatch;
    case RoomRejectRoomIsFull: return IdRoomIsFull;
    case RoomRejectNameCollision: return IdNameCollision;
    case RoomRejectIpCollision: return IdIpCollision;
    case RoomRejectNone:
    case RoomRejectCloseRoom:
    default: return IdCloseRoom;
    }
}

/*
 * Override how long a silent member keeps its slot. 0 disables eviction
 * entirely, which is the safe default for callers that never want a member
 * dropped implicitly.
 */
void room_server_set_idle_timeout_ms(RoomServer *server, uint64_t ms)
{
    if (!server) {
        return;
    }
    server->member_idle_timeout_ms = ms;
}

void room_send_reject(RoomServer *server, int member_id, RoomRejectReason reason)
{
    MemberSlot *m = find_by_id_any(server, member_id);
    if (!m) {
        return;
    }

    Packet p;
    pk_begin(&p);
    pk_u8(&p, reject_message_type(reason));
    /* Only IdWrongPassword carries a payload ("this is the message"). */
    if (reason == RoomRejectWrongPassword) {
        pk_str(&p, "wrong password");
    }

    send_to(server, m, p.buf, p.len);
    LOG_W("room: rejected member %d ('%s') with message type %u", m->info.id,
          m->info.nickname, reject_message_type(reason));
}

void room_broadcast_information(RoomServer *server)
{
    Packet p;
    pk_begin(&p);
    pk_u8(&p, IdRoomInformation);
    pk_str(&p, server->information.name);
    pk_str(&p, server->information.description);
    pk_u32(&p, server->information.member_slots);
    pk_u16(&p, server->information.port);
    pk_str(&p, server->information.preferred_game.name);
    pk_str(&p, server->information.host_username);
    pk_u32(&p, (uint32_t)server->member_count);

    for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
        const RoomMemberInfo *m = &server->members[i].info;
        if (!m->in_use) {
            continue;
        }
        pk_str(&p, m->nickname);
        pk_raw(&p, m->fake_ip, 4);
        pk_str(&p, m->game.name);
        pk_u64(&p, m->game.id);
        pk_str(&p, m->game.version);
        pk_str(&p, m->username);
        pk_str(&p, m->display_name);
        pk_str(&p, m->avatar_url);
    }

    /*
     * The pk_* helpers stop growing the buffer and set ok=false once a field
     * would not fit. Without this check the datagram would go out truncated
     * and the emulator would decode a partial member list - exactly the kind
     * of silent failure this file is supposed to avoid.
     */
    if (!p.ok) {
        LOG_E("room: RoomInformation does not fit in %zu bytes (%u members); "
              "not sending a truncated room list",
              PACKET_BUFSIZE, server->member_count);
        return;
    }

    for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
        if (server->members[i].info.in_use) {
            send_to(server, &server->members[i], p.buf, p.len);
        }
    }
}

void room_send_ldn_packet(RoomServer *server, int member_id, LDNPacketType type,
                          const uint8_t local_ip[4], const uint8_t remote_ip[4],
                          bool broadcast, const void *data, uint32_t data_len)
{
    MemberSlot *m = find_by_id(server, member_id);
    if (!m) {
        return;
    }
    Packet p;
    pk_begin(&p);
    pk_u8(&p, IdLdnPacket);
    pk_u8(&p, (uint8_t)type);
    pk_raw(&p, local_ip, 4);
    pk_raw(&p, remote_ip, 4);
    pk_u8(&p, broadcast ? 1 : 0);
    pk_u32(&p, data_len);
    pk_raw(&p, data, data_len);

    /*
     * Same guard as room_broadcast_information: pk_* stops growing the buffer
     * and sets ok=false, and sending anyway would put a datagram on the wire
     * whose length prefix no longer matches its body.
     */
    if (!p.ok) {
        LOG_E("room: IdLdnPacket of %u bytes does not fit in %zu bytes", data_len,
              PACKET_BUFSIZE);
        return;
    }

    send_to(server, m, p.buf, p.len);
}

/* ------------------------------------------------------------------ */
/* Proxy relay (game traffic into the room)                           */
/* ------------------------------------------------------------------ */

int room_proxy_decompress(const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t out_cap)
{
    if (!in || !out || !in_len) {
        return -1;
    }
    unsigned long long want = ZSTD_getFrameContentSize(in, in_len);
    if (want == ZSTD_CONTENTSIZE_ERROR || want == ZSTD_CONTENTSIZE_UNKNOWN ||
        want > out_cap) {
        return -1;
    }
    size_t got = ZSTD_decompress(out, out_cap, in, in_len);
    if (ZSTD_isError(got) || got != want) {
        return -1;
    }
    return (int)got;
}

int room_send_proxy_packet(RoomServer *server, int member_id,
                          const uint8_t local_ip[4], uint16_t local_port,
                          const uint8_t remote_ip[4], uint16_t remote_port,
                          bool broadcast, const void *data, uint32_t data_len)
{
    MemberSlot *m = find_by_id(server, member_id);
    if (!m || !data || !data_len) {
        return -1;
    }

    /*
     * Compress first: the room member decompresses unconditionally, so a
     * plaintext payload would be rejected as a malformed frame.
     */
    uint8_t compressed[PACKET_BUFSIZE];
    size_t clen = ZSTD_compress(compressed, sizeof(compressed), data, data_len,
                                ZSTD_CLEVEL_DEFAULT);
    if (ZSTD_isError(clen)) {
        LOG_E("room: zstd compress failed: %s", ZSTD_getErrorName(clen));
        return -1;
    }

    Packet p;
    pk_begin(&p);
    pk_u8(&p, IdProxyPacket);
    pk_u8(&p, ROOM_DOMAIN_INET);
    pk_raw(&p, local_ip, 4);
    pk_u16(&p, local_port);
    pk_u8(&p, ROOM_DOMAIN_INET);
    pk_raw(&p, remote_ip, 4);
    pk_u16(&p, remote_port);
    pk_u8(&p, ROOM_PROTOCOL_UDP);
    pk_u8(&p, broadcast ? 1 : 0);
    /* std::vector<u8> on the wire is a u32 length prefix followed by the bytes. */
    pk_u32(&p, (uint32_t)clen);
    pk_raw(&p, compressed, clen);

    if (!p.ok) {
        LOG_E("room: IdProxyPacket does not fit in %zu bytes", PACKET_BUFSIZE);
        return -1;
    }

    send_to(server, m, p.buf, p.len);
    LOG_T("room: IdProxyPacket %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%zu bytes on the "
          "wire, %u of payload)",
          local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
          remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], remote_port,
          p.len, data_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Incoming                                                           */
/* ------------------------------------------------------------------ */

static void handle_join_request(RoomServer *server, MemberSlot *m, Packet *p)
{
    char nickname[128] = {0};
    uint8_t preferred[4] = {0};
    uint32_t version = 0;
    char password[64] = {0};
    char token[128] = {0};

    rd_str(p, nickname, sizeof(nickname));
    rd_raw(p, preferred, 4);
    version = rd_u32(p);
    rd_str(p, password, sizeof(password));
    rd_str(p, token, sizeof(token));
    if (!p->ok) {
        LOG_W("room: malformed IdJoinRequest from %s", "peer");
        return;
    }

    if (version != ROOM_NETWORK_VERSION) {
        room_send_reject(server, m->info.id, RoomRejectVersionMismatch);
        return;
    }
    if (nickname[0] == '\0') {
        room_send_reject(server, m->info.id, RoomRejectNameCollision);
        return;
    }

    /*
     * A member that sends IdJoinRequest twice is just re-syncing (ENet gives
     * each connection a distinct peer, but a plain-UDP member is identified by
     * its address). Re-sending the existing identity is the safe answer; we
     * must not reallocate the fake IP, or the member silently loses its
     * address and every other member keeps forwarding to a dead one.
     */
    if (m->info.in_use) {
        LOG_D("room: member %d re-joined, keeping %u.%u.%u.%u", m->info.id,
              m->info.fake_ip[0], m->info.fake_ip[1], m->info.fake_ip[2],
              m->info.fake_ip[3]);
        room_send_join_success(server, m->info.id);
        return;
    }

    /*
     * Eden's HandleJoinRequest rejects a join the moment
     * members.size() >= room_information.member_slots, so the room never runs
     * past the number of members the game opened it for. Without this the
     * bridge only stops at its own table size (ROOM_MAX_MEMBERS), so a ninth
     * member is accepted into a room declared for eight people.
     *
     * Deliberately placed *after* the re-sync branch above: an existing member
     * re-sending its identity must keep its place even in a full room, or it
     * would read the IdRoomIsFull as having been dropped and lose its fake IP.
     */
    if ((uint32_t)server->member_count >= server->information.member_slots) {
        /*
         * The room is full. Before refusing, reclaim slots held by members
         * that stopped talking: this is what stops the room from filling up
         * for good once an emulator closes its socket.
         */
        reclaim_idle_members(server, now_ms());
    }

    if ((uint32_t)server->member_count >= server->information.member_slots) {
        LOG_W("room: member %d ('%s') rejected, room is full (%u/%u members)",
              m->info.id, nickname, (unsigned)server->member_count,
              server->information.member_slots);
        room_send_reject(server, m->info.id, RoomRejectRoomIsFull);
        return;
    }

    /* Assign (or honour) the fake IP. */
    if (preferred[0] != 0xFF || preferred[1] != 0xFF || preferred[2] != 0xFF ||
        preferred[3] != 0xFF) {
        bool taken = room_server_find_by_fake_ip(server, preferred) >= 0;
        if (taken && memcmp(m->info.fake_ip, preferred, 4) != 0) {
            LOG_W("room: fake IP %u.%u.%u.%u already taken; reassigning",
                  preferred[0], preferred[1], preferred[2], preferred[3]);
            generate_fake_ip(server, m->info.fake_ip);
        } else {
            memcpy(m->info.fake_ip, preferred, 4);
        }
    } else {
        generate_fake_ip(server, m->info.fake_ip);
    }

    snprintf(m->info.nickname, sizeof(m->info.nickname), "%s", nickname);
    snprintf(m->info.username, sizeof(m->info.username), "%s", nickname);
    snprintf(m->info.display_name, sizeof(m->info.display_name), "%s", nickname);
    snprintf(m->info.avatar_url, sizeof(m->info.avatar_url), "%s", "");
    m->info.in_use = true;

    room_send_join_success(server, m->info.id);
    server->member_count++;

    /* Eden also expects the room list right after joining. */
    room_broadcast_information(server);

    if (server->handlers.on_join) {
        server->handlers.on_join(server, &m->info, server->user);
    }
}

static void handle_set_game_info(RoomServer *server, MemberSlot *m, Packet *p,
                                 RoomPacketIn *out)
{
    char name[200] = {0};
    uint64_t id = 0;
    char version[16] = {0};

    rd_str(p, name, sizeof(name));
    id = rd_u64(p);
    rd_str(p, version, sizeof(version));
    if (!p->ok) {
        return;
    }

    memset(out, 0, sizeof(*out));
    out->type = IdSetGameInfo;
    snprintf(out->game_name, sizeof(out->game_name), "%s", name);
    out->game_id = id;
    snprintf(out->game_version, sizeof(out->game_version), "%s", version);

    snprintf(m->info.game.name, sizeof(m->info.game.name), "%s", name);
    m->info.game.id = id;
    snprintf(m->info.game.version, sizeof(m->info.game.version), "%s", version);

    if (id) {
        snprintf(server->information.preferred_game.name,
                 sizeof(server->information.preferred_game.name), "%s", name);
        server->information.preferred_game.id = id;
        snprintf(server->information.preferred_game.version,
                 sizeof(server->information.preferred_game.version), "%s", version);
        room_broadcast_information(server);
    }

    LOG_D("room: IdSetGameInfo from member %d: name='%s' id=%016llx version='%s' ok=%d",
           m->info.id, name, (unsigned long long)id, version, (int)p->ok);
    if (server->handlers.on_packet) {
        server->handlers.on_packet(server, m->info.id, out, server->user);
    }
}

static void handle_proxy_packet(RoomServer *server, MemberSlot *m, Packet *p,
                                RoomPacketIn *out)
{
    memset(out, 0, sizeof(*out));
    out->type = IdProxyPacket;

    out->local_family = rd_u8(p);
    rd_raw(p, out->local_ip, 4);
    out->local_port = rd_u16(p);

    out->remote_family = rd_u8(p);
    rd_raw(p, out->remote_ip, 4);
    out->remote_port = rd_u16(p);

    out->protocol = rd_u8(p);
    /* The broadcast byte must still be consumed to keep the layout aligned;
     * it is deliberately not stored - see the note in room.h. */
    (void)rd_u8(p);

    uint32_t n = rd_u32(p);
    if (!p->ok || n > p->len - p->pos) {
        return;
    }
    out->data = p->buf + p->pos;
    out->data_len = n;
    p->pos += n;

    if (server->handlers.on_packet) {
        server->handlers.on_packet(server, m->info.id, out, server->user);
    }
}

static void handle_ldn_packet(RoomServer *server, MemberSlot *m, Packet *p,
                              RoomPacketIn *out)
{
    memset(out, 0, sizeof(*out));
    out->type = IdLdnPacket;

    out->ldn_packet_type = rd_u8(p);
    rd_raw(p, out->ldn_local_ip, 4);
    rd_raw(p, out->ldn_remote_ip, 4);
    /* broadcast byte: consumed, not stored - see the note in room.h. */
    (void)rd_u8(p);

    uint32_t n = rd_u32(p);
    if (!p->ok || n > p->len - p->pos) {
        LOG_W("room: truncated IdLdnPacket");
        return;
    }
    out->data = p->buf + p->pos;
    out->data_len = n;
    p->pos += n;

    /*
     * Optional trailing passphrase (patched Eden). Only present when extra
     * bytes follow the data vector, so a stock Eden decodes exactly as before.
     */
    if (p->pos < p->len && p->len - p->pos >= 4) {
        uint32_t plen = rd_u32(p);
        if (p->ok && plen <= sizeof(out->passphrase) && p->pos + plen <= p->len) {
            memcpy(out->passphrase, p->buf + p->pos, plen);
            out->passphrase_len = plen;
            p->pos += plen;
        } else {
            LOG_W("room: malformed trailing passphrase blob (len=%u)", plen);
        }
    }

    if (server->handlers.on_packet) {
        server->handlers.on_packet(server, m->info.id, out, server->user);
    }
}

/* ------------------------------------------------------------------ */
/* Server                                                             */
/* ------------------------------------------------------------------ */

RoomServer *room_server_create(const char *bind_addr, uint16_t port,
                               const RoomHandlers *handlers, void *user,
                               const char *room_name, const char *room_description,
                               const char *host_username, uint32_t member_slots)
{
    RoomServer *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    memset(&s->handlers, 0, sizeof(s->handlers));

    s->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s->fd < 0) {
        LOG_E("room: socket: %s", strerror(errno));
        free(s);
        return NULL;
    }

    int one = 1;
    setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (!bind_addr || inet_pton(AF_INET, bind_addr ? bind_addr : "0.0.0.0",
                                &addr.sin_addr) != 1) {
        LOG_E("room: invalid bind address '%s'", bind_addr ? bind_addr : "0.0.0.0");
        close(s->fd);
        free(s);
        return NULL;
    }
    if (bind(s->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_E("room: bind(%s:%u): %s", bind_addr, port, strerror(errno));
        close(s->fd);
        free(s);
        return NULL;
    }

    s->port = port;
    if (handlers) {
        s->handlers = *handlers;
    }
    s->user = user;
    s->next_fake_ip = 0;
    s->member_count = 0;
    s->next_id = 0;
    s->member_idle_timeout_ms = ROOM_MEMBER_IDLE_TIMEOUT_MS;

    snprintf(s->information.name, sizeof(s->information.name), "%s",
             room_name && *room_name ? room_name : "switch_ldn");
    snprintf(s->information.description, sizeof(s->information.description), "%s",
             room_description ? room_description : "");
    snprintf(s->information.host_username, sizeof(s->information.host_username), "%s",
             host_username ? host_username : "");
    s->information.member_slots = member_slots ? member_slots : LDN_NODE_MAX;
    s->information.port = port;

    LOG_I("room: server listening on %s:%u (Room protocol, %u members max, network v%u)",
          bind_addr ? bind_addr : "0.0.0.0", port, s->information.member_slots,
          ROOM_NETWORK_VERSION);
    return s;
}

void room_server_destroy(RoomServer *server)
{
    if (!server) {
        return;
    }
    for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
        if (server->members[i].info.in_use && server->handlers.on_leave) {
            server->handlers.on_leave(server, server->members[i].info.id, server->user);
        }
    }
    close(server->fd);
    free(server);
}

void room_server_poll(RoomServer *server, int timeout_ms)
{
    struct pollfd fd;
    fd.fd = server->fd;
    fd.events = POLLIN;

    if (poll(&fd, 1, timeout_ms) <= 0) {
        return;
    }

    for (;;) {
        room_service_one(server);
        if (!room_more_pending(server)) {
            break;
        }
    }
}

/* True while the socket still has unread data. */
static int room_more_pending(RoomServer *server)
{
    struct pollfd fd;
    fd.fd = server->fd;
    fd.events = POLLIN;
    return poll(&fd, 1, 0) > 0;
}

static void room_service_one(RoomServer *server)
{
    uint8_t buf[2048];
    struct sockaddr_in peer;
    socklen_t peerlen = sizeof(peer);
    ssize_t n = recvfrom(server->fd, buf, sizeof(buf), MSG_DONTWAIT,
                         (struct sockaddr *)&peer, &peerlen);
    if (n <= 0) {
        return;
    }

    MemberSlot *m = find_by_addr(server, &peer);
    bool is_new = false;
    if (!m) {
        /* A new peer. Reserve a slot and wait for its JoinRequest. */
        if (buf[0] != IdJoinRequest) {
            LOG_W("room: peer sent message type %u before joining", buf[0]);
            return;
        }
        for (int i = 0; i < ROOM_MAX_MEMBERS; i++) {
            if (!server->members[i].info.in_use) {
                m = &server->members[i];
                break;
            }
        }
        if (!m) {
            LOG_E("room: no free member slot");
            return;
        }
        memset(m, 0, sizeof(*m));
        m->addr = peer;
        m->addr_len = peerlen;
        m->info.id = ++server->next_id;
        m->info.in_use = false; /* set only once the join succeeds */
        is_new = true;
    }

    /* Anything at all counts as proof of life, including re-joins. */
    m->last_seen_ms = now_ms();
    Packet p;
    pk_begin(&p);
    memcpy(p.buf, buf, (size_t)n);
    p.len = (size_t)n;

    uint8_t type = rd_u8(&p);

    /* A peer that has completed the join may send anything. */
    if (!m->info.in_use && type != IdJoinRequest) {
        LOG_W("room: peer %d is not joined yet, ignoring message type %u", m->info.id,
              type);
        return;
    }

    RoomPacketIn decoded;
    bool free_slot = !m->info.in_use && type != IdJoinRequest;

    switch (type) {
    case IdJoinRequest:
        handle_join_request(server, m, &p);
        if (is_new && !m->info.in_use) {
            /* the join was rejected; release the reserved slot without
             * touching member_count, which only counts successful joins */
            memset(m, 0, sizeof(*m));
        }
        break;

    case IdSetGameInfo:
        handle_set_game_info(server, m, &p, &decoded);
        break;

    case IdProxyPacket:
        handle_proxy_packet(server, m, &p, &decoded);
        break;

    case IdLdnPacket:
        handle_ldn_packet(server, m, &p, &decoded);
        break;

    default:
        LOG_W("room: unsupported message type %u from member %d", type, m->info.id);
        break;
    }

    (void)free_slot;
}
