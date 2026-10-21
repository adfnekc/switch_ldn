/*
 * switch_ldn - bridge real Nintendo Switch consoles to the Ryujinx and yuzu
 * emulator families over the Switch's own local wireless (LDN) protocol.
 *
 * Architecture:
 *
 *      ┌────────────────────┐  802.11 LDN   ┌──────────────────────────┐
 *      │  real Switch (D3)  │ ◄──────────►  │  RTL8812AU  +  ldn_bridge│
 *      └────────────────────┘  (host role)  │  radio.c / host.c        │
 *                                          └──────────────────────────┘
 *                                              │ RyuLdn protocol
 *                                              ▼
 *                                          ┌──────────────────────────┐
 *                                          │  Ryubing/Eden guest      │
 *                                          │  (thinks it joined a LAN)│
 *                                          └──────────────────────────┘
 *
 * The bridge plays the LDN *host* (it is the AP). That role is chosen
 * deliberately: as host it issues the LDN v3+ authentication challenge and is
 * therefore free to answer "success" without owning the game, whereas a
 * station would have to prove independent ownership.
 *
 * See DESIGN.md for the full reasoning, the protocol layout and the numbered
 * open questions.
 */

#include <arpa/inet.h>
#include <getopt.h>
#include <limits.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "host.h"
#include "ldn.h"
#include "radio.h"
#include "room.h"
#include "ryuldn.h"


typedef struct {
    Radio *radio;
    Host *host;
    RyuLdnServer *server;
    const ProdKeys *prodkeys;

    RoomServer *room_server; /* Eden / yuzu lineage */
        int room_member;          /* the emulator member id */

    RyuLdnSession *guest; /* the emulator instance (RyuLdn) */
    uint64_t title_id;
    uint8_t channel;
    uint8_t band;
    uint32_t guest_proxy_ip; /* Ryujinx-format, e.g. 10.114.0.1 */
    uint8_t guest_mac[6];    /* MAC we assigned the guest at Initialize */
    /* The LDN crypto passphrase as told to us by the emulator's own
     * CreateNetwork call. There is no CLI or table fallback by design: both
     * transports now have a source. */
    uint8_t learned_passphrase[64];
    size_t learned_passphrase_len;
} Bridge;

/* ------------------------------------------------------------------ */
/* Radio -> RyuLdn (game traffic)                                      */
/* ------------------------------------------------------------------ */

/*
 * Both paths that push something to the emulator historically dropped the
 * packet silently when b->guest was NULL, which made "the emulator died"
 * indistinguishable from "the network is quiet". Say so, but not more than
 * once every few seconds: a guest that stays away for minutes must not turn
 * into a log flood.
 */
static uint64_t g_guest_gone_warned_at;

static void warn_guest_gone(const char *what)
{
    uint64_t now = now_ms();
    if (g_guest_gone_warned_at && now - g_guest_gone_warned_at < 5000) {
        return;
    }
    g_guest_gone_warned_at = now;
    LOG_W("%s: no emulator guest is connected, dropping", what);
}

static bool parse_udp(const uint8_t *eth, size_t len, const uint8_t **udp,
                      size_t *udp_len, uint16_t *sport, uint16_t *dport,
                      uint32_t *src_ip, uint32_t *dst_ip){
    if (rd_be16(eth + 12) != 0x0800) {
        return false;
    }
    const uint8_t *ip = eth + 14;
    if ((ip[0] >> 4) != 4) {
        return false;
    }
    size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
    if (len < 14 + ihl + 8) {
        return false;
    }
    if (ip[9] != 17) {
        return false;
    }
    const uint8_t *u = ip + ihl;
    *src_ip = rd_be32(ip + 12);
    *dst_ip = rd_be32(ip + 16);
    *sport = rd_be16(u);
    *dport = rd_be16(u + 2);
    *udp_len = rd_be16(u + 4);
    *udp = u + 8;
    if (len < 14 + ihl + 8 + *udp_len) {
        *udp_len = len - 14 - ihl - 8;
    }
    return true;
}

/*
 * Real-console game traffic has to reach the emulator, whichever transport it
 * is using. RyuLdn takes it as ProxyData, the Room transport as an IdProxyPacket
 * - two encodings of the same thing, which is why they share the parse above.
 */
/*
 * A frame from a console that we could not turn into UDP is worth saying out
 * loud, once every few seconds rather than per frame: if a real console ever
 * wraps its Pia traffic in something we do not expect (an LDN-layer encryption,
 * say), every single frame would otherwise be discarded without a trace and the
 * symptom would be "the emulator sees nothing" with a completely clean log.
 */
static uint64_t g_unparsed_warned_at;

static void warn_unparsed_console_frame(const uint8_t *eth, size_t len)
{
    uint64_t now = now_ms();
    if (g_unparsed_warned_at && now - g_unparsed_warned_at < 5000) {
        return;
    }
    g_unparsed_warned_at = now;
    uint16_t etype = len >= 14 ? rd_be16(eth + 12) : 0;
    unsigned proto = len >= 14 + 10 ? eth[14 + 9] : 0;
    LdnFrameDiag why = ldn_diagnose_ethernet(eth, len);
    LOG_W("radio->guest: %zu-byte frame dropped (ethertype %#06x, ip proto %u): %s",
          len, etype, proto, ldn_frame_diag_text(why));
}

static void deliver_to_guest(Bridge *b, const uint8_t *eth, size_t len)
{
    const uint8_t *udp;
    size_t udp_len;
    uint16_t sport, dport;
    uint32_t src_ip, dst_ip;

    if (!parse_udp(eth, len, &udp, &udp_len, &sport, &dport, &src_ip, &dst_ip)) {
        warn_unparsed_console_frame(eth, len);
        return;
    }

    if (b->guest) {
        /* Broadcast on the LDN mesh has to fan out to every guest. */
        bool broadcast = (dst_ip & 0xFF) == 0xFF;

        RyuLdnProxyInfo info;
        memset(&info, 0, sizeof(info));
        info.source_ipv4 = src_ip;

        /*
         * Broadcast must sit in the guest's own subnet. The RyuLdn default
         * (10.114.0.0/16) makes 0x0A72FFFF look right, but the Room transport's
         * fake IPs are 192.168.x.y, so a hard-coded value sends the packet to a
         * subnet nobody is listening on. Derive it from what we handed out.
         */
        uint32_t subnet = b->guest_proxy_ip & 0xFFFF0000u;
        info.dest_ipv4 = broadcast ? (subnet | 0x0000FFFFu) : b->guest_proxy_ip;
        info.source_port = sport;
        info.dest_port = dport;
        info.protocol = 17;

        ryuldn_send_proxy_data(b->guest, info, udp, udp_len);
        LOG_T("radio->guest %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%zu bytes)",
              (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
              (src_ip >> 8) & 0xFF, src_ip & 0xFF, sport,
              (info.dest_ipv4 >> 24) & 0xFF, (info.dest_ipv4 >> 16) & 0xFF,
              (info.dest_ipv4 >> 8) & 0xFF, info.dest_ipv4 & 0xFF, dport, udp_len);
        return;
    }

    if (b->room_member) {
        /*
         * The emulator's game socket is addressed by the LDN IP we published for
         * it, and the console is identified by its own LDN IP. From Eden's point
         * of view local_* is the sender and remote_* the recipient, which is
         * what ProxySocket::HandleProxyPacket matches its own local port
         * against.
         */
        uint32_t src_host = src_ip;
        uint8_t local_ip[4] = {(uint8_t)(src_host >> 24), (uint8_t)(src_host >> 16),
                               (uint8_t)(src_host >> 8), (uint8_t)src_host};
        uint32_t guest_host = b->guest_proxy_ip;
        uint8_t remote_ip[4] = {(uint8_t)(guest_host >> 24), (uint8_t)(guest_host >> 16),
                                (uint8_t)(guest_host >> 8), (uint8_t)guest_host};
        bool rbroadcast = (dst_ip & 0xFF) == 0xFF;
        if (room_send_proxy_packet(b->room_server, b->room_member, local_ip, sport,
                                   remote_ip, dport, rbroadcast, udp,
                                   (uint32_t)udp_len) != 0) {
            LOG_W("radio->room: console frame to %u.%u.%u.%u:%u was not relayed",
                  remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], dport);
            return;
        }
        LOG_T("radio->room %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%zu bytes)",
              (src_host >> 24) & 0xFF, (src_host >> 16) & 0xFF, (src_host >> 8) & 0xFF,
              src_host & 0xFF, sport, remote_ip[0], remote_ip[1], remote_ip[2],
              remote_ip[3], dport, udp_len);
        return;
    }

    warn_guest_gone("radio->guest");
}

/* ------------------------------------------------------------------ */
/* RyuLdn -> radio (game traffic)                                      */
/* ------------------------------------------------------------------ */

static size_t build_udp_frame(uint8_t *out, size_t out_len, const uint8_t src_mac[6],
                              const uint8_t dst_mac[6], uint32_t src_ip,
                              uint32_t dst_ip, uint16_t sport, uint16_t dport,
                              const uint8_t *payload, size_t payload_len)
{
    size_t total = 14 + 20 + 8 + payload_len;
    if (out_len < total) {
        return 0;
    }
    memset(out, 0, total);
    memcpy(out, dst_mac, 6);
    memcpy(out + 6, src_mac, 6);
    wr_be16(out + 12, 0x0800);

    uint8_t *ip = out + 14;
    ip[0] = 0x45;
    wr_be16(ip + 2, (uint16_t)(20 + 8 + payload_len));
    ip[4] = 0;
    ip[5] = 0;
    ip[6] = 0x40;
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = 17;
    wr_be32(ip + 12, src_ip);
    wr_be32(ip + 16, dst_ip);

    uint8_t *u = ip + 20;
    wr_be16(u, sport);
    wr_be16(u + 2, dport);
    wr_be16(u + 4, (uint16_t)(8 + payload_len));
    wr_be16(u + 6, 0); /* checksum: optional in practice */

    memcpy(u + 8, payload, payload_len);
    return total;
}

static void deliver_from_guest(Bridge *b, RyuLdnProxyInfo info, const uint8_t *data,
                               size_t len)
{
    if (!b->host) {
        return;
    }

    uint32_t dest_host = info.dest_ipv4;
    uint8_t dst_mac[6];
    bool to_broadcast = (dest_host & 0xFF) == 0xFF;

    if (to_broadcast) {
        memset(dst_mac, 0xFF, 6);
    } else {
        /* find the station that owns this LDN IP */
        bool found = false;
        for (int i = 0; i < HOST_MAX_STATIONS; i++) {
            const HostStation *st = host_station(b->host, i);
            if (st && st->in_use && st->ipv4 == info.dest_ipv4) {
                memcpy(dst_mac, st->mac, 6);
                found = true;
                break;
            }
        }
        if (!found) {
            /*
             * Not TRACE: a guest that keeps sending to an address we no longer
             * know (a console that left, or a network we just rebuilt) must be
             * visible at the default log level, or it looks like the console
             * is dropping traffic while the emulator retries forever.
             */
            LOG_W("guest sent to unknown LDN IP %u.%u.%u.%u (no such station)",
                  (dest_host >> 24) & 0xFF, (dest_host >> 16) & 0xFF,
                  (dest_host >> 8) & 0xFF, dest_host & 0xFF);
            return;
        }
    }

    uint8_t frame[2304];
    size_t n = build_udp_frame(
        frame, sizeof(frame), radio_config(b->radio)->mac, dst_mac,
        b->guest_proxy_ip, info.dest_ipv4, info.source_port, info.dest_port, data, len);
    if (!n) {
        LOG_E("guest->radio: %zu-byte payload does not fit in a 802.11 frame, "
              "dropping it",
              len);
        return;
    }
    if (radio_send(b->radio, frame, n) != 0) {
        LOG_E("guest->radio: could not transmit to %02x:%02x:%02x:%02x:%02x:%02x",
              dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
        return;
    }
    LOG_T("guest->radio %zu bytes to %02x:%02x:%02x:%02x:%02x:%02x", len, dst_mac[0],
          dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
}

/* ------------------------------------------------------------------ */
/* RyuLdn handlers                                                    */
/* ------------------------------------------------------------------ */

static void build_network_info(Bridge *b, RyuLdnNetworkInfo *info)
{
    /* The radio is optional (the interop harness runs without one), so fall
     * back to an all-zero MAC instead of dereferencing a null Radio. */
    static const uint8_t zero_mac[6] = {0};
    const RadioConfig *rcfg = radio_config(b->radio);
    const uint8_t *own_mac = rcfg ? rcfg->mac : zero_mac;

    ryuldn_network_info_init(info);

    /* network_id = intent id (title id in the first 8 bytes) */
    wr_le64(info->network_id, b->title_id);

    /* CommonNetworkInfo: mac, ssid, channel, link level, network type */
    memcpy(info->common, own_mac, 6);
    memset(info->common + 6, 0, 34);
    wr_le16(info->common + 40, b->channel);
    wr_le16(info->common + 42, 3); /* link level: "good" */
    info->common[44] = 2;          /* NetworkType.Ldn */

    /* LdnNetworkInfo */
    if (b->host) {
        memcpy(info->security_parameter, host_advertise(b->host)->server_random, 16);
    }

    HostStation *self = (HostStation *)host_station(b->host, 0);
    int count = 0;

    /*
     * Node layout. The guest identifies its own node by matching its
     * assigned IP, so we place the guest's station at index 0 and each real
     * console after it.
     */
    for (int i = 0; i < HOST_MAX_STATIONS; i++) {
        const HostStation *st = i == 0 ? self : host_station(b->host, i);
        if (!st || !st->in_use) {
            continue;
        }

        RyuLdnNodeInfo *node = &info->nodes[count];
        node->ipv4_address = (i == 0) ? b->guest_proxy_ip : st->ipv4;
        memcpy(node->mac, i == 0 ? own_mac : st->mac, 6);
        node->node_id = (uint8_t)count;
        node->is_connected = 1;
        strncpy(node->user_name, st->username, sizeof(node->user_name) - 1);
        node->local_communication_version = st->app_communication_version;
        count++;
    }

    info->node_count = (uint8_t)count;
    info->node_count_max = HOST_MAX_STATIONS;
    info->advertise_data_size = host_advertise(b->host)->app_data_size;
    memcpy(info->advertise_data, host_advertise(b->host)->app_data,
           info->advertise_data_size);
}

/*
 * Step 3 of the handshake. There is no network yet - ProxyConfig and Connected
 * are sent later, when the guest's game creates its LDN network (see
 * on_access_point). Sending them here would reference a null host.
 */
static void on_initialized(RyuLdnSession *session, const uint8_t session_id[16],
                           const uint8_t mac[6], void *user)
{
    Bridge *b = user;
    (void)session_id;

    /*
     * The guest's MAC is assigned by us, and the emulator will present it on
     * the mesh. Keep it in sync with what the real consoles will see so the
     * advertisement and the RyuLdn view agree.
     */
    if (radio_config(b->radio)) {
        /* RadioConfig.mac is ours, not the guest's; nothing to copy. */
    }
    memcpy(b->guest_mac, mac, 6);
    LOG_D("guest initialized with MAC %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
          mac[2], mac[3], mac[4], mac[5]);
}

static void on_access_point(RyuLdnSession *session, const uint8_t *payload, size_t len,
                            bool is_private, void *user)
{
    Bridge *b = user;
    (void)payload;
    (void)len;
    b->guest = session;

    /*
     * The emulator's game has just created its LDN network. Its
     * nn::ldn::CreateNetwork call carried the crypto passphrase, the title id,
     * the channel, the player limit and the local communication version, and
     * RyuLdn forwarded all of it to us. So this is where the real 802.11
     * network is configured - and why no per-game lookup table is needed.
     */
    const RyuLdnGuestGameSettings *guest = ryuldn_session_guest_settings(session);
    if (!guest) {
        LOG_E("guest created a network but sent no settings");
        ryuldn_send_network_error(session, 0);
        return;
    }

    uint8_t passphrase[64];
    size_t passphrase_len = 0;
    if (guest->security.passphrase_size &&
        guest->security.passphrase_size <= sizeof(passphrase)) {
        memcpy(passphrase, guest->security.passphrase, guest->security.passphrase_size);
        passphrase_len = guest->security.passphrase_size;
    }

    uint64_t title_id = guest->network.intent_id.local_communication_id;
    uint16_t requested_channel = guest->network.channel ? guest->network.channel : b->channel;

    /*
     * The advertisement goes out on whatever channel the radio is tuned to, so
     * the channel written into it has to be that one. Advertising the channel
     * the *game* asked for while transmitting on another one is the worst of
     * both: the console tunes to the advertised channel and hears nothing.
     *
     * A radio only exists in live mode; with --radio-socket the harness decides,
     * so the guest's request is all we have.
     */
    uint16_t channel = requested_channel;
    {
        const RadioConfig *rc = radio_config(b->radio);
        if (rc && rc->channel && rc->channel != requested_channel) {
            LOG_W("the guest asked for channel %u but the radio is on %u; "
                  "advertising %u - pass --channel %u and set CHANNEL=%u for "
                  "hostapd, or the network will be invisible to a console "
                  "scanning %u",
                  requested_channel, rc->channel, rc->channel, rc->channel,
                  rc->channel, requested_channel);
            channel = rc->channel;
        }
    }
    const char *username =
        guest->user.user_name[0] ? guest->user.user_name : "Player";
    uint16_t comm_version = guest->network.local_communication_version;

    if (b->guest_proxy_ip == 0) {
        b->guest_proxy_ip = 0x0A720001;
    }

    if (!b->host) {
        b->host = host_create(b->prodkeys, title_id, channel, b->band,
                              guest->network.node_count_max, passphrase,
                              passphrase_len, username, comm_version);
    } else {
        if (host_adopt_guest_settings(b->host, title_id, channel,
                                     guest->network.node_count_max, passphrase,
                                     passphrase_len, username,
                                     comm_version) != 0) {
            /*
             * Deliberately a timeout, not a NetworkError: only None(0) and
             * ConnectionRejected(202) are confirmed codes, and guessing a third
             * makes the emulator misreport instead of waiting (DESIGN.md Q9).
             * Say so, so the silence is explainable at 3 a.m.
             */
            LOG_E("could not configure the LDN network from the guest's settings "
                  "(see the error above); the previous network is untouched and "
                  "the guest's CreateNetwork will time out rather than get an "
                  "invented error code");
            return;
        }
    }
    if (!b->host) {
        LOG_E("could not start the LDN host (see the error above); the guest's "
              "CreateNetwork will time out - there is no confirmed NetworkError "
              "code for this, so a timeout is the honest answer (DESIGN.md Q9)");
        return;
    }

    b->title_id = title_id;
    b->channel = channel;

    /* Mirror the guest's advertise data so both sides of the mesh agree. */
    host_set_app_data(b->host, guest->advertise_data, guest->advertise_data_size);
    host_sync_station_list(b->host);

    /*
     * Step 5: the guest is now in a network. ProxyConfig tells it the LDN
     * subnet, then Connected hands over the NetworkInfo it must publish.
     */
    RyuLdnProxyConfig cfg;
    cfg.proxy_ip = b->guest_proxy_ip;
    cfg.proxy_subnet_mask = 0xFFFF0000;
    ryuldn_send_proxy_config(session, cfg);

    RyuLdnNetworkInfo info;
    build_network_info(b, &info);
    ryuldn_send_connected(session, &info);

    LOG_I("%s network live for real consoles: title=%016llx channel=%u "
          "(guest proxy IP %u.%u.%u.%u)",
          is_private ? "private" : "public", (unsigned long long)title_id, channel,
          (b->guest_proxy_ip >> 24) & 0xFF, (b->guest_proxy_ip >> 16) & 0xFF,
          (b->guest_proxy_ip >> 8) & 0xFF, b->guest_proxy_ip & 0xFF);
}

/*
 * Step 5: the guest's game created the network, so this guest is the LDN host.
 * ProxyConfig tells it which subnet the mesh uses, and Connected hands over the
 * NetworkInfo it has to publish to its own players.
 *
 * Called from on_access_point once b->host is configured.
 */
static void on_connected(RyuLdnSession *session, void *user)
{
    Bridge *b = user;

    RyuLdnProxyConfig cfg;
    cfg.proxy_ip = b->guest_proxy_ip;
    cfg.proxy_subnet_mask = 0xFFFF0000;
    ryuldn_send_proxy_config(session, cfg);

    RyuLdnNetworkInfo info;
    build_network_info(b, &info);
    ryuldn_send_connected(session, &info);

    LOG_I("guest connected as node 0 (proxy IP %u.%u.%u.%u)",
          (b->guest_proxy_ip >> 24) & 0xFF, (b->guest_proxy_ip >> 16) & 0xFF,
          (b->guest_proxy_ip >> 8) & 0xFF, b->guest_proxy_ip & 0xFF);
}

/*
 * Scanning is a *station* activity. In p0 the guest is the host and real
 * consoles join it, so there is never anything for the guest to discover.
 * Reply with an empty list so the game's UI does not hang.
 */
static void on_scan(RyuLdnSession *session, const uint8_t *payload, size_t len,
                    void *user)
{
    (void)payload;
    (void)len;
    (void)user;
    LOG_D("scan: p0 has no networks to report (the guest hosts)");
    ryuldn_send_scan_reply_end(session);
}

static void on_proxy_data(RyuLdnSession *session, RyuLdnProxyInfo info,
                         const uint8_t *data, size_t len, void *user)
{
    (void)session;
    deliver_from_guest(user, info, data, len);
}

static void on_proxy_connect(RyuLdnSession *session, RyuLdnProxyInfo info, void *user)
{
    Bridge *b = user;
    (void)b;
    ryuldn_send_proxy_connect_reply(session, info);
}

static void on_proxy_disconnect(RyuLdnSession *session, RyuLdnProxyInfo info, void *user)
{
    (void)session;
    (void)info;
    (void)user;
}

/*
 * The emulator's TCP connection dropped (or it sent Disconnect). RyuLdn only
 * tells us *which* session left; the session itself is owned by ryuldn.c's
 * session table and is about to be closed and freed by the reap path. All we
 * may do is drop our reference to it, otherwise the next SyncNetwork or
 * ProxyData would write into freed heap.
 *
 * This handler never frees anything and never dereferences the session beyond
 * the name lookup below, which ryuldn.c performs *before* reaping.
 */
static void on_guest_disconnected(RyuLdnSession *session, void *user)
{
    Bridge *b = user;
    if (!b) {
        return;
    }

    const RyuLdnGuestGameSettings *gs = ryuldn_session_guest_settings(session);
    const char *who = (gs && gs->user.user_name[0]) ? gs->user.user_name : "unnamed";

    if (b->guest == session) {
        b->guest = NULL;
        LOG_I("guest '%s' left: it is offline, nothing will be bridged until it "
              "comes back",
              who);
        return;
    }

    LOG_I("session for '%s' left (it was not the current guest)", who);
}

static const RyuLdnHandlers k_handlers = {
    .on_initialized = on_initialized,
    .on_connected = on_connected,
    .on_access_point = on_access_point,
    .on_scan = on_scan,
    .on_proxy_data = on_proxy_data,
    .on_proxy_connect = on_proxy_connect,
    .on_proxy_disconnect = on_proxy_disconnect,
    .on_disconnected = on_guest_disconnected,
};

/* ------------------------------------------------------------------ */
/* Notifying the emulator that a real console joined or left          */
/* ------------------------------------------------------------------ */

/*
 * A real console associating to our AP is invisible to the emulator until we
 * say so: RyuLdn guests expect a SyncNetwork, Room members expect an
 * IdLdnPacket{Connect}/IdLdnPacket{Disconnect} carrying a Ryujinx-format
 * NodeInfo. Both carry the very same struct, which is why the LDN core can be
 * shared.
 */
static void fill_node_info(RyuLdnNodeInfo *node, const HostStation *st,
                           const uint8_t mac[6], const char *username)
{
    memset(node, 0, sizeof(*node));
    node->ipv4_address = st->ipv4;
    memcpy(node->mac, mac, 6);
    node->node_id = 0; /* filled in by the peer from its own table */
    node->is_connected = 1;
    snprintf(node->user_name, sizeof(node->user_name), "%s",
             username && *username ? username : "Switch");
    node->local_communication_version = st->app_communication_version;
}

static void notify_station_changed(Bridge *b, const HostEvent *ev)
{
    if (!b->host) {
        return;
    }

    /*
     * Build the node from the event's snapshot, not from host_station(): the
     * host has already cleared the slot when it drained a leave, which is why
     * gating on st->in_use here used to swallow every departure.
     */
    HostStation st;
    memset(&st, 0, sizeof(st));
    st.in_use = true;
    memcpy(st.mac, ev->mac, sizeof(st.mac));
    st.ipv4 = ev->ipv4;
    st.app_communication_version = ev->app_communication_version;
    memcpy(st.username, ev->username, sizeof(st.username));

    RyuLdnNodeInfo node;
    fill_node_info(&node, &st, st.mac, st.username);

    bool joined = ev->kind == HOST_EVENT_STATION_JOINED;

    /* --- RyuLdn guest: push the whole NetworkInfo --- */
    if (b->guest) {
        RyuLdnNetworkInfo info;
        build_network_info(b, &info);
        ryuldn_send_sync_network(b->guest, &info);
        LOG_D("SyncNetwork -> RyuLdn guest (%d stations)", info.node_count);
    } else {
        warn_guest_gone("SyncNetwork");
    }

    /* --- Room member: Connect/Disconnect carrying a NodeInfo --- */
    if (b->room_member) {
        LDNPacketType type = joined ? LDNPacketTypeConnect : LDNPacketTypeDisconnect;

        /*
         * local_ip is the joining node's own address from the room member's
         * point of view; yuzu pushes it straight onto connected_clients.
         */
        uint32_t st_host = st.ipv4;
        uint8_t st_ip[4] = {(uint8_t)(st_host >> 24), (uint8_t)(st_host >> 16),
                            (uint8_t)(st_host >> 8), (uint8_t)st_host};
        room_send_ldn_packet(b->room_server, b->room_member, type, st_ip, st_ip, false,
                             &node, (uint32_t)sizeof(node));
        LOG_D("IdLdnPacket{%s} -> room member (slot %d)",
              joined ? "Connect" : "Disconnect", ev->index);
    }
}

/* ------------------------------------------------------------------ */
/* Room transport (Eden / yuzu lineage)                               */
/* ------------------------------------------------------------------ */

/*
 * yuzu's LANDiscovery maps its LDN state machine onto six LDNPacketType
 * values. The bridge is the LDN host, so:
 *
 *   Scan        -> answer with a ScanResp carrying our NetworkInfo
 *   ScanResp    -> nothing to do (we are the host, not a scanner)
 *   Connect     -> the emulator wants in; it is already the host, so ack
 *   SyncNetwork -> the emulator re-published its view; ignore (ours wins)
 *   Disconnect   -> the emulator left
 *   DestroyNetwork -> the emulator tore the room down
 */

static void room_on_join(RoomServer *server, const RoomMemberInfo *member, void *user)
{
    Bridge *b = user;
    b->room_member = member->id;

    LOG_I("room member #%d '%s' joined as %u.%u.%u.%u", member->id, member->nickname,
          member->fake_ip[0], member->fake_ip[1], member->fake_ip[2],
          member->fake_ip[3]);

    /*
     * The room's fake IP replaces RyuLdn's assigned IP as the guest's address
     * on the mesh. Both are "the emulator's own address".
     */
    uint32_t ip = ((uint32_t)member->fake_ip[0] << 24) |
                 ((uint32_t)member->fake_ip[1] << 16) |
                 ((uint32_t)member->fake_ip[2] << 8) | (uint32_t)member->fake_ip[3];
    b->guest_proxy_ip = ip;

    /* The room list is what the game's UI reads. */
    room_broadcast_information(server);
}

static void room_on_leave(RoomServer *server, int member_id, void *user)
{
    Bridge *b = user;
    if (b->room_member == member_id) {
        b->room_member = 0;
        LOG_I("room member #%d left", member_id);
    }
}

/*
 * The Room protocol has no CreateAccessPoint equivalent: IdSetGameInfo carries
 * contains only {name, id, version}, and JoinRequest's "password" is the ROOM password,
 * not the LDN crypto passphrase. So unlike RyuLdn - where the guest's own
 * CreateNetwork supplies everything - the bridge has to learn the passphrase
 * from the patched Eden, which appends it to every IdLdnPacket.
 *
 * Without a passphrase the LDN network cannot be built at all, because retail
 * firmware only accepts security level 1 (AES-CTR), whose key is derived from
 * it. Better to fail loudly than to advertise a network that no console will
 * ever be able to join.
 */
static int room_configure_host(Bridge *b, const RoomPacketIn *pkt,
                               const char *nickname)
{
    if (!pkt->game_id) {
        return 0; /* not a game report; nothing to do */
    }

    if (b->host) {
        /* Already configured. Re-read the title id in case the member
         * switched games without leaving the room. */
        if (b->title_id != pkt->game_id) {
            LOG_I("room member switched to title %016llx",
                  (unsigned long long)pkt->game_id);
            b->title_id = pkt->game_id;
        }
        return 0;
    }

    uint8_t passphrase[64];
    size_t passphrase_len = 0;

    if (b->learned_passphrase_len) {
        /* The patched Eden forward it inside its own IdLdnPacket. */
        memcpy(passphrase, b->learned_passphrase, b->learned_passphrase_len);
        passphrase_len = b->learned_passphrase_len;
    }

    if (!passphrase_len) {
        LOG_E("Room transport: cannot build the LDN network for title %016llx, "
              "because the LDN crypto passphrase never arrived. Stock Eden "
              "drops it in LANDiscovery::CreateNetwork(); apply "
              "patches/eden-room-passphrase.patch to forward it.",
              (unsigned long long)pkt->game_id);
        room_send_reject(b->room_server, b->room_member, RoomRejectCloseRoom);
        return -1;
    }

    LOG_I("using the %zu-byte passphrase supplied by the room member", passphrase_len);

    b->host = host_create(b->prodkeys, pkt->game_id, b->channel, b->band, 8, passphrase,
                          passphrase_len, nickname, pkt->game_version[0] ? 1 : 0);
    if (!b->host) {
        return -1;
    }
    b->title_id = pkt->game_id;

    LOG_I("LDN host created from the room member's game report (title=%016llx, "
          "channel=%u)", (unsigned long long)b->title_id, b->channel);
    return 0;
}

static void room_on_packet(RoomServer *server, int member_id, const RoomPacketIn *pkt,
                           void *user)
{
    Bridge *b = user;
    if (!b->room_member || member_id != b->room_member) {
        return;
    }

    if (pkt->type == IdSetGameInfo) {
        if (room_configure_host(b, pkt, pkt->game_name) == 0 && b->host) {
            /* The guest will start scanning; answer with our own view. */
            host_sync_station_list(b->host);
        }
        return;
    }

    if (pkt->type == IdLdnPacket) {
        /* A patched Eden repeats the passphrase on every packet; remember the
         * first one so the host can be built as soon as we know the title. */
        if (pkt->passphrase_len && !b->learned_passphrase_len) {
            memcpy(b->learned_passphrase, pkt->passphrase, pkt->passphrase_len);
            b->learned_passphrase_len = pkt->passphrase_len;
            LOG_D("learned a %u-byte LDN passphrase from the room member",
                  pkt->passphrase_len);
        }

        switch ((LDNPacketType)pkt->ldn_packet_type) {
        case LDNPacketTypeScan: {
            if (!b->host) {
                /*
                 * The room member is in this room but the emulator's game has
                 * not called CreateNetwork yet, so there is no LDN network to
                 * advertise. Replying with an empty ScanResp would make yuzu
                 * insert an all-zero NetworkInfo into scan_results, so it is
                 * better to say nothing and let it scan again.
                 */
                LOG_D("room: Scan before the guest created a network; ignoring");
                return;
            }

            LOG_D("room: LDN Scan -> replying with our NetworkInfo");
            RyuLdnNetworkInfo info;
            build_network_info(b, &info);
            room_send_ldn_packet(server, member_id, LDNPacketTypeScanResp,
                                 pkt->ldn_remote_ip, pkt->ldn_local_ip, false, &info,
                                 (uint32_t)sizeof(info));
            return;
        }

        case LDNPacketTypeScanResp:
            /* we are the host; other scanners reply, not us */
            return;

        case LDNPacketTypeConnect:
            LOG_D("room: LDN Connect from guest (it is the host, nothing to do)");
            return;

        case LDNPacketTypeSyncNetwork:
            return;

        case LDNPacketTypeDisconnect:
            LOG_I("room: guest disconnected");
            return;

        case LDNPacketTypeDestroyNetwork:
            LOG_I("room: guest destroyed the network");
            return;
        }
        return;
    }

    if (pkt->type == IdProxyPacket) {
        /* yuzu's game traffic: same shape as RyuLdn ProxyData. */
        RyuLdnProxyInfo info;
        memset(&info, 0, sizeof(info));
        info.source_ipv4 = rd_be32(pkt->local_ip);
        info.source_port = pkt->local_port;
        info.dest_ipv4 = pkt->remote_ip[0] == 0xFF && pkt->remote_ip[3] == 0xFF
                             ? 0xFFFFFFFFu
                             : rd_be32(pkt->remote_ip);
        info.dest_port = pkt->remote_port;
        info.protocol = pkt->protocol;

        /*
         * ProxySocket::SendPacket ZSTD-compresses every payload and only the
         * receiving game socket decompresses it, so the relay has to undo it
         * or the console would be handed compressed bytes. Fail loudly rather
         * than emit garbage onto the air.
         */
        uint8_t plain[2304];
        int plain_len = room_proxy_decompress(pkt->data, pkt->data_len, plain,
                                              sizeof(plain));
        if (plain_len < 0) {
            LOG_E("room: IdProxyPacket payload is not a zstd frame (%u bytes); "
                  "dropping it",
                  pkt->data_len);
            return;
        }
        deliver_from_guest(b, info, plain, (size_t)plain_len);
        return;
    }

}

/* ------------------------------------------------------------------ */
/* Radio RX                                                           */
/* ------------------------------------------------------------------ */

static void radio_rx(const RadioFrame *frame, void *user)
{
    Bridge *b = user;

    /*
     * radio.c's emit() normalises everything it receives into a frame with a
     * *synthesised* 24-byte 802.11 header, so there is no EtherType to read:
     * bytes 12..13 are part of addr2, the sender's MAC. Matching against them
     * silently disabled both branches below - LDN control frames never reached
     * the host FSM, so no console could ever authenticate, and Pia traffic
     * never reached the emulator.
     *
     * So classify from the payload instead, via the same macro emit() and the
     * rest of the stack use for "where the payload starts".
     */
    if (RADIO_PAYLOAD_LEN(frame) < 6) {
        return;
    }
    const uint8_t *body = RADIO_PAYLOAD(frame);

    /*
     * Two LDN framings exist and they are NOT the same:
     *
     *   - the advertisement, from ldn_build_advertisement_action_frame():
     *     cat(1) OUI(3) proto(1) pad(1) type(2), so the type is at +6;
     *   - the auth/disconnect control frames, from build_88b7_header():
     *     OUI(3) type(2) pad(1), so the type is at +3.
     *
     * Both carry the 00:22:AA OUI, so identify them by the OUI and then by
     * the type at whichever offset that framing uses.
     */
    bool is_advertisement =
        frame->frame_len >= IEEE80211_HDRLEN + 12 &&
        body[0] == LDN_CATEGORY_VENDOR_SPECIFIC && body[1] == LDN_OUI_0 &&
        body[2] == LDN_OUI_1 && body[3] == LDN_OUI_2 && body[4] == LDN_PROTOCOL_ID &&
        rd_be16(body + 6) == LDN_PACKET_ADVERTISEMENT;
    bool is_control =
        frame->frame_len >= IEEE80211_HDRLEN + 5 && body[0] == LDN_OUI_0 &&
        body[1] == LDN_OUI_1 && body[2] == LDN_OUI_2 &&
        rd_be16(body + 3) == LDN_PACKET_AUTHENTICATION;

    if (is_advertisement || is_control) {
        /* LDN control frames (auth/disconnect) - the host FSM owns those. */
        if (b->host) {
            host_handle_frame(b->host, b->radio, frame);
        }
        return;
    }

    /*
     * Otherwise it is Pia mesh traffic. emit() stripped whatever encapsulation
     * the frame arrived with, so what follows the 802.11 header is the IP
     * packet. Re-attach an Ethernet header over it, because that is the shape
     * parse_udp() and build_udp_frame() already speak, which also keeps the
     * two directions symmetric.
     */
    size_t payload_len = RADIO_PAYLOAD_LEN(frame);
    uint8_t eth[14 + 2304];
    if (payload_len + 14 > sizeof(eth)) {
        LOG_E("radio->guest: %zu-byte payload does not fit, dropping it", payload_len);
        return;
    }
    memcpy(eth, frame->dst_mac, 6);
    memcpy(eth + 6, frame->src_mac, 6);
    wr_be16(eth + 12, 0x0800);
    memcpy(eth + 14, body, payload_len);
    deliver_to_guest(b, eth, payload_len + 14);
}

/* ------------------------------------------------------------------ */
/* CLI                                                                */
/* ------------------------------------------------------------------ */

static const char *k_usage =
    "switch_ldn - bridge real Nintendo Switch consoles to the Ryujinx and yuzu\n"
    "emulator families over the Switch's own local wireless (LDN) protocol.\n"
    "\n"
    "  switch_ldn --selfcheck <iface>\n"
    "\n"
    "  # Both transports listen at once. The emulator's own CreateNetwork call\n"
    "  # supplies the passphrase, the title id and the local communication\n"
    "  # version, so prod.keys is the only thing the bridge needs from you.\n"
    "  switch_ldn --ap-iface wlan0 --channel 1 --prodkeys prod.keys\n"
    "  switch_ldn --radio-socket /tmp/ldn-console.sock --prodkeys prod.keys\n"
    "\n"
    "Options:\n"
    "  --selfcheck <if>       probe the NIC (mode, freq, VIF support) and exit\n"
    "  --ap-iface <if>        interface managed by hostapd\n"
    "  --mon-iface <if>       optional monitor interface for action frames;\n"
    "                         omitted by default, which injects them over\n"
    "                         nl80211 on --ap-iface instead (needed for the\n"
    "                         RTL8812AU, where a monitor VIF hangs the driver)\n"
    "  --radio-socket <path>  Unix datagram socket standing in for the radio,\n"
    "                         so a fake console can talk to the bridge with no\n"
    "                         NIC and no root. --ap-iface becomes optional.\n"
    "  --channel <n>          LDN channel: 1/6/11 (2.4G) or 36-48 (5G).\n"
    "                         Used as the default until the game picks one.\n"
    "  --band <2|5>           band, default 2\n"
    "  --prodkeys <file>      prod.keys (default: ./prod.keys, then\n"
    "                         ~/.config/switch_ldn/prod.keys,\n"
    "                         then ~/.switch/prod.keys)\n"
    "  --bind <addr>          bind address for both protocols (default 127.0.0.1)\n"
    "  --port <n>             RyuLdn port (default 30456) - Ryubing/Ryujinx\n"
    "  --room-port <n>        Room port (default 24872) - Eden/yuzu\n"
    "  --room-name <s>        name shown in the room list\n"
    "  -v, --verbose          raise log verbosity\n"
    "\n";

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/*
 * Where prod.keys comes from when --prodkeys is not given.
 *
 * The three values the bridge actually needs out of that file - master_key_00,
 * aes_kek_generation_source, aes_key_generation_source - are the *common*
 * console keys: every Switch has the same ones, which is exactly why one
 * console can decrypt another console's LDN advertisement. So "which file"
 * does not matter, only that it is a real one; a file dumped from a different
 * console works just as well as your own.
 *
 * Hence: look in the obvious places instead of demanding the flag every time.
 * If none of them exist, say which ones were tried - a bare "needs --prodkeys"
 * sends people looking for a flag they already know about.
 */
static int find_prodkeys(const char *explicit_path, char *out, size_t cap)
{
    if (explicit_path) {
        snprintf(out, cap, "%s", explicit_path);
        return 0;
    }

    const char *home = getenv("HOME");
    const char *xdg = getenv("XDG_CONFIG_HOME");
    char cand[4][PATH_MAX];
    size_t n = 0;

    /* A checkout or a working directory with prod.keys beside the binary. */
    if (snprintf(cand[n], PATH_MAX, "prod.keys") > 0) {
        n++;
    }
    /* XDG first if set, so $XDG_CONFIG_HOME overrides the ~/.config default. */
    if (xdg && *xdg && snprintf(cand[n], PATH_MAX, "%s/switch_ldn/prod.keys", xdg) > 0) {
        n++;
    } else if (home && *home &&
               snprintf(cand[n], PATH_MAX, "%s/.config/switch_ldn/prod.keys", home) > 0) {
        n++;
    }
    if (home && *home && snprintf(cand[n], PATH_MAX, "%s/.switch/prod.keys", home) > 0) {
        n++;
    }

    for (size_t i = 0; i < n; i++) {
        if (access(cand[i], R_OK) == 0) {
            snprintf(out, cap, "%s", cand[i]);
            LOG_I("using prod.keys from %s", cand[i]);
            return 0;
        }
    }

    LOG_E("prod.keys not found. Pass --prodkeys <file>, or put one in:");
    for (size_t i = 0; i < n; i++) {
        LOG_E("  %s", cand[i]);
    }
    LOG_E("Only three common keys are read: master_key_00,");
    LOG_E("aes_kek_generation_source and aes_key_generation_source.");
    return -1;
}

int main(int argc, char **argv)
{
    static struct option opts[] = {
        {"selfcheck", required_argument, 0, 'S'},
        {"ap-iface", required_argument, 0, 'a'},
        {"mon-iface", required_argument, 0, 'm'},
        {"radio-socket", required_argument, 0, 's'},
        {"channel", required_argument, 0, 'c'},
        {"band", required_argument, 0, 'b'},
        {"prodkeys", required_argument, 0, 'k'},
        {"host-name", required_argument, 0, 'n'},
        {"bind", required_argument, 0, 'B'},
        {"room-port", required_argument, 0, 'R'},
        {"room-name", required_argument, 0, 'N'},
        {"port", required_argument, 0, 'P'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    const char *ap_iface = NULL;
    const char *mon_iface = NULL;
    const char *radio_socket = NULL;
    const char *prodkeys_path = NULL;
    const char *host_name = "Player";
    const char *bind_addr = "127.0.0.1";
    uint16_t room_port = ROOM_DEFAULT_PORT;
    const char *room_name = "switch_ldn";
    const char *selfcheck_iface = NULL;
    uint16_t port = 30456;
    uint8_t channel = 1;
    uint8_t band = 2;

    int c;
    int idx = 0;
    while ((c = getopt_long(argc, argv, "v", opts, &idx)) != -1) {
        switch (c) {
        case 'S': selfcheck_iface = optarg; break;
        case 'a': ap_iface = optarg; break;
        case 'm': mon_iface = optarg; break;
        case 's': radio_socket = optarg; break;
        case 'c': channel = (uint8_t)atoi(optarg); break;
        case 'b': band = (uint8_t)atoi(optarg); break;
        case 'k': prodkeys_path = optarg; break;
        case 'n': host_name = optarg; break;
        case 'B': bind_addr = optarg; break;
        case 'R': room_port = (uint16_t)atoi(optarg); break;
        case 'N': room_name = optarg; break;
        case 'P': port = (uint16_t)atoi(optarg); break;
        case 'v': log_set_level(LOG_DEBUG); break;
        case 'h': fputs(k_usage, stdout); return 0;
        default: fputs(k_usage, stderr); return 1;
        }
    }

    /* ---------------- selfcheck mode ---------------- */
    if (selfcheck_iface) {
        /* Nonzero when the probe fails, so a script can branch on it. */
        return radio_selfcheck(selfcheck_iface) < 0 ? 1 : 0;
    }

    /* ---------------- prod.keys ---------------- */
    ProdKeys prodkeys;
    memset(&prodkeys, 0, sizeof(prodkeys));

    char prodkeys_used[PATH_MAX];
    if (find_prodkeys(prodkeys_path, prodkeys_used, sizeof(prodkeys_used)) != 0) {
        return 1;
    }
    if (prodkeys_load(&prodkeys, prodkeys_used) != 0) {
        return 1;
    }

    /* ---------------- live mode ---------------- */
    if (!ap_iface && !radio_socket) {
        LOG_E("either --ap-iface or --radio-socket is required in live mode");
        fputs(k_usage, stderr);
        return 1;
    }
    if (band == 5 && (channel < 36 || channel > 48)) {
        LOG_W("5 GHz band needs channel 36-48");
    }
    if (band == 2 && channel != 1 && channel != 6 && channel != 11) {
        LOG_W("2.4 GHz band should use channel 1, 6 or 11 (got %u)", channel);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    Bridge bridge;
    memset(&bridge, 0, sizeof(bridge));
    bridge.prodkeys = &prodkeys;
    bridge.channel = channel;
    bridge.band = band;
    bridge.guest_proxy_ip = 0x0A720001; /* 10.114.0.1, plain number */

    Bridge *b = &bridge;

    b->server = ryuldn_server_create(bind_addr, port, &k_handlers, b);
    if (!b->server) {
        return 1;
    }

    /*
     * Same bridge, second transport. Ryubing points at --port, Eden points at
     * --room-port; both drive the identical LDN core underneath, so a user can
     * switch between them without noticing anything.
     */
    RoomHandlers room_handlers = {
        .on_join = room_on_join,
        .on_leave = room_on_leave,
        .on_packet = room_on_packet,
    };
    b->room_server = room_server_create(bind_addr, room_port, &room_handlers, b,
                                       room_name, "switch_ldn bridge", host_name,
                                       LDN_NODE_MAX);
    if (!b->room_server) {
        LOG_E("could not start the Room transport (port %u in use?)", room_port);
        return 1;
    }

    RadioConfig rcfg;
    memset(&rcfg, 0, sizeof(rcfg));
    if (radio_socket) {
        /*
         * Socket backend: no NIC, no root, and the peer is a separate process
         * speaking the bridge's own framing. The MAC is fixed and locally
         * administered so a fake console has something stable to address.
         */
        static const uint8_t socket_mac[6] = {0x02, 0x4A, 0x57, 0x53, 0x53, 0x4B};
        strncpy(rcfg.radio_socket, radio_socket, sizeof(rcfg.radio_socket) - 1);
        if (ap_iface) {
            strncpy(rcfg.ap_iface, ap_iface, sizeof(rcfg.ap_iface) - 1);
            /* No default: an empty monitor interface selects the nl80211
             * injection path, which is what the RTL8812AU needs. Only an
             * explicit --mon-iface asks for the AF_PACKET monitor. */
            if (mon_iface) {
                strncpy(rcfg.mon_iface, mon_iface, sizeof(rcfg.mon_iface) - 1);
            }
            if (radio_get_hwaddr(ap_iface, rcfg.mac) != 0) {
                LOG_E("cannot read MAC of %s", ap_iface);
                return 1;
            }
        } else {
            memcpy(rcfg.mac, socket_mac, sizeof(rcfg.mac));
        }
        LOG_I("radio socket: MAC %02x:%02x:%02x:%02x:%02x:%02x to be used by the "
              "fake console",
              rcfg.mac[0], rcfg.mac[1], rcfg.mac[2], rcfg.mac[3], rcfg.mac[4],
              rcfg.mac[5]);
    } else {
        strncpy(rcfg.ap_iface, ap_iface, sizeof(rcfg.ap_iface) - 1);
        if (mon_iface) {
            strncpy(rcfg.mon_iface, mon_iface, sizeof(rcfg.mon_iface) - 1);
        }
        if (radio_get_hwaddr(ap_iface, rcfg.mac) != 0) {
            LOG_E("cannot read MAC of %s", ap_iface);
            return 1;
        }
        LOG_I("AP MAC %02x:%02x:%02x:%02x:%02x:%02x", rcfg.mac[0], rcfg.mac[1],
              rcfg.mac[2], rcfg.mac[3], rcfg.mac[4], rcfg.mac[5]);
    }
    rcfg.channel = channel;
    rcfg.band = band;

    b->radio = radio_open(&rcfg, radio_rx, b);
    if (!b->radio) {
        return 1;
    }

    /*
     * The LDN host is created lazily, when the emulator's game calls
     * CreateNetwork: that call carries the passphrase, the title id and the
     * local communication version. All we need up front is prod.keys.
     */
    LOG_I("bridge running: RyuLdn on %s:%u, Room on %s:%u, hostapd on '%s'",
          bind_addr, port, bind_addr, room_port, ap_iface);
    LOG_I("  Ryubing/Ryujinx -> Multiplayer > LDN > Mode: RyuLDN, server %s:%u",
          bind_addr, port);
    LOG_I("  Eden/Citron     -> Multiplayer > Direct Connect > %s:%u", bind_addr,
          room_port);

    while (!g_stop) {
        ryuldn_server_poll(b->server, 0);
        room_server_poll(b->room_server, 0);

        /*
         * Always poll the radio. The AP-interface read is what learns a
         * console's frames, and on the socket backend it is also how the peer
         * is discovered - gating this on mon_iface used to leave the socket
         * backend deaf in both directions.
         */
        radio_poll(b->radio, 50);
        if (b->host) {
            host_tick(b->host, b->radio);

            HostEvent ev;
            while (host_poll_event(b->host, &ev)) {
                notify_station_changed(b, &ev);
            }
        }
    }

    LOG_I("shutting down");
    host_destroy(b->host);
    radio_close(b->radio);
    room_server_destroy(b->room_server);
    ryuldn_server_destroy(b->server);
    return 0;
}
