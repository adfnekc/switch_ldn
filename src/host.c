#include "host.h"

#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include <openssl/sha.h>

#include "common.h"

typedef struct Host {
    LdnHost pub;
    uint64_t adv_expire_ms;

    /* A joined station that has not been heard from for this long is evicted. */
    uint64_t station_timeout_ms;

    /* Ring of join/leave events for the transports to drain. */
    HostEvent events[16];
    int event_head, event_count;
} Host;

/*
 * `st` is copied into the event before the caller clears the slot, so the
 * transports can still see *who* left when they drain the ring.
 */
static void host_push_event(Host *host, HostEventKind kind, int index,
                           const HostStation *st)
{
    if (host->event_count == (int)(sizeof(host->events) / sizeof(host->events[0]))) {
        LOG_W("host: event ring full, dropping a %s for slot %d",
              kind == HOST_EVENT_STATION_JOINED ? "join" : "leave", index);
        return;
    }
    int at = (host->event_head + host->event_count) %
             (int)(sizeof(host->events) / sizeof(host->events[0]));
    HostEvent *ev = &host->events[at];
    memset(ev, 0, sizeof(*ev));
    ev->kind = kind;
    ev->index = index;
    if (st) {
        memcpy(ev->mac, st->mac, sizeof(ev->mac));
        ev->ipv4 = st->ipv4;
        ev->app_communication_version = st->app_communication_version;
        memcpy(ev->username, st->username, sizeof(ev->username));
    }
    host->event_count++;
}

int host_poll_event(Host *host, HostEvent *ev)
{
    if (!host->event_count) {
        return 0;
    }
    *ev = host->events[host->event_head];
    host->event_head = (host->event_head + 1) %
                       (int)(sizeof(host->events) / sizeof(host->events[0]));
    host->event_count--;
    return 1;
}

static void rng_fill(uint8_t *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(buf, 1, len, f) != len) {
            /* fall through */
        }
        fclose(f);
        return;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

/*
 * 169.254.X.Y - Y=1 is always us (the host); joining stations get .2, .3, ...
 */
static uint32_t alloc_station_ip(const Host *host, int index)
{
    return (169u << 24) | (254u << 16) |
           ((uint32_t)host->pub.host_ip_octet_x << 8) | (uint32_t)(index + 2);
}

int host_station_index_by_mac(const Host *host, const uint8_t mac[6])
{
    for (int i = 0; i < HOST_MAX_STATIONS; i++) {
        if (host->pub.stations[i].in_use &&
            memcmp(host->pub.stations[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

const HostStation *host_station(const Host *host, int index)
{
    if (index < 0 || index >= HOST_MAX_STATIONS) {
        return NULL;
    }
    return &host->pub.stations[index];
}

const LdnAdvertiseData *host_advertise(const Host *host)
{
    return &host->pub.adv_data;
}

const LdnSessionInfo *host_session_info(const Host *host)
{
    return &host->pub.session_info;
}

/* ------------------------------------------------------------------ */

/*
 * Configure (or reconfigure) everything the advertisement depends on.
 *
 * There is exactly one entry point: the emulator's own nn::ldn::CreateNetwork
 * call, delivered either as a RyuLdn CreateAccessPoint packet or inside a
 * patched Eden IdLdnPacket.
 *
 * The keys only depend on prod.keys + session_info + passphrase, so they are
 * derived once here instead of for every 100 ms advertisement.
 */
static int host_configure(Host *host, uint64_t title_id, uint16_t channel,
                          uint8_t band, uint8_t node_count_max,
                          const uint8_t *passphrase, size_t passphrase_len,
                          const char *host_username, uint16_t app_comm_version)
{
    const ProdKeys *prodkeys = host->pub.prodkeys;

    host->pub.title_id = title_id;
    host->pub.channel = channel;
    host->pub.band = band;
    host->pub.security_level = LDN_SECURITY_LEVEL_BOTH_ENCRYPTED;
    host->pub.host_ip_octet_x = 1;
    host->pub.keys_ready = false;

    LdnAdvertiseData *ad = &host->pub.adv_data;
    memset(ad, 0, sizeof(*ad));
    rng_fill(ad->server_random, 16);
    ad->security_level = host->pub.security_level;
    ad->station_accept_policy = LDN_ACCEPT_OPEN;
    ad->channel = channel;
    ad->band = band;
    ad->node_count_max = node_count_max ? node_count_max : 8;
    if (ad->node_count_max > LDN_NODE_MAX) {
        ad->node_count_max = LDN_NODE_MAX;
    }

    memset(&host->pub.session_info, 0, sizeof(host->pub.session_info));
    host->pub.session_info.local_communication_id = title_id;
    rng_fill(host->pub.session_info.ssid, 16);

    /* Node 0 is us. Consoles that join get 169.254.X.2, X.3, ... */
    HostStation *self = &host->pub.stations[0];
    memset(self, 0, sizeof(*self));
    self->in_use = true;
    self->associated = true;
    self->ldn_joined = true;
    self->platform = LDN_PLATFORM_SWITCH;
    self->ipv4 = (169u << 24) | (254u << 16) |
                 ((uint32_t)host->pub.host_ip_octet_x << 8) | 1u;
    snprintf(self->username, sizeof(self->username), "%s",
             host_username && *host_username ? host_username : "switch_ldn");
    self->app_communication_version = app_comm_version;

    /* Drop any stations that had already joined: the network is being rebuilt
     * with a new SSID and new keys, so their association is meaningless. */
    for (int i = 1; i < HOST_MAX_STATIONS; i++) {
        memset(&host->pub.stations[i], 0, sizeof(HostStation));
    }
    host->pub.station_count = 0;

    host->adv_expire_ms = 0;
    rng_fill(host->pub.nonce, LDN_NONCE_SIZE);

    if (!prodkeys_ready(prodkeys)) {
        LOG_E("prod.keys incomplete; cannot build an encrypted LDN network");
        return -1;
    }

    uint8_t session_info_raw[32];
    ldn_session_info_encode(&host->pub.session_info, session_info_raw);

    /* Advertisement key: session_info only. */
    if (ldn_adv_key(prodkeys, session_info_raw, host->pub.adv_key) != 0) {
        LOG_E("advertisement key derivation failed");
        return -1;
    }

    /* Data key: server_random || passphrase. */
    if (!passphrase_len) {
        LOG_E("no LDN passphrase given by the guest; the console will reject "
              "the network (LDN requires security level %u with a passphrase)",
              host->pub.security_level);
        return -1;
    }
    if (ldn_data_key(prodkeys, ad->server_random, passphrase, passphrase_len,
                     host->pub.data_key) != 0) {
        LOG_E("data key derivation failed (passphrase longer than 64 bytes?)");
        return -1;
    }

    host->pub.keys_ready = true;
    LOG_D("host configured: title=%016llx chan=%u/%uG nodes=%u passphrase=%zu bytes",
          (unsigned long long)title_id, channel, band, ad->node_count_max,
          passphrase_len);
    return 0;
}

Host *host_create(const ProdKeys *prodkeys, uint64_t title_id, uint16_t channel,
                  uint8_t band, uint8_t node_count_max, const uint8_t *passphrase,
                  size_t passphrase_len, const char *host_username,
                  uint16_t app_comm_version)
{
    if (!prodkeys) {
        LOG_E("host_create needs prod.keys");
        return NULL;
    }

    Host *host = calloc(1, sizeof(*host));
    if (!host) {
        return NULL;
    }

    host->pub.prodkeys = prodkeys;
    host->station_timeout_ms = 30000;

    if (host_configure(host, title_id, channel, band, node_count_max, passphrase,
                       passphrase_len, host_username, app_comm_version) != 0) {
        free(host);
        return NULL;
    }
    return host;
}

int host_adopt_guest_settings(Host *host, uint64_t title_id, uint16_t channel,
                              uint8_t node_count_max, const uint8_t *passphrase,
                              size_t passphrase_len, const char *username,
                              uint16_t app_comm_version)
{
    /*
     * Called when the emulator's game creates its LDN network. Everything here
     * comes from the guest, so the bridge never has to know which game it is.
     */
    LOG_I("adopting the guest's LDN settings: title=%016llx chan=%u ver=%u "
          "passphrase=%zu bytes user='%s'",
          (unsigned long long)title_id, channel, app_comm_version, passphrase_len,
          username);

    /* The guest picked the channel, so ask the radio to follow it. */
    host->pub.channel = channel;

    return host_configure(host, title_id, channel, host->pub.band, node_count_max,
                          passphrase, passphrase_len, username, app_comm_version);
}


void host_set_guest_identity(Host *host, const char *username, const uint8_t mac[6],
                             uint16_t app_comm_version)
{
    if (!host) {
        return;
    }
    HostStation *self = &host->pub.stations[0];
    self->in_use = true;
    self->associated = true;
    self->ldn_joined = true;
    self->platform = LDN_PLATFORM_SWITCH;
    if (username && *username) {
        snprintf(self->username, sizeof(self->username), "%s", username);
    }
    if (mac) {
        memcpy(self->mac, mac, 6);
    }
    self->app_communication_version = app_comm_version;
}

int host_station_count(const Host *host)
{
    if (!host) {
        return 0;
    }
    return host->pub.station_count;
}

void host_touch_station(Host *host, int index)
{
    if (!host || index < 0 || index >= HOST_MAX_STATIONS) {
        return;
    }
    HostStation *st = &host->pub.stations[index];
    if (!st->in_use) {
        return;
    }
    st->last_seen_ms = now_ms();
}

void host_set_station_timeout_ms(Host *host, uint64_t ms)
{
    if (!host || ms == 0) {
        return;
    }
    host->station_timeout_ms = ms;
}

void host_destroy(Host *host)
{
    if (host) {
        free(host);
    }
}

/* ------------------------------------------------------------------ */
/* Advertisement                                                      */
/* ------------------------------------------------------------------ */

void host_sync_station_list(Host *host)
{
    LdnAdvertiseData *ad = &host->pub.adv_data;
    memset(ad->nodes, 0, sizeof(ad->nodes));

    ad->node_count = 0;
    for (int i = 0; i < HOST_MAX_STATIONS && ad->node_count < LDN_NODE_MAX; i++) {
        HostStation *st = &host->pub.stations[i];
        if (!st->in_use) {
            continue;
        }
        LdnParticipant *p = &ad->nodes[ad->node_count];
        p->ipv4 = st->ipv4;
        memcpy(p->mac, st->mac, 6);
        p->is_connected = st->associated && st->ldn_joined;
        p->platform = st->platform;
        memcpy(p->username, st->username, 32);
        p->app_communication_version = st->app_communication_version;
        ad->node_count++;
    }

    /* The BSSID shown in the advertisement must match the AP's MAC. */
    rng_fill(ad->auth_token, 8);
}

/*
 * host_tick() emits one advertisement every 100 ms and each of them must carry
 * a nonce one higher than the last, big-endian and wrapping at 2^32.
 */
static void advance_advert_nonce(uint8_t nonce[LDN_NONCE_SIZE])
{
    /* Big-endian increment with carry; wraps back to zero at 2^32. */
    for (int i = LDN_NONCE_SIZE - 1; i >= 0; i--) {
        if (++nonce[i] != 0) {
            break;
        }
    }
}

void host_set_app_data(Host *host, const uint8_t *data, uint16_t size)
{
    LdnAdvertiseData *ad = &host->pub.adv_data;
    memset(ad->app_data, 0, sizeof(ad->app_data));
    if (size > LDN_APP_DATA_SIZE) {
        size = LDN_APP_DATA_SIZE;
    }
    if (size) {
        memcpy(ad->app_data, data, size);
    }
    ad->app_data_size = size;
}

const uint8_t *host_nonce(const Host *host)
{
    return host->pub.nonce;
}

void host_tick(Host *host, Radio *radio)
{
    uint64_t now = now_ms();

    if (now >= host->adv_expire_ms) {
        host->adv_expire_ms = now + 100;
        host_sync_station_list(host);

        /*
         * The advertisement nonce must advance on every frame. A console's LDN
         * stack compares it against the previous one to tell a fresh
         * advertisement from a stale duplicate, so a constant nonce makes every
         * 100 ms frame look like a replay of the first and the player list is
         * never refreshed.
         */
        advance_advert_nonce(host->pub.nonce);

        const uint8_t *mac = radio ? radio_config(radio)->mac
                                   : host->pub.stations[0].mac;
        uint8_t frame[IEEE80211_HDRLEN + LDN_ACTION_BODY_PREFIX_SIZE +
                      LDN_ADVERTISEMENT_PAYLOAD_SIZE];
        int n = ldn_build_advertisement_action_frame(
            frame, sizeof(frame), mac, &host->pub.session_info, &host->pub.adv_data,
            host->pub.prodkeys, host->pub.security_level, host->pub.nonce, NULL);
        if (n < 0) {
            LOG_E("failed to build advertisement");
        } else {
            size_t len = (size_t)(n > 0 ? n : 0);
            if (radio) {
                radio_send_action_frame(radio, frame, len);
            } else {
                LOG_W("host_tick: no radio attached; advertisement not transmitted");
            }
        }
    }

    /*
     * Station watchdog. hostapd owns 802.11 association and keep-alive; what we
     * can observe is LDN traffic, so `last_seen_ms` is touched by every LDN
     * authentication frame. A station that goes quiet for longer than
     * station_timeout_ms is presumed gone: tell the transports, free the slot,
     * and let the advertisement shrink on the next emission.
     */
    for (int i = 1; i < HOST_MAX_STATIONS; i++) {
        HostStation *st = &host->pub.stations[i];
        if (!st->in_use || st->last_seen_ms == 0) {
            continue;
        }
        if (now - st->last_seen_ms > host->station_timeout_ms) {
            LOG_W("station %02x:%02x:%02x:%02x:%02x:%02x: timed out after "
                  "%llums, broadcasting leave",
                  st->mac[0], st->mac[1], st->mac[2], st->mac[3], st->mac[4],
                  st->mac[5], (unsigned long long)(now - st->last_seen_ms));
            host_push_event(host, HOST_EVENT_STATION_LEFT, i, st);
            memset(st, 0, sizeof(*st));
            if (host->pub.station_count > 0) {
                host->pub.station_count--;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Frame handling                                                     */
/* ------------------------------------------------------------------ */

/*
 * TODO(radio): 802.11 association is owned by hostapd and the kernel station
 * table; LDN learns a station's existence from its LDN authentication frame,
 * which is why this only ever sees stations that already associated. To map an
 * association event to an IP slot we would have to hook nl80211 (or read the
 * hostapd station list). Not needed while the LDN auth path carries the join.
 */

/*
 * Every rejection follows kinnay/LDN's _check_authentication_request():
 * an unsupported protocol version is reported as LDN_AUTH_INVALID_VERSION,
 * everything else we refuse (a request that is not well-formed, a station
 * that belongs to a different game, a different local play mode, or a stale
 * server_random from an advertisement we have since replaced) is reported as
 * LDN_AUTH_MALFORMED_REQUEST.
 */
static void reject_auth(Host *host, Radio *radio, const uint8_t station_mac[6],
                        const LdnAuthData *auth, uint8_t status)
{
    LdnAuthData rej;
    memset(&rej, 0, sizeof(rej));
    rej.version = LDN_VERSION_3;
    rej.is_response = 1;
    rej.status_code = status;
    rej.payload_size = LDN_AUTH_RESPONSE_PAYLOAD;
    rej.platform = LDN_PLATFORM_SWITCH;
    memcpy(rej.session_info, auth->session_info, 32);
    memcpy(rej.server_random, auth->server_random, 16);
    memcpy(rej.client_random, auth->client_random, 16);

    if (!radio) {
        LOG_W("reject_auth: no radio attached");
        return;
    }

    /*
     * Ethernet + 0x88B7, not a raw 802.11 frame: this goes to the AP
     * interface, which hostapd bridges to the station.
     */
    uint8_t buf[6 + LDN_AUTH_HEADER_SIZE + LDN_AUTH_RESPONSE_PAYLOAD];
    size_t len = 0;
    int n = ldn_build_auth_body(buf, sizeof(buf), &rej, &len);
    if (n > 0) {
        radio_send_ldn_control(radio, station_mac, buf, (size_t)n);
    }
}


static const uint8_t *host_mac(const Host *host, const Radio *radio)
{
    if (radio) {
        return radio_config(radio)->mac;
    }
    return host->pub.stations[0].mac;
}

bool host_handle_frame(Host *host, Radio *radio, const RadioFrame *frame)
{
    if (!host || !frame) {
        return false;
    }
    if (!radio) {
        LOG_W("host_handle_frame: no radio attached");
    }

    /* Only respond to frames addressed to our BSSID/MAC. */
    if (frame->frame_len < IEEE80211_HDRLEN + 8) {
        return false;
    }
    if (memcmp(frame->dst_mac, host_mac(host, radio), 6) != 0) {
        return false;
    }

    uint16_t fc = rd_le16(frame->frame); /* 802.11 header is little-endian */
    uint8_t type = (uint8_t)((fc >> 2) & 0x3);
    uint8_t subtype = (uint8_t)((fc >> 4) & 0xF);
    (void)type;
    (void)subtype;

    const uint8_t *body = frame->frame + IEEE80211_HDRLEN;
    if (frame->frame_len < sizeof(struct ethhdr)) {
        return false;
    }

    /*
     * NOTE: there is deliberately no ethertype check here.
     *
     * emit() hands us a frame with a synthesised 24-byte 802.11 header, so
     * bytes 12..13 are part of addr2 (the sender's MAC), not an EtherType -
     * comparing them against ETH_P_LDN could never match unless the console's
     * MAC happened to contain 88:B7 at bytes 2-3, and no authentication request
     * was ever recognised. The packet type lives in the vendor-specific body,
     * exactly where ldn_parse_auth_frame() reads it.
     */
    if (rd_be16(body + 3) == LDN_PACKET_AUTHENTICATION) {
        /* --- LDN authentication request -------------------------- */
        LdnAuthData auth;
        memset(&auth, 0, sizeof(auth));

        /* Authentication frames travel in the clear on the AES-CTR path. */
        if (ldn_parse_auth_frame(frame->frame, frame->frame_len, &auth) != 0) {
            return false;
        }
        if (auth.is_response) {
            LOG_D("station %02x:%02x:%02x:%02x:%02x:%02x: auth response status=%u",
                  frame->src_mac[0], frame->src_mac[1], frame->src_mac[2],
                  frame->src_mac[3], frame->src_mac[4], frame->src_mac[5],
                  auth.status_code);
            return true;
        }

        if (auth.version != LDN_VERSION_2 && auth.version != LDN_VERSION_3 &&
            auth.version != LDN_VERSION_4) {
            LOG_W("station %02x:%02x:%02x:%02x:%02x:%02x rejected: unsupported "
                  "protocol version %u",
                  frame->src_mac[0], frame->src_mac[1], frame->src_mac[2],
                  frame->src_mac[3], frame->src_mac[4], frame->src_mac[5],
                  auth.version);
            reject_auth(host, radio, frame->src_mac, &auth, LDN_AUTH_INVALID_VERSION);
            return true;
        }

        if (auth.status_code != LDN_AUTH_SUCCESS) {
            reject_auth(host, radio, frame->src_mac, &auth, LDN_AUTH_MALFORMED_REQUEST);
            return true;
        }

        /*
         * server_random is echoed back by the station in the request and by
         * us in the response; both sides use it to tie the exchange to one
         * advertisement. If it differs, the station heard a different
         * advertisement than the one we are serving now.
         */
        if (memcmp(auth.server_random, host->pub.adv_data.server_random, 16) != 0) {
            LOG_W("station %02x:%02x:%02x:%02x:%02x:%02x rejected: server_random "
                  "does not match our current advertisement",
                  frame->src_mac[0], frame->src_mac[1], frame->src_mac[2],
                  frame->src_mac[3], frame->src_mac[4], frame->src_mac[5]);
            reject_auth(host, radio, frame->src_mac, &auth, LDN_AUTH_MALFORMED_REQUEST);
            return true;
        }

        /*
         * A well-behaved host rejects stations whose network id does not match
         * its own: the request's session_info carries the title id and scene
         * id, and a mismatch means either a different game or a different local
         * play mode.
         *
         * Our session_info is stored big-endian, the frame's is little-endian
         * (reversed by ldn_build_auth_frame), so compare field by field rather
         * than memcmp'ing the buffers.
         */
        uint8_t want_be[32];
        ldn_session_info_encode(&host->pub.session_info, want_be);
        uint8_t got_be[32];
        for (int i = 0; i < 32; i++) {
            got_be[i] = auth.session_info[31 - i];
        }
        if (memcmp(want_be, got_be, 32) != 0) {
            uint64_t want_id = host->pub.session_info.local_communication_id;
            uint64_t got_id = rd_be64(got_be);
            uint16_t want_scene = host->pub.session_info.game_mode;
            uint16_t got_scene = rd_be16(got_be + 0x0A);
            LOG_W("station %02x:%02x:%02x:%02x:%02x:%02x rejected: title %016llx "
                  "scene %u, expected %016llx scene %u",
                  frame->src_mac[0], frame->src_mac[1], frame->src_mac[2],
                  frame->src_mac[3], frame->src_mac[4], frame->src_mac[5],
                  (unsigned long long)got_id, got_scene, (unsigned long long)want_id,
                  want_scene);

            reject_auth(host, radio, frame->src_mac, &auth, LDN_AUTH_MALFORMED_REQUEST);
            return true;
        }

        if (memcmp(frame->src_mac, host_mac(host, radio), 6) == 0) {
            LOG_W("station %02x:%02x:%02x:%02x:%02x:%02x rejected: MAC collides "
                  "with the host/AP MAC",
                  frame->src_mac[0], frame->src_mac[1], frame->src_mac[2],
                  frame->src_mac[3], frame->src_mac[4], frame->src_mac[5]);
            reject_auth(host, radio, frame->src_mac, &auth, LDN_AUTH_MALFORMED_REQUEST);
            return true;
        }

        int idx = host_station_index_by_mac(host, frame->src_mac);
        if (idx < 0) {
            for (int i = 1; i < HOST_MAX_STATIONS; i++) {
                if (!host->pub.stations[i].in_use) {
                    idx = i;
                    break;
                }
            }
            if (idx < 0) {
                LOG_W("no free station slot for %02x:...:xx",
                      frame->src_mac[0]);
                return false;
            }
            HostStation *st = &host->pub.stations[idx];
            memset(st, 0, sizeof(*st));
            st->in_use = true;
            st->associated = true;
            memcpy(st->mac, frame->src_mac, 6);
            st->platform = LDN_PLATFORM_SWITCH;
            snprintf(st->username, sizeof(st->username), "%s", auth.username);
            st->app_communication_version = auth.app_communication_version;
            st->ipv4 = alloc_station_ip(host, idx);
            st->last_seen_ms = now_ms();
            st->joined_ms = st->last_seen_ms;
            host->pub.station_count++;
            host_push_event(host, HOST_EVENT_STATION_JOINED, idx, st);
            LOG_I("station joined: %02x:%02x:%02x:%02x:%02x:%02x slot=%d ip=%u.%u.%u.%u",
                  st->mac[0], st->mac[1], st->mac[2], st->mac[3], st->mac[4], st->mac[5],
                  idx, (st->ipv4 >> 24) & 0xFF, (st->ipv4 >> 16) & 0xFF,
                  (st->ipv4 >> 8) & 0xFF, st->ipv4 & 0xFF);
        }

        host_touch_station(host, idx);

        /* Auth response: always Success (status 0). As host we do not have to
         * prove anything; Nintendo's challenge just guards against a single
         * purchase being reused, and we can simply decline to check. */
        LdnAuthData resp;
        memset(&resp, 0, sizeof(resp));
        resp.is_response = 1;
        resp.status_code = 0; /* success */
        resp.payload_size = LDN_AUTH_RESPONSE_PAYLOAD;
        resp.version = LDN_VERSION_3;
        memcpy(resp.session_info, auth.session_info, 32);
        memcpy(resp.server_random, auth.server_random, 16);
        memcpy(resp.client_random, auth.client_random, 16);
        resp.platform = LDN_PLATFORM_SWITCH;
        resp.has_challenge = auth.has_challenge;
        resp.challenge_ok = 1;

        uint8_t out[6 + LDN_AUTH_HEADER_SIZE + LDN_AUTH_RESPONSE_PAYLOAD];
        size_t payload_len = 0;
        if (!radio) {
            LOG_W("host_handle_frame: no radio attached; auth response not sent");
            return true;
        }
        int n = ldn_build_auth_body(out, sizeof(out), &resp, &payload_len);
        if (n > 0) {
            /* Ethernet + 0x88B7 on the AP interface; see radio.h. */
            if (radio_send_ldn_control(radio, frame->src_mac, out, (size_t)n) != 0) {
                LOG_E("could not send the auth response to station %d", idx);
            } else {
                LOG_D("sent auth success to station %d", idx);
            }
        }
        return true;
    }

    if (rd_be16(body + 3) == LDN_PACKET_DISCONNECT) {
        LOG_I("station left: %02x:%02x:%02x:%02x:%02x:%02x", frame->src_mac[0],
              frame->src_mac[1], frame->src_mac[2], frame->src_mac[3],
              frame->src_mac[4], frame->src_mac[5]);
        int idx = host_station_index_by_mac(host, frame->src_mac);
        if (idx >= 0) {
            host_push_event(host, HOST_EVENT_STATION_LEFT, idx,
                            &host->pub.stations[idx]);
            memset(&host->pub.stations[idx], 0, sizeof(HostStation));
            host->pub.station_count--;
        }
        return true;
    }

    return false;
}

