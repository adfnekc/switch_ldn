/*
 * Station watchdog tests.
 *
 * There is no public "add a remote station" API, so this drives the real LDN
 * authentication path through host_handle_frame() with a synthesised auth
 * request and a NULL radio. That is enough for the host to allocate a slot and
 * push HOST_EVENT_STATION_JOINED, which gives the watchdog something real to
 * evict once its timeout expires.
 *
 * The same path also lets us check that host_set_station_timeout_ms(host, 0)
 * leaves the 30 s default in place: after a tick with a few milliseconds of
 * wall-clock elapsed the station must still be present (a zero timeout would
 * have evicted it immediately).
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "host.h"
#include "ldn.h"

static int fail;

static void expect(const char *what, int ok)
{
    printf("  %-52s %s\n", what, ok ? "ok" : "FAILED");
    if (!ok) {
        fail++;
    }
}

/* Drain the event ring and report whether `want` was seen. */
static int poll_kind(Host *host, HostEventKind want, int *index, HostEvent *out)
{
    HostEvent ev;
    while (host_poll_event(host, &ev)) {
        if (ev.kind == want) {
            if (index) {
                *index = ev.index;
            }
            if (out) {
                *out = ev;
            }
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    /*
     * host_create() derives the LDN keys, so it needs a complete prod.keys.
     * The fixture is synthetic: any 16 bytes work, because this test only
     * exercises the station bookkeeping around the watchdog.
     */
    static ProdKeys keys;
    memset(&keys, 0, sizeof(keys));
    for (int i = 0; i < LDN_KEY_LEN; i++) {
        keys.master_key_00[i] = (uint8_t)(0x11 * (i + 1));
        keys.aes_kek_generation_source[i] = (uint8_t)(0x22 * (i + 1));
        keys.aes_key_generation_source[i] = (uint8_t)(0x33 * (i + 1));
    }
    keys.has_master_key_00 = true;
    keys.has_aes_kek_generation_source = true;
    keys.has_aes_key_generation_source = true;

    static const uint8_t passphrase[16] = "LDN_PASSPHRASE!!";
    const uint64_t title = 0x01006F8002320000ULL;

    Host *host = host_create(&keys, title, 1, 0, 8, passphrase,
                             sizeof(passphrase), "switch_ldn", 0);
    if (!host) {
        printf("  host_create failed (prod.keys fixture rejected)\n");
        return 1;
    }

    const uint8_t host_mac[6] = {0x02, 0x4A, 0x57, 0x53, 0x44, 0x00};
    const uint8_t sta_mac[6] = {0x02, 0x4A, 0x57, 0x53, 0x44, 0x01};
    host_set_guest_identity(host, "switch_ldn", host_mac, 0);

    /* A fresh host with no stations: a tick must not crash or emit events. */
    host_set_station_timeout_ms(host, 0);
    host_tick(host, NULL);
    HostEvent ev;
    expect("fresh host tick does not emit events", host_poll_event(host, &ev) == 0);
    expect("fresh host has zero stations", host_station_count(host) == 0);

    /* --- Drive a real join through the LDN authentication path. --- */
    uint8_t session_be[32];
    ldn_session_info_encode(host_session_info(host), session_be);

    LdnAuthData auth;
    memset(&auth, 0, sizeof(auth));
    auth.version = LDN_VERSION_3;
    auth.is_response = 0;
    auth.status_code = LDN_AUTH_SUCCESS;
    auth.payload_size = LDN_AUTH_REQUEST_PAYLOAD;
    auth.platform = LDN_PLATFORM_SWITCH;
    snprintf(auth.username, sizeof(auth.username), "Tester");
    auth.app_communication_version = 0x1234;
    memcpy(auth.session_info, session_be, 32);
    memcpy(auth.server_random, host_advertise(host)->server_random, 16);
    auth.client_random[0] = 0xAB;

    uint8_t raw[IEEE80211_HDRLEN + LDN_AUTH_HEADER_SIZE + LDN_AUTH_REQUEST_PAYLOAD];
    size_t payload_len = 0;
    int n = ldn_build_auth_frame(raw, sizeof(raw), sta_mac, host_mac, &auth,
                                 &payload_len);
    expect("auth request builds", n > 0);
    if (n <= 0) {
        host_destroy(host);
        printf("\n%s\n", fail ? "FAILED" : "all host watchdog tests passed");
        return fail ? 1 : 0;
    }

    /*
     * host_handle_frame() reads the destination from frame->dst_mac and
     * looks for ETH_P_LDN at frame[12], while the LDN body starts at
     * IEEE80211_HDRLEN. Build a RadioFrame that satisfies both.
     */
    RadioFrame rf;
    memset(&rf, 0, sizeof(rf));
    memcpy(rf.dst_mac, host_mac, 6);
    memcpy(rf.src_mac, sta_mac, 6);
    /*
     * Only the payload matters: radio.c's emit() gives every frame a synthetic
     * 24-byte MAC header, and host_handle_frame() identifies an LDN auth
     * request by the vendor body at +24 - not by an EtherType. There used to be
     * a `wr_be16(rf.frame + 12, ETH_P_LDN)` and a `payload_ethertype` field
     * here, both written to satisfy a dispatch that read bytes 12..13 as an
     * EtherType. Those bytes are addr2, so the old pairing was asserting the
     * bug rather than the behaviour.
     */
    memcpy(rf.frame + IEEE80211_HDRLEN, raw + IEEE80211_HDRLEN,
           (size_t)n - IEEE80211_HDRLEN);
    rf.frame_len = (size_t)n;

    expect("auth request is consumed", host_handle_frame(host, NULL, &rf));

    int idx = -1;
    expect("join event pushed", poll_kind(host, HOST_EVENT_STATION_JOINED, &idx, NULL));
    expect("join used slot 1", idx == 1);
    expect("station count is one", host_station_count(host) == 1);

    const HostStation *st = host_station(host, 1);
    expect("station is in use", st && st->in_use);
    expect("last_seen_ms is set", st && st->last_seen_ms != 0);
    expect("joined_ms is set", st && st->joined_ms != 0);
    expect("joined_ms <= last_seen_ms", st && st->joined_ms <= st->last_seen_ms);

    /*
     * Timeout 0 must not install a zero timeout: wait past a millisecond and
     * tick; the default (30 s) must leave the station joined.
     */
    uint64_t t0 = now_ms();
    while (now_ms() - t0 < 5) {
        /* spin until the clock advances */
    }
    host_tick(host, NULL);
    expect("timeout 0 keeps the default (station survives)",
           host_station_count(host) == 1 &&
           !poll_kind(host, HOST_EVENT_STATION_LEFT, NULL, NULL));

    /* Now shrink the timeout and confirm the watchdog evicts the station. */
    host_set_station_timeout_ms(host, 1);
    t0 = now_ms();
    while (now_ms() - t0 < 5) {
        /* spin until the clock advances */
    }
    host_tick(host, NULL);

    int left_idx = -1;
    HostEvent left = {0};
    expect("leave event pushed on timeout",
           poll_kind(host, HOST_EVENT_STATION_LEFT, &left_idx, &left));
    expect("leave event names slot 1", left_idx == 1);
    /*
     * The slot is already cleared at this point, so the event must carry the
     * station's identity itself. Without that snapshot the transports branched
     * on st->in_use and dropped every departure.
     */
    expect("leave event carries the MAC",
           memcmp(left.mac, "\x02\x4a\x57\x53\x44\x01", 6) == 0);
    expect("leave event carries the username",
           strcmp(left.username, "Tester") == 0);
    expect("leave event carries an IP", left.ipv4 != 0);
    expect("station count back to zero", host_station_count(host) == 0);
    st = host_station(host, 1);
    expect("evicted slot is cleared", st && !st->in_use);

    host_destroy(host);

    printf("\n%s\n", fail ? "FAILED" : "all host watchdog tests passed");
    return fail ? 1 : 0;
}
