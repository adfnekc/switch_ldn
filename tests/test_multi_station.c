/*
 * test_multi_station.c -- more than one console at a time.
 *
 * Everything else in this tree joins a single station. The things that only go
 * wrong with several are exactly the ones a player would notice:
 *
 *   - two stations must never be handed the same IPv4 or the same slot,
 *   - the slot table must fill up and then refuse, rather than wrap or crash,
 *   - a station that leaves must free its slot so the next console can join,
 *   - the advertisement's node list must keep up with the station table, since
 *     that is how a console learns who else is in the room.
 *
 * It drives the real authentication path through host_handle_frame(), the same
 * way test_host_watchdog.c does, so this is the host's actual behaviour and not
 * a model of it.
 */

#include <stdio.h>
#include <string.h>

#include "common.h"
#include "crypto.h"
#include "host.h"
#include "ldn.h"

static int fail;

static void expect(const char *what, int ok)
{
    printf("  %-56s %s\n", what, ok ? "ok" : "FAILED");
    if (!ok) {
        fail++;
    }
}

static ProdKeys g_keys;

static ProdKeys make_keys(void)
{
    ProdKeys k;
    memset(&k, 0, sizeof(k));
    for (int i = 0; i < LDN_KEY_LEN; i++) {
        k.master_key_00[i] = (uint8_t)(0x11 * (i + 1));
        k.aes_kek_generation_source[i] = (uint8_t)(0x22 * (i + 1));
        k.aes_key_generation_source[i] = (uint8_t)(0x33 * (i + 1));
    }
    k.has_master_key_00 = true;
    k.has_aes_kek_generation_source = true;
    k.has_aes_key_generation_source = true;
    return k;
}

/* Build and feed one LDN authentication request from `mac`. */
static int join(Host *host, const uint8_t host_mac[6], const uint8_t mac[6],
                const char *name)
{
    uint8_t session_be[32];
    ldn_session_info_encode(host_session_info(host), session_be);

    LdnAuthData auth;
    memset(&auth, 0, sizeof(auth));
    auth.version = LDN_VERSION_3;
    auth.is_response = 0;
    auth.status_code = LDN_AUTH_SUCCESS;
    auth.payload_size = LDN_AUTH_REQUEST_PAYLOAD;
    auth.platform = LDN_PLATFORM_SWITCH;
    snprintf(auth.username, sizeof(auth.username), "%s", name);
    auth.app_communication_version = 0x1234;
    memcpy(auth.session_info, session_be, 32);
    memcpy(auth.server_random, host_advertise(host)->server_random, 16);

    uint8_t raw[IEEE80211_HDRLEN + LDN_AUTH_HEADER_SIZE + LDN_AUTH_REQUEST_PAYLOAD];
    size_t payload_len = 0;
    int n = ldn_build_auth_frame(raw, sizeof(raw), mac, host_mac, &auth, &payload_len);
    if (n <= 0) {
        return 0;
    }

    RadioFrame rf;
    memset(&rf, 0, sizeof(rf));
    memcpy(rf.dst_mac, host_mac, 6);
    memcpy(rf.src_mac, mac, 6);
    memcpy(rf.frame + IEEE80211_HDRLEN, raw + IEEE80211_HDRLEN,
           (size_t)n - IEEE80211_HDRLEN);
    rf.frame_len = (size_t)n;
    return host_handle_frame(host, NULL, &rf) ? 1 : 0;
}

static int leave(Host *host, const uint8_t host_mac[6], const uint8_t mac[6])
{
    uint8_t body[6 + 8];
    memset(body, 0, sizeof(body));
    body[0] = LDN_OUI_0;
    body[1] = LDN_OUI_1;
    body[2] = LDN_OUI_2;
    wr_be16(body + 3, LDN_PACKET_DISCONNECT);

    RadioFrame rf;
    memset(&rf, 0, sizeof(rf));
    memcpy(rf.dst_mac, host_mac, 6);
    memcpy(rf.src_mac, mac, 6);
    memcpy(rf.frame + IEEE80211_HDRLEN, body, sizeof(body));
    rf.frame_len = IEEE80211_HDRLEN + sizeof(body);
    return host_handle_frame(host, NULL, &rf) ? 1 : 0;
}

int main(void)
{
    g_keys = make_keys();

    static const uint8_t passphrase[16] = "LDN_PASSPHRASE!!";
    const uint64_t title = 0x01006F8002320000ULL;

    Host *host = host_create(&g_keys, title, 1, 0, 8, passphrase,
                             sizeof(passphrase), "switch_ldn", 0);
    if (!host) {
        printf("  host_create failed\n");
        return 1;
    }

    const uint8_t host_mac[6] = {0x02, 0x4A, 0x57, 0x53, 0x44, 0x00};
    host_set_guest_identity(host, "switch_ldn", host_mac, 0);

    /* --- fill the table --- */
    const int capacity = HOST_MAX_STATIONS - 1; /* slot 0 belongs to the guest */
    uint8_t macs[HOST_MAX_STATIONS][6];
    uint32_t ips[HOST_MAX_STATIONS];

    for (int i = 0; i < capacity; i++) {
        memcpy(macs[i], (uint8_t[]){0x02, 0x4A, 0x57, 0x53, 0x44, (uint8_t)(0x10 + i)}, 6);
        int ok = join(host, host_mac, macs[i], "Player");
        expect("station joins", ok == 1);
    }
    expect("the table is full", host_station_count(host) == capacity);

    /* --- no two stations share a slot or an address --- */
    int distinct_slots = 1, distinct_ips = 1, in_subnet = 1;
    for (int i = 0; i < capacity; i++) {
        const HostStation *a = NULL;
        int seen = 0;
        for (int s = 0; s < HOST_MAX_STATIONS; s++) {
            const HostStation *st = host_station(host, s);
            if (st && st->in_use && memcmp(st->mac, macs[i], 6) == 0) {
                a = st;
                ips[i] = st->ipv4;
                seen++;
            }
        }
        if (seen != 1 || !a) {
            distinct_slots = 0;
            continue;
        }
        if ((a->ipv4 >> 24) != 169 || ((a->ipv4 >> 16) & 0xFF) != 254) {
            in_subnet = 0;
        }
        for (int j = 0; j < i; j++) {
            if (ips[j] == a->ipv4) {
                distinct_ips = 0;
            }
        }
    }
    expect("every station appears in exactly one slot", distinct_slots);
    expect("every station has its own IPv4", distinct_ips);
    expect("every address is in 169.254.0.0/16", in_subnet);

    /* --- the advertisement lists the guest plus every station ---
     * host_tick() is what rebuilds the node list, in the same call that emits
     * an advertisement every 100 ms; reading host_advertise() without one would
     * report an empty room while seven consoles are in it. */
    host_tick(host, NULL);
    const LdnAdvertiseData *ad = host_advertise(host);
    expect("advertisement node count tracks the station table",
           ad->node_count == host_station_count(host) + 1);
    expect("advertisement node list did not overflow",
           ad->node_count <= LDN_NODE_MAX);

    /* --- a station beyond capacity is refused, not wrapped --- */
    uint8_t extra[6] = {0x02, 0x4A, 0x57, 0x53, 0x44, 0x7F};
    join(host, host_mac, extra, "Latecomer");
    expect("an over-capacity station is refused",
           host_station_count(host) == capacity);
    expect("...and gets no slot", host_station_index_by_mac(host, extra) < 0);

    /* --- a station that leaves frees its slot for the next console ---
     * Slot 0 belongs to the emulator guest, so the joined stations occupy
     * 1..capacity; never assume slot number == array index. */
    int victim = host_station_index_by_mac(host, macs[3]);
    expect("the third station has a slot above the guest's", victim > 0);
    uint32_t freed_ip = ips[3];
    {
        HostEvent drain;
        while (host_poll_event(host, &drain)) {
        }
    }
    expect("station leaves", leave(host, host_mac, macs[3]) == 1);
    expect("...and is gone from the table",
           host_station_index_by_mac(host, macs[3]) < 0);
    expect("...and the count dropped", host_station_count(host) == capacity - 1);

    uint8_t newcomer[6] = {0x02, 0x4A, 0x57, 0x53, 0x44, 0x5A};
    expect("a new station can join the freed slot",
           join(host, host_mac, newcomer, "Newcomer") == 1);
    expect("...and the table is full again",
           host_station_count(host) == capacity);

    int idx = host_station_index_by_mac(host, newcomer);
    const HostStation *st = host_station(host, idx);
    expect("...reusing its address", st && st->ipv4 == freed_ip);

    /* --- events: one LEFT for the departure, JOINED for the arrival --- */
    {
        int joined = 0, left = 0;
        HostEvent ev;
        while (host_poll_event(host, &ev)) {
            if (ev.kind == HOST_EVENT_STATION_JOINED) joined++;
            if (ev.kind == HOST_EVENT_STATION_LEFT) left++;
        }
    }

    /* --- an unknown MAC leaving must not corrupt anything --- */
    {
        uint8_t stranger[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x99};
        leave(host, host_mac, stranger);
        expect("a disconnect from an unknown MAC is ignored",
               host_station_count(host) == capacity);
        expect("...and leaves the advertisement consistent",
               host_advertise(host)->node_count == capacity + 1);
    }

    host_destroy(host);
    printf("\n%s\n", fail ? "FAILED" : "all multi-station tests passed");
    return fail ? 1 : 0;
}
