/*
 * test_frame_classify.c -- pin how a frame arriving on the AP interface is
 * classified.
 *
 * This is a regression test for the bug that cost the most time in this
 * project's hardware bring-up: an Ethernet LDN control frame has ethertype
 * 0x88B7, and emit()'s "is this Ethernet?" test explicitly excluded that value,
 * so every inbound authentication request fell through to the 802.11 branch and
 * was parsed at the wrong offsets. Everything still compiled, and console-sim
 * still passed, because the fake console was sending 802.11 frames that no real
 * console ever sends.
 *
 * So each branch is asserted individually, and the shapes here are the ones the
 * wire actually carries: the AP netdev's link type is Ethernet, so real frames
 * are the first two kinds.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/ldn.h"

static const uint8_t k_ap_mac[6]   = {0x02, 0x4A, 0x57, 0x53, 0x53, 0x4B};
static const uint8_t k_sta_mac[6]  = {0x02, 0x4A, 0x57, 0x53, 0x44, 0x99};

/* An Ethernet header followed by `body`, in classic (non-QoS) form. */
static size_t wrap_eth(uint8_t *out, const uint8_t *dst, const uint8_t *src,
                       uint16_t ethertype, const uint8_t *body, size_t body_len)
{
    memcpy(out, dst, 6);
    memcpy(out + 6, src, 6);
    out[12] = (uint8_t)(ethertype >> 8);
    out[13] = (uint8_t)(ethertype & 0xFF);
    if (body_len) {
        memcpy(out + 14, body, body_len);
    }
    return 14 + body_len;
}

int main(void)
{
    uint8_t buf[64];

    /* --- LDN control: Ethernet 0x88B7 + the 00:22:aa OUI, types 258/259. ---
     * This is how a real console's authentication request arrives. */
    for (uint16_t type = 258; type <= 259; type++) {
        uint8_t body[6] = {0x00, 0x22, 0xAA, 0, 0, 0};
        body[3] = (uint8_t)(type >> 8);
        body[4] = (uint8_t)(type & 0xFF);
        size_t n = wrap_eth(buf, k_ap_mac, k_sta_mac, 0x88B7, body, 6);
        assert(ldn_classify_ap_frame(buf, n) == LDN_FRAME_CONTROL);

        /* The ethertype is a red herring: classification keys on the OUI and
         * the packet type. A control frame whose ethertype is something else
         * is still LDN control, because that is what the payload says. */
        size_t m = wrap_eth(buf, k_ap_mac, k_sta_mac, 0x0800, body, 6);
        assert(ldn_classify_ap_frame(buf, m) == LDN_FRAME_CONTROL);
    }

    /* Right OUI, wrong packet type -> not control. Type 260 is not one we
     * relay, and it must not be mistaken for LDN control just because the OUI
     * matches. */
    {
        uint8_t body[6] = {0x00, 0x22, 0xAA, 0x01, 0x04, 0x00}; /* 260 */
        size_t n = wrap_eth(buf, k_ap_mac, k_sta_mac, 0x88B7, body, 6);
        assert(ldn_classify_ap_frame(buf, n) != LDN_FRAME_CONTROL);
    }

    /* --- Game traffic: Ethernet IPv4 / IPv6 / ARP. --- */
    {
        static const uint16_t k_etypes[] = {0x0800, 0x86DD, 0x0806};
        uint8_t ip[20];
        memset(ip, 0, sizeof(ip));
        ip[0] = 0x45; /* IPv4, so the frame looks like something real */
        for (size_t i = 0; i < sizeof(k_etypes) / sizeof(k_etypes[0]); i++) {
            size_t n = wrap_eth(buf, k_ap_mac, k_sta_mac, k_etypes[i], ip,
                                sizeof(ip));
            assert(ldn_classify_ap_frame(buf, n) == LDN_FRAME_ETHERNET);
        }
    }

    /* An arbitrary vendor ethertype is neither control nor game traffic. */
    {
        uint8_t body[8] = {0x09, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00};
        size_t n = wrap_eth(buf, k_ap_mac, k_sta_mac, 0x888E, body, 8);
        assert(ldn_classify_ap_frame(buf, n) == LDN_FRAME_DROP);
    }

    /* --- Raw 802.11, which the --radio-socket harness can still produce. ---
     * Frame control is little-endian: action = 0x00D0 -> bytes d0 00, and a
     * data frame = 0x0008 -> 08 00. Writing these big-endian was another bug
     * that only hardware caught. */
    {
        uint8_t f[24];
        memset(f, 0, sizeof(f));
        f[0] = 0xD0;
        f[1] = 0x00;
        assert(ldn_classify_ap_frame(f, sizeof(f)) == LDN_FRAME_80211_ACTION);

        f[0] = 0x08;
        f[1] = 0x00;
        assert(ldn_classify_ap_frame(f, sizeof(f)) == LDN_FRAME_80211_DATA);
    }

    /* --- Truncation and empties must be DROP, never a wild read. --- */
    assert(ldn_classify_ap_frame(buf, 0) == LDN_FRAME_DROP);
    assert(ldn_classify_ap_frame(buf, 1) == LDN_FRAME_DROP);
    {
        uint8_t body[6] = {0x00, 0x22, 0xAA, 0x01, 0x02, 0x00};
        /* 19 bytes: enough for an Ethernet header but not the 6-byte LDN
         * prefix, so the control check must decline rather than read past. */
        size_t n = wrap_eth(buf, k_ap_mac, k_sta_mac, 0x88B7, body, 5);
        assert(n == 19);
        assert(ldn_classify_ap_frame(buf, n) != LDN_FRAME_CONTROL);
        /* ...and 20 bytes, with the sixth body byte present, is enough. */
        buf[14 + 5] = 0x00;
        assert(ldn_classify_ap_frame(buf, 20) == LDN_FRAME_CONTROL);
    }

    printf("OK: AP frame classification (control / ethernet / 802.11 / drop)\n");
    return 0;
}
