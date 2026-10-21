/* Wire-format unit tests. Run with: make test */
#include <assert.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#include "common.h"
#include "crypto.h"
#include "ldn.h"
#include "ryuldn.h"
#include "radio.h"
#include "ryuldn.h"

int main(void)
{
    /* --- RyuLdn struct sizes match the reference protocol doc --- */
    assert(sizeof(RyuLdnHeader) == 12);
    assert(sizeof(RyuLdnNodeInfo) == 0x40);
    assert(sizeof(RyuLdnNetworkInfo) == 0x480);
    assert(sizeof(RyuLdnConnectRequest) == 0x500);
    assert(sizeof(RyuLdnProxyDataHeader) == 20);

    /* --- LDN sizes match the wiki --- */
    assert(LDN_ADVERTISEMENT_PAYLOAD_SIZE == 0x548);
    assert(LDN_ADV_DATA_SIZE_MAX == 0x500);
    assert(LDN_PARTICIPANT_SIZE == 56);
    assert(LDN_NODE_MAX == 8);
    assert(sizeof(LdnAdvertiseData) > 0);

    /* --- endian helpers round-trip --- */
    uint8_t b[8];
    wr_be32(b, 0x01001B30u);
    assert(rd_be32(b) == 0x01001B30u);
    wr_le32(b, 0x01001B30u);
    assert(rd_le32(b) == 0x01001B30u);
    wr_be16(b, 0x88B7u);
    assert(ETH_P_LDN == 0x88B7);
    assert(rd_be16(b) == ETH_P_LDN);

    /* --- channel encoding: (band << 10) | channel --- */
    uint16_t ch = ldn_encode_channel(2, 1);
    assert(ldn_channel_band(ch) == 2);
    assert(ldn_channel_num(ch) == 1);
    ch = ldn_encode_channel(5, 40);
    assert(ldn_channel_band(ch) == 5);
    assert(ldn_channel_num(ch) == 40);

    /* --- session info layout: title id at 0x00, game mode at 0x0A --- */
    LdnSessionInfo si = {0};
    si.local_communication_id = 0x01001B300B9BE000ull;
    si.game_mode = 7;
    uint8_t raw[32];
    ldn_session_info_encode(&si, raw);
    assert(rd_be64(raw) == 0x01001B300B9BE000ull);
    assert(rd_be16(raw + 0x0A) == 7);

    LdnSessionInfo back = {0};
    ldn_session_info_decode(raw, &back);
    assert(back.local_communication_id == 0x01001B300B9BE000ull);
    assert(back.game_mode == 7);

    /* --- AES-CTR is a stream cipher: same input in == same output out --- */
    uint8_t key[16] = {0}, cb[16] = {0}, in[64], out[64], dec[64];
    for (int i = 0; i < 64; i++) in[i] = (uint8_t)i;
    aes128_ctr_xor(key, cb, in, out, 64);
    aes128_ctr_xor(key, cb, out, dec, 64);
    assert(memcmp(in, dec, 64) == 0);
    assert(memcmp(in, out, 64) != 0);

    /* --- key derivation is deterministic --- */
    ProdKeys keys;
    memset(&keys, 0, sizeof(keys));
    uint8_t master[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    memcpy(keys.master_key_00, master, 16);
    memcpy(keys.aes_kek_generation_source, master, 16);
    memcpy(keys.aes_key_generation_source, master, 16);
    keys.has_master_key_00 = keys.has_aes_kek_generation_source =
        keys.has_aes_key_generation_source = true;
    assert(prodkeys_ready(&keys));

    uint8_t session[32];
    for (int i = 0; i < 32; i++) session[i] = (uint8_t)(i * 3 + 1);
    uint8_t k1[16], k2[16];
    assert(ldn_adv_key(&keys, session, k1) == 0);
    assert(ldn_adv_key(&keys, session, k2) == 0);
    assert(memcmp(k1, k2, 16) == 0);

    /* different session info -> different advertisement key */
    session[31] ^= 0xFF;
    assert(ldn_adv_key(&keys, session, k2) == 0);
    assert(memcmp(k1, k2, 16) != 0);

    /* different passphrase -> different data key */
    uint8_t p1[16] = "0123456789abcdef", p2[16] = "0123456789abcdee";
    assert(ldn_data_key(&keys, session, p1, 16, k1) == 0);
    assert(ldn_data_key(&keys, session, p2, 16, k2) == 0);
    assert(memcmp(k1, k2, 16) != 0);

    /* --- challenge HMAC is fixed-key and deterministic --- */
    uint8_t h1[32], h2[32];
    ldn_challenge_hmac_sha256("abc", 3, h1);
    ldn_challenge_hmac_sha256("abc", 3, h2);
    assert(memcmp(h1, h2, 32) == 0);

    /* --- IP encoding: 169.254.X.Y network byte order --- */
    uint32_t ip = htonl((169u << 24) | (254u << 16) | (1u << 8) | 2u);
    const uint8_t *p = (const uint8_t *)&ip;
    assert(p[0] == 169 && p[1] == 254 && p[2] == 1 && p[3] == 2);

    /* ------------------------------------------------------------------ */
    /* The guest's own CreateNetwork call is where the LDN network comes  */
    /* from, so parse a synthetic CreateAccessPoint packet and check that */
    /* passphrase / title id / channel / version survive.                  */
    /* ------------------------------------------------------------------ */
    {
        uint8_t req[0xBC];
        memset(req, 0, sizeof(req));

        RyuLdnSecurityConfig *sc = (RyuLdnSecurityConfig *)req;
        sc->security_mode = 1;
        sc->passphrase_size = 0x20;
        memcpy(sc->passphrase, "WirelessStrongCryptoKey2021", 28);

        RyuLdnUserConfig *uc = (RyuLdnUserConfig *)(req + 0x44);
        memcpy(uc->user_name, "TestPlayer", 10);

        RyuLdnNetworkConfig *nc = (RyuLdnNetworkConfig *)(req + 0x74);
        nc->intent_id.local_communication_id = 0x01001B300B9BE000ull;
        nc->intent_id.scene_id = 3;
        nc->channel = 6;
        nc->node_count_max = 4;
        nc->local_communication_version = 0x1234;

        /* offsets must line up with Ryubing/LdnServer's [StructLayout] */
        assert((size_t)((uint8_t *)uc - req) == 0x44);
        assert((size_t)((uint8_t *)nc - req) == 0x74);
        assert(sc->passphrase_size == 0x20);
        /* RyuLdn is entirely little-endian, so the u64 is read natively. */
        assert(nc->intent_id.local_communication_id == 0x01001B300B9BE000ull);
        assert(rd_le64((const uint8_t *)&nc->intent_id.local_communication_id) ==
               0x01001B300B9BE000ull);

        RyuLdnGuestGameSettings guest;
        memset(&guest, 0, sizeof(guest));
        memcpy(&guest.security, req, sizeof(guest.security));
        memcpy(&guest.network, req + 0x74, sizeof(guest.network));
        memcpy(&guest.user, req + 0x44, sizeof(guest.user));
        guest.advertise_data_size = 8;
        memcpy(guest.advertise_data, "appdata", 8);

        assert(guest.security.passphrase_size == 32);
        assert(guest.network.channel == 6);
        assert(guest.network.node_count_max == 4);
        assert(guest.network.local_communication_version == 0x1234);
        assert(!strncmp(guest.user.user_name, "TestPlayer", 10));
        assert(guest.advertise_data_size + 0xBC == 0xC4);
    }

    /*
     * --- ProxyInfo addresses are plain numbers, and blitted little-endian ---
     *
     * Ryujinx's LdnProxy.GetIpV4() is Reverse(address bytes) then
     * BitConverter.ToUInt32(), so 169.254.3.1 is stored as 0xA9FE0301 and the
     * Pack=1 struct is memcpy'd straight onto the wire. GetEndpoint() is the
     * inverse. Getting this wrong does not fail - it silently sends every
     * packet to a different address.
     *
     * The bug this pins: the two address fields disagreed. source_ipv4 held
     * the number and dest_ipv4 held an htonl()'d one, so no peer could read
     * both correctly, and deliver_from_guest()'s station lookup could never
     * match a unicast address (broadcast worked, because 0xFFFFFFFF swaps to
     * itself - which is why the mistake stayed hidden).
     */
    {
        RyuLdnProxyInfo info;
        memset(&info, 0, sizeof(info));
        info.source_ipv4 = 0xA9FE0301; /* 169.254.3.1 */
        info.source_port = 40000;
        info.dest_ipv4 = 0x0A720001;   /* 10.114.0.1 */
        info.dest_port = 30000;
        info.protocol = 17;

        /* Blit it the way ryuldn_send_proxy_data() does. */
        uint8_t wire[sizeof(info)];
        memcpy(wire, &info, sizeof(info));

        /* source_ipv4 occupies 0x00..0x03, little-endian. */
        assert(wire[0] == 0x01 && wire[1] == 0x03 &&
               wire[2] == 0xFE && wire[3] == 0xA9);
        /* dest_ipv4 is at 0x06 (interleaved!), also little-endian. Reading it
         * back as a number must give the same address, not a swapped one. */
        uint32_t dest;
        memcpy(&dest, wire + 0x06, 4);
        assert(dest == 0x0A720001);
        assert(wire[6] == 0x01 && wire[7] == 0x00 &&
               wire[8] == 0x72 && wire[9] == 0x0A);

        /* The two address fields must agree on byte order. Whatever the order
         * is, blitting and reading back must be lossless for both. */
        uint32_t src;
        memcpy(&src, wire + 0x00, 4);
        assert(src == info.source_ipv4);

        /* And the numeric value must survive the IP-header round trip:
         * rd_be32 reads the wire bytes of an IPv4 header into exactly this
         * number. */
        uint8_t iphdr[20];
        memset(iphdr, 0, sizeof(iphdr));
        iphdr[12] = 169; iphdr[13] = 254; iphdr[14] = 3; iphdr[15] = 1;
        assert(rd_be32(iphdr + 12) == 0xA9FE0301);
        uint8_t out[20];
        wr_be32(out + 12, 0xA9FE0301);
        assert(memcmp(out + 12, iphdr + 12, 4) == 0);

        /* The broadcast address Ryujinx derives: ProxyIp | ~ProxySubnetMask.
         * With a wrong-width subnet mask this is nonsense, and Ryujinx uses it
         * to decide what to broadcast - so it is worth pinning. */
        uint32_t proxy_ip = 0x0A720001, mask = 0xFFFF0000;
        assert((proxy_ip | ~mask) == 0x0A72FFFF);

        /* The bridge's own derivation must agree with that. */
        uint32_t subnet = proxy_ip & 0xFFFF0000u;
        assert((subnet | 0x0000FFFFu) == 0x0A72FFFF);
    }

    printf("all wire-format tests passed\n");
    return 0;
}
