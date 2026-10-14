#ifndef SWITCH_LDN_LDN_H
#define SWITCH_LDN_LDN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

/*
 * LDN (Local Wireless, "nn::ldn") wire format.
 * Reference: NintendoClients/wiki/LDN-Protocol (and Local-Wireless-Communication-on-PC).
 * All multi-byte fields are big-endian unless noted.
 */

#define LDN_OUI_0 0x00
#define LDN_OUI_1 0x22
#define LDN_OUI_2 0xAA

#define LDN_CATEGORY_VENDOR_SPECIFIC 127
#define LDN_PROTOCOL_ID 4

enum {
    LDN_PACKET_ADVERTISEMENT = 257,
    LDN_PACKET_AUTHENTICATION = 258,
    LDN_PACKET_DISCONNECT = 259,
};

/* ethertype used by LDN control frames (OUI extended). */
#define ETH_P_LDN 0x88B7

/* LDN protocol versions (see the changelog in the wiki). */
enum {
    LDN_VERSION_2 = 2, /* 2.0.0  - 5.1.0  */
    LDN_VERSION_3 = 3, /* 6.0.0  - 18.1.0, adds the auth challenge */
    LDN_VERSION_4 = 4, /* 19.0.0 - 20.4.0, adds AES-GCM + band/channel */
};

enum {
    LDN_SECURITY_LEVEL_BOTH_ENCRYPTED = 1, /* only value allowed on retail firmware */
    LDN_SECURITY_LEVEL_ADV_ONLY = 2,
    LDN_SECURITY_LEVEL_PLAINTEXT = 3,
};

enum {
    LDN_ENC_TYPE_PLAIN = 1,
    LDN_ENC_TYPE_AES_CTR = 2,
    LDN_ENC_TYPE_AES_GCM = 3,
};

enum {
    LDN_ACCEPT_OPEN = 0,
    LDN_ACCEPT_CLOSED = 1,
    LDN_ACCEPT_BLACKLIST = 2,
    LDN_ACCEPT_WHITELIST = 3,
};

enum {
    LDN_PLATFORM_SWITCH = 0,
    LDN_PLATFORM_SWITCH_2 = 1,
};

/* 802.11 management/action frame header size (no QoS body). */
#define IEEE80211_HDRLEN 24

/* Sizes of the LDN payloads. */
#define LDN_SESSION_INFO_SIZE 32
#define LDN_ADVERTISEMENT_HEADER_SIZE 0x28
/*
 * Total advertisement payload:
 *   0x28 header + 0x20 SHA-256 + 0x500 advertisement data = 0x548.
 * (The advertisement data runs to 0x4F8 + 8 for the auth token.)
 */
#define LDN_ADVERTISEMENT_PAYLOAD_SIZE 0x548
#define LDN_PARTICIPANT_SIZE 56
#define LDN_NODE_MAX 8
#define LDN_APP_DATA_SIZE 384
#define LDN_NONCE_SIZE 4

/* Total serialised advertisement data: 0x500 bytes including the auth token. */
#define LDN_ADV_DATA_SIZE_MAX 0x500

#define LDN_ADV_DATA_OFF_PARTICIPANTS 0x18

/*
 * Vendor-specific action frame body prefix:
 *   category(1) OUI(3) protocol_id(1) padding(1) packet_type(2) 0(2) padding(2)
 * so the advertisement payload starts at body offset 0xC.
 */
#define LDN_ACTION_BODY_PREFIX_SIZE 0x0C

typedef struct {
    uint64_t local_communication_id; /* usually the title id */
    uint16_t game_mode;
    uint8_t ssid[16];
} LdnSessionInfo;

typedef struct {
    uint32_t ipv4; /* network byte order */
    uint8_t mac[6];
    bool is_connected;
    uint8_t platform;
    char username[32];
    uint16_t app_communication_version;
} LdnParticipant;

typedef struct {
    uint8_t server_random[16];
    uint16_t security_level;
    uint8_t station_accept_policy;
    uint16_t channel;
    uint8_t band;
    uint8_t node_count_max;
    uint8_t node_count;
    LdnParticipant nodes[LDN_NODE_MAX];
    uint16_t app_data_size;
    uint8_t app_data[LDN_APP_DATA_SIZE];
    uint8_t auth_token[8];
} LdnAdvertiseData;

typedef struct {
    uint8_t session_info[LDN_SESSION_INFO_SIZE];
    uint8_t version;
    uint8_t enc_type;
    uint16_t adv_data_size;
    uint8_t nonce[LDN_NONCE_SIZE];
    /* when enc_type == AES_CTR everything from here on is ciphertext */
    uint8_t hash[32];
    uint8_t data[LDN_ADVERTISEMENT_PAYLOAD_SIZE - LDN_ADVERTISEMENT_HEADER_SIZE - 32];
    size_t data_len;
} LdnAdvertisement;

/*
 * Build the vendor-specific action frame (802.11 header included) that the LDN
 * AP broadcasts every 100 ms.
 *
 * `mac` is our MAC address, `bssid` normally equals `mac`.
 * Returns the frame length or -1.
 */
int ldn_build_advertisement_action_frame(uint8_t *out, size_t out_len,
                                         const uint8_t mac[6],
                                         const LdnSessionInfo *session_info,
                                         const LdnAdvertiseData *adv_data,
                                         const ProdKeys *prodkeys,
                                         uint8_t security_level, uint8_t nonce[4],
                                         uint8_t *adv_key_out);

/* Helpers */
int ldn_session_info_encode(const LdnSessionInfo *info, uint8_t out[32]);
int ldn_session_info_decode(const uint8_t raw[32], LdnSessionInfo *info);

size_t ldn_participant_offset(int index);

/* 0x88B7 LDN control frames. */
typedef struct {
    uint8_t version;
    uint8_t session_info[32]; /* little-endian! */
    uint8_t server_random[16];
    uint8_t client_random[16];
    uint8_t status_code;
    uint8_t is_response; /* 0 = request, 1 = response */
    uint32_t payload_size;
    /* request payload */
    char username[32];
    uint16_t app_communication_version;
    uint8_t platform;
    /* response payload */
    uint8_t challenge_ok;
    bool has_challenge;
} LdnAuthData;

/*
 * Payload sizes (LDN version 3+).
 *
 *   request : 0x364 bytes - username(32) + app_version(2) + platform(1) +
 *             pad(29) + pad(0x24) + challenge(0x300)
 *   response: 0x84 bytes  - platform(1) + pad(0x83), plus an optional 0x100
 *                         challenge response we do not send, because as host
 *                         we are the verifier rather than the claimant.
 */
#define LDN_AUTH_REQUEST_PAYLOAD 0x364
#define LDN_AUTH_RESPONSE_PAYLOAD 0x84
#define LDN_AUTH_HEADER_SIZE 0x4E

/*
 * Status codes carried by an AuthenticationResponse. These are the values a
 * station surfaces as a connection error; they are enumerated on switchbrew
 * and match kinnay/LDN's AUTH_* constants.
 */
typedef enum {
    LDN_AUTH_SUCCESS = 0,
    LDN_AUTH_DENIED_BY_POLICY = 1,
    LDN_AUTH_MALFORMED_REQUEST = 2,
    LDN_AUTH_INVALID_VERSION = 4,
} LdnAuthStatus;

/* Sent in the clear; see the layout notes in ldn.c. */
int ldn_build_auth_frame(uint8_t *out, size_t out_len, const uint8_t mac[6],
                         const uint8_t bssid[6], const LdnAuthData *auth,
                         size_t *payload_len);

int ldn_parse_auth_frame(const uint8_t *frame, size_t frame_len, LdnAuthData *auth);

/* Channel helper: encodes (band << 10) | channel as the wiki describes. */
static inline uint16_t ldn_encode_channel(uint8_t band, uint16_t channel)
{
    return (uint16_t)(((band & 0x7) << 10) | (channel & 0x3FF));
}

static inline uint8_t ldn_channel_band(uint16_t v)
{
    return (uint8_t)((v >> 10) & 0x7);
}

static inline uint16_t ldn_channel_num(uint16_t v)
{
    return (uint16_t)(v & 0x3FF);
}

#endif /* SWITCH_LDN_LDN_H */
