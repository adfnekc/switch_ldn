#ifndef SWITCH_LDN_RYULDN_H
#define SWITCH_LDN_RYULDN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * RyuLdn protocol (Ryujinx/Ryubing "LDN over TCP").
 *
 * Reference: https://ethiquema.github.io/ryu_ldn_nx/reference/protocol/ and
 * Ryubing/LdnServer (src/LdnServer/Session/LdnSession.cs, Network/...).
 *
 * This is a *headless server* implementation: the bridge listens on a TCP port
 * and Ryubing/Eden connect to it, exactly as they would connect to a normal
 * LdnServer instance. That is what turns "an emulator guest" into just another
 * LDN participant that the bridge can bridge to real 802.11 consoles.
 *
 * Wire rules that matter:
 *   - all integers little-endian
 *   - LdnHeader is 12 bytes (a 2-byte `reserved` pads data_size onto a
 *     4-byte boundary at offset 0x08)
 *   - NetworkInfo is 0x480 bytes, LdnNetworkInfo is 0x430,
 *     ConnectRequest is 0x500 with an explicit _padding at 0x7C so that
 *     NetworkInfo lands on an 8-byte boundary (0x80)
 *   - IP addresses are stored "Ryujinx format": the literal dotted quad bytes,
 *     i.e. big-endian as a u32, no bswap
 */

#define RYULDN_MAGIC 0x4E444C52u /* "RLDN" */
#define RYULDN_VERSION 1

enum {
    RYULDN_INITIALIZE = 0,
    RYULDN_PASSPHRASE = 1,
    RYULDN_CREATE_ACCESS_POINT = 2,
    RYULDN_CREATE_ACCESS_POINT_PRIVATE = 3,
    RYULDN_EXTERNAL_PROXY = 4,
    RYULDN_EXTERNAL_PROXY_TOKEN = 5,
    RYULDN_EXTERNAL_PROXY_STATE = 6,
    RYULDN_SYNC_NETWORK = 7,
    RYULDN_REJECT = 8,
    RYULDN_REJECT_REPLY = 9,
    RYULDN_SCAN = 10,
    RYULDN_SCAN_REPLY = 11,
    RYULDN_SCAN_REPLY_END = 12,
    RYULDN_CONNECT = 13,
    RYULDN_CONNECT_PRIVATE = 14,
    RYULDN_CONNECTED = 15,
    RYULDN_DISCONNECT = 16,
    RYULDN_PROXY_CONFIG = 17,
    RYULDN_PROXY_CONNECT = 18,
    RYULDN_PROXY_CONNECT_REPLY = 19,
    RYULDN_PROXY_DATA = 20,
    RYULDN_PROXY_DISCONNECT = 21,
    RYULDN_SET_ACCEPT_POLICY = 22,
    RYULDN_SET_ADVERTISE_DATA = 23,
    RYULDN_PING = 254,
    RYULDN_NETWORK_ERROR = 255,
};

#define RYULDN_HEADER_SIZE 12

typedef struct {
    uint8_t magic[4];
    uint8_t type;
    uint8_t version;
    uint8_t reserved[2];
    uint32_t data_size;
} RyuLdnHeader;

/* ---------------------------------------------------------------- */
/* Wire structures (all __attribute__((packed)) to keep offsets      */
/* identical to the C# server without Pack=1)                        */
/* ---------------------------------------------------------------- */

typedef struct __attribute__((packed)) {
    uint8_t id[16];
    uint8_t mac[6];
} RyuLdnInitializeMessage; /* 22 bytes */

typedef struct __attribute__((packed)) {
    uint8_t passphrase[128];
} RyuLdnPassphraseMessage;

/*
 * The *game's own* LDN network security configuration, forwarded verbatim from
 * the guest's nn::ldn::CreateNetwork call. It carries the crypto passphrase,
 * which is why the bridge needs no per-game table when the emulator creates
 * the network (see DESIGN.md "Adopting the game's settings").
 */
typedef struct __attribute__((packed)) {
    uint16_t security_mode;
    uint16_t passphrase_size; /* 0x10-0x40, or 0 if the game passed none */
    uint8_t passphrase[64];
} RyuLdnSecurityConfig; /* 0x44 */

typedef struct __attribute__((packed)) {
    char user_name[33];
    uint8_t unknown1[15];
} RyuLdnUserConfig; /* 0x30 */

/*
 * IntentId is 16 bytes. In Ryubing/LdnServer it is:
 *   LocalCommunicationId (ulong, 0x00)  -> the title id
 *   SceneId             (ushort, 0x08)  -> which "local play mode"
 *   reserved            (6 bytes, 0x0A)
 */
typedef struct __attribute__((packed)) {
    uint64_t local_communication_id;
    uint16_t scene_id;
    uint8_t reserved[6];
} RyuLdnIntentId; /* 16 bytes */

typedef struct __attribute__((packed)) {
    RyuLdnIntentId intent_id;                 /* 0x00: 16 bytes */
    uint16_t channel;                         /* 0x10 */
    uint8_t node_count_max;                   /* 0x12 */
    uint8_t reserved1;                        /* 0x13 */
    uint16_t local_communication_version;     /* 0x14 */
    uint8_t reserved2[10];                    /* 0x16 */
} RyuLdnNetworkConfig; /* 0x20 */

typedef struct __attribute__((packed)) {
    uint8_t game_version[16];
    uint8_t private_ip[16];
    uint32_t address_family;
    uint16_t external_proxy_port;
    uint16_t internal_proxy_port;
} RyuLdnRyuNetworkConfig; /* 0x28 */

/*
 * CreateAccessPointRequest (0xBC = 188 bytes). The game's advertise data is
 * appended right after this structure, which is how we learn everything
 * needed to put a matching network in the air.
 */
typedef struct __attribute__((packed)) {
    RyuLdnSecurityConfig security_config;      /* 0x00: 0x44 */
    RyuLdnUserConfig user_config;              /* 0x44: 0x30 */
    RyuLdnNetworkConfig network_config;        /* 0x74: 0x20 */
    RyuLdnRyuNetworkConfig ryu_network_config; /* 0x94: 0x28 */
} RyuLdnCreateAccessPointRequest; /* 0xBC */

typedef struct __attribute__((packed)) {
    uint32_t ipv4_address;
    uint8_t mac[6];
    uint8_t node_id;
    uint8_t is_connected;
    char user_name[33];
    uint8_t reserved1;
    uint16_t local_communication_version;
    uint8_t reserved2[16];
} RyuLdnNodeInfo; /* 0x40 */

typedef struct __attribute__((packed)) {
    uint8_t network_id[32];
    /* CommonNetworkInfo (0x30) */
    uint8_t common[48];
    /* LdnNetworkInfo (0x430) */
    uint8_t security_parameter[16];
    uint16_t security_mode;
    uint8_t station_accept_policy;
    uint8_t unknown1;
    uint16_t reserved1;
    uint8_t node_count_max;
    uint8_t node_count;
    RyuLdnNodeInfo nodes[8];
    uint16_t reserved2;
    uint16_t advertise_data_size;
    uint8_t advertise_data[384];
    uint8_t unknown2[140];
    uint64_t authentication_id;
} RyuLdnNetworkInfo; /* 0x480 */

typedef struct __attribute__((packed)) {
    uint32_t proxy_ip;
    uint32_t proxy_subnet_mask;
} RyuLdnProxyConfig;

/*
 * ProxyInfo - matching Ryubing/LdnServer's Network/Types/ProxyInfo.cs, which
 * is [StructLayout(Sequential, Size = 0x10, Pack = 1)].
 *
 * WARNING: the fields are interleaved (ip, port, ip, port, proto), NOT grouped
 * by kind. Both layouts total 16 bytes so a size assertion cannot catch this,
 * but getting it wrong routes every game packet to the wrong address.
 *
 * WARNING: the two address fields are *plain numbers*, not network byte order.
 * Ryujinx's LdnProxy.GetIpV4() reverses the address bytes and runs
 * BitConverter.ToUInt32() on them, so 169.254.3.1 becomes 0xA9FE0301 and the
 * struct is blitted as-is: on x86 that is little-endian on the wire.
 * GetEndpoint() is the exact inverse. Converting these with htonl()/ntohl()
 * therefore swaps them - which shipped once, in one field only, and made the
 * downlink unable to match a station by address.
 *
 * The relay's own addresses (Bridge::guest_proxy_ip, HostStation::ipv4) follow
 * the same convention: a plain number. Use rd_be32()/wr_be32() only when
 * reading or writing an actual IP header.
 */
typedef struct __attribute__((packed)) {
    uint32_t source_ipv4;  /* 0x00 */
    uint16_t source_port;  /* 0x04 */
    uint32_t dest_ipv4;    /* 0x06 */
    uint16_t dest_port;    /* 0x0A */
    uint32_t protocol;    /* 0x0C */
} RyuLdnProxyInfo; /* 16 bytes */

typedef struct __attribute__((packed)) {
    RyuLdnProxyInfo info;
    uint32_t data_length;
} RyuLdnProxyDataHeader; /* 20 bytes */

typedef struct __attribute__((packed)) {
    uint8_t requester;
    uint8_t id;
} RyuLdnPingMessage;

typedef struct __attribute__((packed)) {
    RyuLdnSecurityConfig security_config;
    RyuLdnUserConfig user_config;
    uint32_t local_communication_version;
    uint32_t option_unknown;
    uint32_t padding; /* 0x7C - keeps NetworkInfo 8-byte aligned */
    RyuLdnNetworkInfo network_info;
} RyuLdnConnectRequest; /* 0x500 */

/* Static assertions on the wire layout. */
_Static_assert(sizeof(RyuLdnHeader) == RYULDN_HEADER_SIZE, "LdnHeader must be 12 bytes");
_Static_assert(sizeof(RyuLdnNodeInfo) == 0x40, "NodeInfo must be 0x40");
_Static_assert(sizeof(RyuLdnNetworkInfo) == 0x480, "NetworkInfo must be 0x480");
_Static_assert(sizeof(RyuLdnConnectRequest) == 0x500, "ConnectRequest must be 0x500");
_Static_assert(sizeof(RyuLdnInitializeMessage) == 22, "InitializeMessage must be 22");
_Static_assert(sizeof(RyuLdnProxyDataHeader) == 20, "ProxyDataHeader must be 20");
_Static_assert(sizeof(RyuLdnNetworkConfig) == 0x20, "NetworkConfig must be 0x20");
_Static_assert(sizeof(RyuLdnSecurityConfig) == 0x44, "SecurityConfig must be 0x44");
_Static_assert(sizeof(RyuLdnCreateAccessPointRequest) == 0xBC, "CAP request must be 0xBC");

/* ---------------------------------------------------------------- */
/* Server-side API                                                  */
/* ---------------------------------------------------------------- */

typedef struct RyuLdnSession RyuLdnSession;
typedef struct RyuLdnServer RyuLdnServer;

/* Which emulator protocol this server byte-stream belongs to. */
typedef enum {
    TRANSPORT_RYULDN = 0, /* Ryubing / Ryujinx: LRdn over TCP   */
    TRANSPORT_ROOM,       /* Eden / yuzu lineage: Room over UDP */
} TransportKind;

/*
 * Per-connection callbacks (see main.c).
 *
 * Handshake, matching Ryubing/LdnServer's actual behaviour:
 *
 *   1. client -> Passphrase (1)
 *   2. client -> Initialize (0)
 *   3. server -> Initialize (0)      <-- assigns the guest a session id + MAC;
 *                                        the guest cannot proceed without them
 *   4. client -> CreateAccessPoint (2) | Connect (13)
 *   5. server -> ProxyConfig (17) + Connected (15)   [+ ExternalProxy* if asked]
 *   6. client -> Ping (254) <-> server -> Ping, forever
 *
 * Note the official RyuLdn protocol document shows ProxyConfig/Connected on
 * step 2; the C# server actually sends them from HostedGame.Connect() on
 * step 4/5. Ryubing is derived from that server, so we follow it.
 */
typedef struct {
    /* Step 3 done: `session_id` and `mac` have been assigned. */
    void (*on_initialized)(RyuLdnSession *s, const uint8_t session_id[16],
                           const uint8_t mac[6], void *user);
    /* Step 5: the guest's network is configured; send Connected now. */
    void (*on_connected)(RyuLdnSession *s, void *user);
    /* A guest created/joined a network (payload = CreateAccessPointRequest). */
    void (*on_access_point)(RyuLdnSession *s, const uint8_t *payload, size_t len,
                            bool is_private, void *user);
    void (*on_connect_request)(RyuLdnSession *s, const uint8_t *payload, size_t len,
                               void *user);
    void (*on_scan)(RyuLdnSession *s, const uint8_t *payload, size_t len, void *user);
    void (*on_disconnected)(RyuLdnSession *s, void *user);
    /* A guest (host) opened a proxy pipe; src_ip/port identify the peer. */
    void (*on_proxy_connect)(RyuLdnSession *s, RyuLdnProxyInfo info, void *user);
    void (*on_proxy_data)(RyuLdnSession *s, RyuLdnProxyInfo info, const uint8_t *data,
                          size_t len, void *user);
    void (*on_proxy_disconnect)(RyuLdnSession *s, RyuLdnProxyInfo info, void *user);
    void (*on_set_accept_policy)(RyuLdnSession *s, uint8_t policy, void *user);
    void (*on_set_advertise_data)(RyuLdnSession *s, const uint8_t *data, size_t len,
                                  void *user);
} RyuLdnHandlers;

RyuLdnServer *ryuldn_server_create(const char *bind_addr, uint16_t port,
                                   const RyuLdnHandlers *handlers, void *user);
void ryuldn_server_destroy(RyuLdnServer *server);

/* Pump the server: accept new connections, read/write sessions. */
void ryuldn_server_poll(RyuLdnServer *server, int timeout_ms);

/* ---------------------------------------------------------------- */
/* Outgoing packets                                                 */
/* ---------------------------------------------------------------- */

/*
 * Step 3 of the handshake: the guest learns its server-assigned session id and
 * MAC address. Both are zero on a first contact, in which case we mint them.
 */
void ryuldn_send_initialize(RyuLdnSession *session, const uint8_t session_id[16],
                            const uint8_t mac[6]);
void ryuldn_send_proxy_config(RyuLdnSession *session, RyuLdnProxyConfig cfg);
void ryuldn_send_sync_network(RyuLdnSession *session, const RyuLdnNetworkInfo *info);
void ryuldn_send_connected(RyuLdnSession *session, const RyuLdnNetworkInfo *info);
void ryuldn_send_scan_reply_end(RyuLdnSession *session);
void ryuldn_send_reject_reply(RyuLdnSession *session);
void ryuldn_send_proxy_connect_reply(RyuLdnSession *session, RyuLdnProxyInfo info);
void ryuldn_send_proxy_data(RyuLdnSession *session, RyuLdnProxyInfo info,
                            const uint8_t *data, size_t len);
void ryuldn_send_network_error(RyuLdnSession *session, uint32_t error_code);
void ryuldn_send_ping(RyuLdnSession *session, uint8_t requester, uint8_t id);

/*
 * Deliberately absent, because p0 never needs them and a declaration nothing
 * defines is worse than no declaration at all - it advertises an API that fails
 * only at link time, when the first person to use it has already written the
 * caller:
 *
 *   ryuldn_send_scan_reply()      the bridge hosts; it has no *other* network to
 *                                 report, so on_scan() sends only the end
 *                                 marker. See on_scan() in main.c.
 *   ryuldn_send_proxy_connect()   the bridge never initiates a proxy
 *   ryuldn_send_proxy_disconnect()  connection: it relays the console's own
 *                                 802.11 link, so there is no per-station proxy
 *                                 connection to open or tear down. A station
 *                                 leaving is told to the guest with
 *                                 ryuldn_send_sync_network().
 *
 * Each is three lines over send_packet() if p1 ever needs it.
 */

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

void ryuldn_header_init(RyuLdnHeader *h, uint8_t type, int32_t data_size);
bool ryuldn_header_ok(const RyuLdnHeader *h);
/* Node bookkeeping. */
/*
 * Everything the guest's game told us when it created its LDN network.
 * All of it comes from the guest's own CreateNetwork call - no lookup table.
 */
typedef struct {
    RyuLdnSecurityConfig security;
    RyuLdnNetworkConfig network;
    RyuLdnUserConfig user;
    uint16_t advertise_data_size;
    uint8_t advertise_data[384];
} RyuLdnGuestGameSettings;

const RyuLdnGuestGameSettings *ryuldn_session_guest_settings(const RyuLdnSession *session);

/* Build an empty NetworkInfo of the right shape. */
void ryuldn_network_info_init(RyuLdnNetworkInfo *info);

#endif /* SWITCH_LDN_RYULDN_H */
