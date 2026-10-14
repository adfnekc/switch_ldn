# switch_ldn

Bridge **real** Nintendo Switch consoles to the Ryujinx emulator family using the
Switch's own local wireless (LDN) protocol.

## Scope

**p0 only.**

| Mode | Supported | Notes |
|---|---|---|
| **p0** emulator hosts, real Switch joins | ✅ | Everything in this repo |
| **p1** emulator joins a console-hosted network | ❌ | Actively refused, see `ryuldn.c` `RYULDN_CONNECT` |

p1 would make the bridge an LDN **station**, which must answer the LDN v3+
authentication *challenge* — proof that the game was independently purchased on
that machine (device id, HMAC, undocumented P/Q blob). No public documentation
of the P/Q encoding exists, so it is out of scope until p0 is proven end to end,
and it should start from a capture of two real consoles.

<p>Note the direction: as **host** the challenge runs the other way. A station
sends us a `ChallengeRequest` and is entitled to a `ChallengeResponse`, but the
station never decodes it — its `_check_authentication_response()` only checks
the payload type, network id, both randoms and the status code. We therefore
send `platform + 0x83` zero bytes and no challenge, which is exactly what a
kinnay host with `enable_challenge = false` emits. The undocumented P/Q blobs
never reach the wire in the host-to-station direction.</p>

```
 ┌──────────────────────┐  802.11 LDN   ┌──────────────────────────────┐
 │  real Switch (D3)    │ ◄──────────►  │  RTL8812AU + switch_ldn      │
 └──────────────────────┘   host role   │  hostapd (AP) + radio.c/host │
                                       └──────────────────────────────┘
                                               │ RyuLdn
                                               ▼
                                       ┌──────────────────────────────┐
                                       │  Ryubing guest          │
                                       └──────────────────────────────┘
```

## Adopting the game's settings (why there is no per-game table)

The passphrase is **not** extracted from game binaries. The emulator's game
calls `nn::ldn::CreateNetwork` with a `SecurityConfig` that contains it, Ryujinx
forwards that whole call to the LdnServer, and RyuLdn carries it verbatim:

```
game (Ryubing) --CreateNetwork--> Ryujinx HLE --RyuLdn CreateAccessPoint--> bridge
                                   SecurityConfig  →  passphrase
                                   NetworkConfig    →  title id, channel,
                                                       node_count_max,
                                                       local_comm_version
                                   UserConfig       →  username
```

`src/ryuldn.c` parses that packet (`RYULDN_CREATE_ACCESS_POINT`) and
`host_adopt_guest_settings()` (`src/host.c`) reconfigures the whole LDN host
from it - new SSID, new `server_random`, both AES keys re-derived, station table
reset. **One packet, no table, no reverse engineering.**

This is also why `local_communication_version` matches for free: it is the same
field the real console compares against.

Two things still require a lookup:

1. `--dump-adv` (building a frame with no emulator attached), and
2. a real console hosting the room - then the console chose its own passphrase
   and never transmitted it.

## Layout

```
src/room.c          Room protocol transport (Eden/yuzu lineage)
src/ryuldn.c        RyuLdn transport (Ryubing/Ryujinx)
src/host.c          the LDN host: advertisements, station table, auth
src/ldn.c           LDN wire format + AES-CTR
src/crypto.c        prod.keys + key derivation
src/radio.c         hostapd + AF_PACKET I/O, action-frame injection
```

## Compatibility: the emulator seam

Two transports sit on top of one LDN core, and everything below them
(`radio.c`, `host.c`, `ldn.c`, `crypto.c`) is emulator-agnostic, because 802.11
LDN does not know or care which emulator is on the other end.

| Emulator | Transport | Status |
|---|---|---|
| Ryubing (Ryujinx fork) | `src/ryuldn.c` — RyuLdn over TCP | ✅ |
| Ryujinx (pre-2024) | `src/ryuldn.c` — RyuLdn over TCP | ✅ |
| Eden | `src/room.c` — Room over UDP | ✅ |
| Citron / Sudachi / yuzu | `src/room.c` — Room over UDP | ✅ |

```
src/ryuldn.c  ─┐
               ├─→ Host / radio / ldn / crypto   (shared, unchanged)
src/room.c   ─┘
```

A user switching between Ryubing and Eden only has to point the emulator at the
right port; the bridge listens on both simultaneously.

Why: Ryubing descends from Ryujinx, which HLEs `nn::ldn` and forwards it to an
`LdnServer`. Eden descends from Yuzu, which instead implements a lobby service
(`CreateRoom`, `Browse`, `Join`, `SetPlayerInfo`) with its own UDP message
layout. Eden's docs say so directly: *"The only emulator that has this kind of
functionality is Ryujinx and its forks."*

### The RyuLdn handshake, as actually implemented by Ryubing's server

Worth getting exactly right, because the published protocol document's flow
diagram does not match the C# code:

```
client -> Passphrase (1)
client -> Initialize (0)        [all-zero id + MAC on first contact]
server -> Initialize (0)        assigns a session id AND a MAC. Mandatory:
                                the guest cannot build a network without them.
client -> CreateAccessPoint (2) carries SecurityConfig (passphrase),
                                NetworkConfig (title id, channel,
                                node_count_max, local_comm_version),
                                UserConfig, then the advertise data
server -> ProxyConfig (17)      the LDN subnet
server -> Connected (15)        the NetworkInfo the guest must publish
client -> Ping (254)  <->  server -> Ping (requester = 0, same id)
```

Two traps:

1. **`ProxyConfig`/`Connected` are *not* sent on `Initialize`.** In
   `Ryubing/LdnServer` they come out of `HostedGame.Connect()`, i.e. after the
   game has created or joined a network. Sending them early means sending a
   `NetworkInfo` for a network that does not exist yet.
2. **`ProxyInfo` fields are interleaved**: `{srcIp, srcPort, dstIp, dstPort,
   proto}`, not grouped by kind. It is `Pack = 1` and totals 16 bytes either
   way, so a size assertion cannot catch a mistake - and getting it wrong routes
   every game packet to the wrong address.

### Room protocol (Eden / yuzu lineage)

Reverse-engineered from Eden's `src/network/{room,room_member,packet}.cpp` and
`common/announce_multiplayer_room.h`. The reason this is cheaper than it looks
is that **the Room server is a dumb relay**:

```cpp
// Eden src/network/room.cpp, HandleLdnPacket
in_packet.IgnoreBytes(sizeof(u8));          // Message type
in_packet.IgnoreBytes(sizeof(u8));          // LAN packet type
in_packet.IgnoreBytes(sizeof(IPv4Address)); // Local IP
in_packet.Read(remote_ip);                  // Remote IP
in_packet.Read(broadcast);
// ... then forwards the whole packet verbatim to the member owning remote_ip
```

It reads 7 bytes of address, finds the member with that "fake IP" (`192.168.i.j`
handed out by `GenerateFakeIPAddress`), and forwards the packet unchanged. No
LDN parsing, no crypto, no game knowledge.

The LDN semantics ride in the payload, and they are **the same structs RyuLdn
uses**. Eden's `LANDiscovery` literally `memcpy`s them:

```cpp
// src/core/hle/service/ldn/lan_discovery.cpp
std::memcpy(&info, packet.data.data(), sizeof(NetworkInfo));
```

So the semantic gap is only the envelope, not the content:

| | RyuLdn | Room |
|---|---|---|
| Transport | TCP | ENet over UDP 24872 |
| Framing | `LdnHeader` + 22 packet ids | `u8 type` + big-endian scalars, length-prefixed strings |
| Session | `Initialize` + `CreateAccessPoint`/`Connect` | `IdJoinRequest` + `IdJoinSuccess` (5 bytes total) |
| Game data | `ProxyData` | `IdProxyPacket` |
| LDN view | `ScanReply`/`Connected`/`SyncNetwork` | `IdLdnPacket{Scan/ScanResp/Connect/SyncNetwork}` |
| Payload | `NetworkInfo` 0x480, `NodeInfo` 0x40 | **identical** |

Message layout (Eden's `Packet`: big-endian multi-byte, `std::string`/`vector` as
`u32 length` + bytes, `IPv4Address` as 4 raw bytes, `bool` as 1 byte):

```
IdJoinRequest   u8 type, string nickname, u8[4] fake_ip, u32 version,
                string password, string token
IdJoinSuccess   u8 type, u8[4] fake_ip                        (exactly 5 bytes)
IdRoomInformation  u8 type, string name, string description, u32 member_slots,
                u16 port, string preferred_game.name, string host_username,
                u32 num_members, then per member 8 fields (nickname, fake_ip,
                game name, u64 game id, game version, username, display_name,
                avatar_url)
IdProxyPacket   u8 type, u8 family, u8[4] ip, u16 port, u8 family, u8[4] ip,
                u16 port, u8 protocol, bool broadcast, vector data
IdLdnPacket     u8 type, u8 ldn_type, u8[4] local_ip, u8[4] remote_ip,
                bool broadcast, vector data
```

Eden has no generic error packet: each rejection has its own message
(`IdWrongPassword`, `IdVersionMismatch`, `IdRoomIsFull`, `IdNameCollision`,
`IdIpCollision`). `room_send_reject()` maps a reason onto one, because silently
dropping leaves the emulator spinning forever.

We use plain UDP instead of linking ENet: the bridge is a private relay, every
message is a single datagram, and Eden marks them reliable anyway. If ENet's
sequencing ever matters, linking `libenet` is a drop-in replacement for
`room_server_poll()`.

## Build & smoke test

```bash
make            # needs libssl-dev
make check      # builds a dummy prod.keys and one advertisement frame
```

## Running it

```bash
# 1. radios (root)
sudo IFACE=wlan0 CHANNEL=1 scripts/setup-ap.sh up
hostapd config/ldn-ap.conf &

# 2. verify the NIC can do what we need
scripts/setup-ap.sh selfcheck

# 3. bridge
sudo ./switch_ldn --ap-iface wlan0_ap --mon-iface wlan0_mon \
    --channel 1 --title-id 01001B300B9BE000 \
    --prodkeys prod.keys
```

Then in Ryubing:
`Multiplayer → Direct connect → 127.0.0.1 : 30456`

On the real Switch: start local wireless play in Diablo III. It should see the
bridge as a room.

## Tests

```
make test
```

| Test | Covers |
|---|---|
| `tests/test_wire.c` | RyuLdn struct sizes (12 / 0x40 / 0x480 / 0x500 / 0xBC), LDN payload sizes, channel encoding, session-info layout, AES-CTR round-trip, key derivation determinism, and `CreateAccessPointRequest` field offsets + passphrase extraction |
| `tests/test_p1_refused.c` | socket-level: a guest sending `Connect` (p1) gets `NetworkError(ConnectionRejected)` rather than silence |
| `tests/test_handshake.c` | socket-level: the RyuLdn handshake — `Initialize` must be answered with an `Initialize` carrying an assigned session id + MAC, and `Ping` with `{requester=0, id}`. Both were wrong before this existed. |
| `tests/test_room_wire.c` | socket-level: Room wire format — a hand-built `IdJoinRequest` decodes to a 5-byte `IdJoinSuccess`, fake IPs are allocated from `192.168.x.y` without collision, `IdLdnPacket{Scan}` and `IdProxyPacket` decode field-for-field, the trailing LDN passphrase is surfaced (or correctly absent), and `IdRoomInformation` re-walks to the right member count. |
| `tests/test_ctr_vectors.c` | The AES-CTR counter block, byte-for-byte, against vectors generated with PyCryptodome under `nonce || 0^12` (`tests/ctr_vectors.h`) |
| `tests/test_auth_frame.c` | The LDN authentication frame layout: field order, little-/big-endian choices and the no-truncation guarantee on the response payload |
| `tests/test_advert_nonce.c` | The 4-byte advertisement nonce: changes per emission, advances by exactly one, carries on wrap, survives a reconfigure |
| `tests/test_host_watchdog.c` | Station bookkeeping on join (`last_seen_ms` / `joined_ms`), that the default 30 s timeout is preserved, and that a timed-out station is evicted and produces a `HOST_EVENT_STATION_LEFT` |

Every expected byte string is transcribed from Eden's own encoders.

`make interop` is a separate, non-hardware end-to-end check: it runs the real
transports (radio stubbed) against a source-based RyuLdn peer and an Eden
`Room` peer. See [tests/interop/README.md](tests/interop/README.md).

## The AES-CTR counter block (resolved)

The wiki documents a 4-byte "nonce for the AES algorithm" at advertisement
payload offset `0x24` but never says how it expands into AES-CTR's 16-byte
counter block. This was the one thing that genuinely needed external evidence.

The reference is [kinnay/LDN](https://github.com/kinnay/LDN), a working
implementation that both scans for and *hosts* LDN networks. Its encoders do:

```python
aes = AES.new(key, AES.MODE_CTR, nonce=self.nonce)
```

and PyCryptodome builds the counter block as the nonce prefix followed by a
zero-initialised big-endian counter — `nonce || 0^12`. The increment spans the
whole 128-bit block, which is equivalent to incrementing only the low 12 bytes
for any realistic payload.

`tests/ctr_vectors.h` locks this in with four PyCryptodome-generated vectors,
and `tests/test_ctr_vectors.c` asserts our `aes128_ctr_xor()` reproduces them
byte for byte.

### While checking that, two real bugs turned up

1. **Authentication frames were being AES-CTR encrypted with an all-zero
   counter block.** kinnay only encrypts them for its internal "protocol 3"
   cipher suite, which pairs with AES-GCM advertisements; the AES-CTR path a
   real console expects sends them **in the clear**. The caller passing
   `data_key = NULL` was the only thing keeping it working. Removed.
2. **The parse buffer was `uint8_t buf[0x100]`**, which truncated a version-3
   request (0x4E + 0x364 = 942 bytes). Harmless only because the challenge is
   ignored; now sized to `LDN_AUTH_REQUEST_PAYLOAD`.

Also corrected: the authentication response payload is 0x84 bytes
(`platform` + 0x83 zero bytes), not 1 byte, and the network id at offset 0x0E
is little-endian — a big-endian copy makes a console read the wrong title id
and refuse the join. `tests/test_auth_frame.c` pins both.

## Open questions

Everything p0 needs to be proven on real hardware:

| # | Issue | Where |
|---|---|---|
| 1 | **RESOLVED** — the AES-CTR counter-block layout (`nonce \|\| 0^12`) was derived from kinnay/LDN and pinned byte-for-byte against PyCryptodome. No capture needed. | `tests/test_ctr_vectors.c` |
| 2 | **RESOLVED** — the data-frame counter block is the same `nonce \|\| 0^12` construction with the per-fragment nonce, covered by the same vectors. | `tests/test_ctr_vectors.c` |
| 3 | 802.11 association → LDN station wiring: currently hostapd/kernel owns the station table and `host.c` learns the MAC from the LDN auth frame. Fine for the first milestone. | `host.c`, `handle_assoc` |
| 6 | Channel changes requested by the guest are logged but not applied to a live radio (the guest decides the LDN channel; hostapd was started with `--channel`). Start the bridge on the channel the game uses. | `main.c`, `on_access_point` |
| 7 | Passphrase `0` from the guest: rejected outright (a hard error) because the fixed security level 1 requires one. Not tested against a real console. | `host.c`, `host_configure` |
| 4 | RTL8812AU virtual-interface fragility. Validate with `setup-ap.sh selfcheck`; fallback documented in §3b. | `scripts/setup-ap.sh` |
| 5 | Partial network/USER/paging logic. | `ryuldn.c` |

### §3b Fallback: no hostapd

If VIFs prove unreliable, drop hostapd and implement a full 802.11 MAC FSM on
one monitor interface (beacon, open auth, assoc, data, deauth). That is more
code (~800 lines, `mac80211 + nl80211`) but only one VIF. See
NintendoClients wiki, *Local Wireless Communication on PC*, and the kinnay/LDN
Python package which implements exactly this path.

## Status

Skeleton complete and building. Validated: prod.keys parsing, key derivation,
advertisement frame construction and AES-CTR.

Not yet validated (no hardware in the loop): actual radio I/O, action-frame
injection on the RTL8812AU, and the end-to-end handshake.

## Sources

- NintendoClients/wiki: `LDN-Protocol`, `LDN-Passphrases`,
  `Local-Wireless-Communication-on-PC`
- `RyuLdn Protocol` reference (ethiquema.github.io/ryu_ldn_nx)
- Ryubing/LdnServer (MIT) - `CreateAccessPointRequest` / `SecurityConfig` wire layout
- switchbrew: `LDN services`, title list
- `spacemeowx2/ldn_mitm`, `aircrack-ng/rtl8812au`
- `kinnay/LDN` (Python NL80211 reference implementation)
