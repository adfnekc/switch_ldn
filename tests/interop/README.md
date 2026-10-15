# Interop tests

Two targets, and they cover different halves of the system. Neither subsumes
the other, which is why both exist.

| Target | Direction it covers | How |
|---|---|---|
| `make interop` | emulator → bridge | harness with the radio stubbed, source-based emulator peers |
| `make console-sim` | **console → bridge** | the **real** binary over a Unix datagram socket standing in for the radio |

No hardware and no prebuilt binaries are involved: everything here is source
that the targets compile and run. Both run in CI.

## The emulator side — `make interop`

Builds three things and wires them together:

| Piece | Path | What it is |
|---|---|---|
| `build/bridge_harness` | `tests/bridge_harness.c` | The bridge with the radio stubbed out. It `#include`s `src/main.c` (renaming `main`) so it runs the *same* transports and LDN core as the real binary, minus `radio_open()` and the argument parser. Listens on RyuLdn TCP `30456` and Room UDP `24872`. |
| `tests/interop/ryu_peer.py` | Python | Replays a real Ryubing/Ryujinx client's handshake: `Passphrase` → `Initialize` → `Ping` → `CreateAccessPoint`, then reads the `ProxyConfig` and `NetworkInfo` the bridge answers with. With `--expect-proxy` it also waits for and decodes the `ProxyData` a console sends. |
| `build/room_peer` | `tests/interop/room/room_peer.cpp` | Eden/yuzu `Room` member. It is compiled against Eden's own `packet.cpp`/`packet.h` (copied from upstream, the only edit being the `#include` path), so the bytes on the wire are the bytes Eden would send. |

The interop target requires the RyuLdn peer to see `createAccessPoint` and the
Room peer to reach `IdJoinSuccess`; either failing fails `make interop`.

## RyuLdn peer (`ryu_peer.py`)

Plain TCP against `127.0.0.1:30456`. The frame layout mirrors the C#
`StructLayout` types in Ryubing/Ryujinx (magic `RLDN`, version, type, length),
not a hand-simplified version.

Expected transcript:

```
>>> type=1 Passphrase                   140 bytes
>>> type=0 Initialize                    34 bytes
<<< type=0 data=22 bytes                  (session id + locally-administered MAC)
>>> type=254 Ping                        14 bytes
<<< type=254 data=2 bytes
>>> type=2 CreateAccessPoint            200 bytes
<<< type=17 data=8 bytes                 (ProxyConfig)
<<< type=15 data=1152 bytes              (NetworkInfo)
```

## Room peer (`room_peer.cpp`)

Plain UDP against `127.0.0.1:24872`, so no ENet dependency. It sends the exact
packet sequence `RoomMember::RoomMemberImpl` sends:

1. `IdJoinRequest` — nickname string, preferred fake IP (`0xff,0xff,0xff,0xff`),
   network version `u32`, room password string, token string.
2. `IdSetGameInfo` — game name string, **game id `u64`**, version string.
3. `IdProxyPacket` — four endpoint fields plus the payload.
4. `IdLdnPacket{Scan}` — scan request with the passphrase appended as one more
   length-prefixed blob (the `patches/eden-room-passphrase.patch` extension;
   stock Eden simply sends nothing extra and the trailing `passphrase_len`
   stays `0`).

Expected transcript:

```
[PASS] join.success - reply id=2 (want 2)
[PASS] game_info.send - name='Pokemon Scarlet' id=01006F8002320000
[PASS] proxy_packet.send - 7-byte payload, zstd-compressed
[PASS] ldn_scan.send - scan + 15-byte passphrase
```

The `proxy_packet` stage is the one that matters for the console→emulator
direction: the peer compresses the payload with zstd exactly as
`ProxySocket::SendPacket` does, and the bridge has to decompress it before the
bytes could ever reach a console on the air. Sending it plaintext makes the
bridge log `IdProxyPacket payload is not a zstd frame`, which is how you can
tell the relay path is actually being exercised.

## `prod.keys`

`tests/interop/prod.keys` is **synthetic**. The emulator leg never touches the
LDN console crypto (that only guards the 802.11 leg against a real Switch), so
any 16-byte values work; the harness only needs the file to parse.

The Room transport's uplink (`room_send_proxy_packet`) and its zstd round-trip
have no peer here; they are covered by `tests/test_room_wire.c` instead.

## The console side — `make console-sim`

```
make console-sim
```

`tests/bridge_harness.c` stubs the radio out, so `radio_rx()` never fires and
nothing in `make interop` touches the console → bridge direction. This target
closes that gap by driving the **real binary** with

```
--radio-socket <path>
```

a bound Unix datagram socket (mode 0600) that stands in for both raw sockets.
It needs neither root nor a wireless NIC, so it runs in CI.

| Piece | Path | What it does |
|---|---|---|
| `tests/interop/ryu_peer.py --hold` | Python | Creates the network, then waits for the console's traffic. |
| `tests/interop/fake_console.py` | Python | Plays a real console against that socket. |

The fake console is the first client here that shares **no code** with the
bridge: frame layouts are transcribed from `src/ldn.c`, and
`prodkeys_derive_key()` / `ldn_adv_key()` are re-implemented against
`openssl`. That independence is the point — it caught an advertisement whose
SHA-256 did not cover the advertise data, which every existing test missed.

Expected stages:

```
advertisement received / carries a plaintext session_info / title id matches
advertisement decrypts with a key we derived ourselves
decrypted payload hashes to the advertised SHA-256
AuthenticationRequest sent
AuthenticationResponse status is SUCCESS / marked as a response / echoes our session_info
Pia frame sent upstream as a data frame
ProxyData received from a real console / payload is intact
```

## What interop cannot cover

`radio` is stubbed in `tests/bridge_harness.c`, so no 802.11 frames exist and
`radio_rx()` never fires — that direction is what `make console-sim` is for.
`console-sim` in turn uses `ryu_peer.py`, a handshake peer rather than a full
client: it reads `ProxyData` and checks the ports and payload, but a real
Ryubing instance may treat the `NetworkInfo` in `SyncNetwork` differently. See
[DESIGN.md](../../DESIGN.md#open-questions) for the closed list of things both
targets still cannot show.
