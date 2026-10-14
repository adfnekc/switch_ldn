# switch_ldn

Bridge **real** Nintendo Switch consoles to the Ryujinx and yuzu emulator
families using the Switch's own local wireless (LDN) protocol.

```
 ┌────────────────────┐  802.11 LDN   ┌──────────────────────────────┐
 │  real Switch (D3)  │ ◄──────────►  │  RTL8812AU + switch_ldn      │
 └────────────────────┘   host role   │  hostapd (AP) + radio/host.c │
                                     └──────────────────────────────┘
                                              │ LDN core (shared)
                          ┌──────────────────┴──────────────────┐
                          ▼                                     ▼
                  ┌───────────────┐                     ┌───────────────┐
                  │ RyuLdn (TCP)  │                     │ Room (UDP)    │
                  │ Ryubing       │                     │ Eden/yuzu     │
                  │ Ryujinx       │                     │ Citron        │
                  └───────────────┘                     └───────────────┘
```

> **状态：p0（模拟器开房 → 真机加入）已完整实现，两套协议同时监听。硬件尚未实测。**
> p1（模拟器加入真机房间）明确不支持，见 [Scope](#scope)。

## Compatibility

Two transports, one LDN core, both listening at the same time — switching
emulator needs no reconfiguration.

| Emulator family | Protocol | Port | Status |
|---|---|---|---|
| **Ryubing** (Ryujinx fork) | RyuLdn over TCP | `30456` | ✅ |
| **Ryujinx** (pre-2024) | RyuLdn over TCP | `30456` | ✅ |
| **Eden** (yuzu lineage) | Room over UDP | `24872` | ✅ |
| **Citron / Sudachi / yuzu** | Room over UDP | `24872` | ✅ |

### Ryubing / Ryujinx

`Multiplayer → LDN → Mode: RyuLDN`, server `127.0.0.1:30456`. The game's own
`CreateNetwork` call is forwarded verbatim, so nothing needs configuring.

### Eden / yuzu lineage

`Multiplayer → Direct Connect → 127.0.0.1:24872`.

Stock Eden **drops the LDN crypto passphrase it receives**:
`LANDiscovery::CreateNetwork()` keeps `security_config.security_mode` and never
reads the passphrase. Without it the bridge cannot derive the AES key and no
console can join.

`patches/eden-room-passphrase.patch` restores it. It appends the passphrase
after the `data` field of `IdLdnPacket`, which keeps the wire format
backward-compatible in both directions:

- the Room server relays datagrams verbatim, so the extra bytes ride along;
- `HandleLdnPackets()` reads only the fields it knows and ignores trailing
  bytes, so unpatched peers are unaffected.

```bash
git -C eden apply < switch_ldn/patches/eden-room-passphrase.patch
```

After that, Eden needs no configuration either.

## Scope

| Mode | Supported | Notes |
|---|---|---|
| **p0** emulator hosts, real Switch joins | ✅ | Everything here |
| **p1** emulator joins a console-hosted network | ❌ | Refused; see below |

p1 would make the bridge an LDN **station**, which must answer the LDN v3+
authentication *challenge* — proof that the game was independently purchased on
that machine (device id, HMAC, undocumented P/Q material). As the **host** we
issue that challenge and can simply answer "success"; as a station we would have
to forge the proof. The RyuLdn `Connect` path answers
`NetworkError(ConnectionRejected)` rather than hanging.

## Why no per-game table

Neither transport needs one, and none is shipped:

- **RyuLdn** forwards the game's `CreateNetwork` verbatim, including the
  `SecurityConfig` holding the passphrase, plus the title id, the channel, the
  player limit and the local communication version.
- **Room** gets it from patched Eden, which sends it inside its own
  `IdLdnPacket`.

The bridge derives the title id, channel, passphrase and versions at the moment
the emulator's game creates its network.

## Build & test

```bash
make            # needs libssl-dev
make test       # 8 suites, all socket-level, no hardware required
make check      # CLI smoke test
make interop    # real RyuLdn + Room peers against the bridge (no radio)
```

The interop target builds `tests/bridge_harness` (the bridge with the radio
stubbed out) and drives it with two source-based peers: a RyuLdn peer that
replays a real Ryubing/Ryujinx handshake, and an Eden `Room` peer built from
Eden's own `packet.cpp`. Both peers are plain source, no prebuilt binaries. See
[tests/interop/README.md](tests/interop/README.md).

## Run

```bash
sudo IFACE=wlan0 CHANNEL=1 scripts/setup-ap.sh selfcheck   # probe the NIC
sudo IFACE=wlan0 CHANNEL=1 scripts/setup-ap.sh up
hostapd config/ldn-ap.conf &

sudo ./switch_ldn --ap-iface wlan0_ap --mon-iface wlan0_mon \
    --channel 1 --prodkeys prod.keys
```

`--prodkeys` is the only thing the bridge needs from you. See
[USAGE.md](USAGE.md) for scenarios, the passphrase question and failure modes.

## What is left

Everything that does not need hardware is done. In order:

1. **Probe the NIC** — `scripts/setup-ap.sh selfcheck`. Answers the three
   hardware risks in one shot: virtual-interface concurrency, regulatory domain,
   USB autosuspend.
2. **Prove action-frame injection** — the 100 ms advertisement actually going
   out on channel 1/6/11. Watch the log; if nothing goes out, this is the first
   thing to fix.
3. **End-to-end handshake** — a console should reach "room found" and
   then either join or fail. The `ChallengeResponse` question is closed (see
   below), so a failure here now points at the passphrase or the radio.
4. **Pia traffic** — the last leg: whether real game traffic survives the
   802.11-to-RyuLdn/Room translation.

Steps 1, 2 and 4 are "run it and look"; step 3 is the only one that can still
surface an unknown, and it is no longer a wire-format unknown.

### Why no `ChallengeResponse` is needed

Checked against kinnay/LDN, which is the only place the format is written down.
The station sends a `ChallengeRequest` inside its `AuthenticationRequest`, and
the host answers with a `ChallengeResponse` inside the
`AuthenticationResponse`. That is kinnay's *host* verifying a station, i.e. the
anti-piracy half.

Going the other way, the station's `_check_authentication_response()` only
looks at five things — the payload type, `local_communication_id`, `scene_id`,
`ssid`, `server_random`, `client_random` and `status_code`. It never decodes
the response's challenge, and `AuthenticationResponse.encode()` writes the
challenge only when it is non-`None`, so a host with the challenge disabled
emits exactly `platform + 0x83` zero bytes. That is what we send.

The two 16-byte `unk` / `unk_host` fields therefore never reach the wire in the
host-to-station direction, and there is nothing left to guess about them.

## Status

Builds clean under `-Wall -Wextra`; 8 test suites pass, plus `make interop`.

Validated without hardware: prod.keys parsing, key derivation, advertisement
frame construction, RyuLdn wire layout and handshake, Room wire layout and fake
IP allocation, adopting the guest's `CreateNetwork` settings, the station
watchdog, and refusing p1. A GitHub Actions workflow runs build + test + check +
interop on every push.

**Not yet validated** (needs the RTL8812AU and a real console): radio I/O,
action-frame injection, and the end-to-end handshake. The `ChallengeResponse`
question is resolved: a console never decodes a host's challenge response, so we
send none and nothing is left to guess (see "What is left" above).

See [docs/ROOM_VISIBILITY.md](docs/ROOM_VISIBILITY.md) for which consoles can
see the room and which can join.

The one thing documentation left open — how the 4-byte advertisement nonce
expands into AES-CTR's 16-byte counter block — has been resolved against
kinnay/LDN and locked in with reference vectors, so no packet capture is
required. See [DESIGN.md](DESIGN.md#the-aes-ctr-counter-block-resolved).

Both transports are also exercised against the emulators' own client code, not
just our own fixtures — see [docs/EMULATOR_SOURCES.md](docs/EMULATOR_SOURCES.md)
for which sources those are and why they were chosen.
