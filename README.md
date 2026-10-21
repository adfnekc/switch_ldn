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
make               # needs libssl-dev, libzstd-dev, libnl-3-dev, libnl-genl-3-dev
make test          # 9 suites, all socket-level, no hardware required
make check         # CLI smoke test
make interop       # real RyuLdn + Room peers against the bridge (no radio)
make console-sim   # a fake console against the real binary (no radio, no root)
```

These five commands are the whole verification surface; everything else in
these docs describes behaviour, not more build steps.

`interop` and `console-sim` are different things and neither subsumes the
other:

- `make interop` stubs the radio out and drives the bridge with source-based
  emulator peers. It **cannot** touch the console → bridge direction, because
  `radio_rx()` never fires.
- `make console-sim` drives the **real** binary with `--radio-socket`, a Unix
  datagram socket standing in for the radio, and runs a fake console through
  the whole chain: advertisement, independent key derivation, authentication,
  and Pia traffic all the way to a `ProxyData` on the emulator side. It needs
  neither root nor a wireless NIC.

The interop target builds `tests/bridge_harness` (the bridge with the radio
stubbed out) and drives it with two source-based peers: a RyuLdn peer that
replays a real Ryubing/Ryujinx handshake, and an Eden `Room` peer built from
Eden's own `packet.cpp`. Both peers are plain source, no prebuilt binaries. See
[tests/interop/README.md](tests/interop/README.md) for the fake console, and
[DESIGN.md](DESIGN.md#open-questions) for what none of this covers.

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

Everything that does not need hardware is done, including both directions of
game traffic (see `room_send_proxy_packet()` for the Room uplink and
`deliver_from_guest()` for the downlink). In order:

1. **Probe the NIC** — `scripts/setup-ap.sh selfcheck`. Answers the three
   hardware risks in one shot: virtual-interface concurrency, regulatory domain,
   USB autosuspend.
2. **Prove action-frame injection** — the 100 ms advertisement actually going
   out on channel 1/6/11. Watch the log; if nothing goes out, this is the first
   thing to fix.
3. **End-to-end handshake** — a console should reach "room found" and
   then either join or fail. The `ChallengeResponse` question is closed (see
   [DESIGN.md](DESIGN.md#why-no-challengeresponse-is-needed)), so a failure here now
   points at the passphrase or the radio.
4. **Confirm the relay on real traffic** — both directions are implemented and
   unit-tested, but only a real console can confirm the 802.11-to-RyuLdn/Room
   translation survives real game payloads.

Step 4 is "run it and look". Step 3 is the only one that can still surface an
unknown, and it is no longer a wire-format unknown.

## Where things are documented

| Topic | File |
|---|---|
| What this is, compatibility, build, run | `README.md` (this file) |
| Operating scenarios, hardware, failure modes (Chinese) | [USAGE.md](USAGE.md) |
| Architecture, protocol internals, test inventory, open questions | [DESIGN.md](DESIGN.md) |
| Why consoles see a room but only some can join | [docs/ROOM_VISIBILITY.md](docs/ROOM_VISIBILITY.md) |
| The Eden passphrase patch, and how to verify it | [docs/EDEN_PATCH.md](docs/EDEN_PATCH.md) |
| Which emulator sources the interop tests use, and why | [docs/EMULATOR_SOURCES.md](docs/EMULATOR_SOURCES.md) |
| Hardware bring-up, stage by stage | [docs/HARDWARE_CHECKLIST.md](docs/HARDWARE_CHECKLIST.md) |
| The source-based interop peers | [tests/interop/README.md](tests/interop/README.md) |
| Conventions for anyone (human or agent) working here | [AGENTS.md](AGENTS.md) |

If a topic is described in more than one of these files, the one in the table
is the authority and the others should point at it.


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
