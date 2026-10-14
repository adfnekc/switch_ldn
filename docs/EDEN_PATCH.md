# Forwarding the LDN passphrase through the Room protocol

## Why a patch is needed at all

`Network::LDNPacket` (Eden's Room-protocol packet for LAN traffic) has no field
for the LDN crypto passphrase, and `LANDiscovery::CreateNetwork()` — the function
a game calls to **host** a local-wireless network — reads the passphrase out of
`SecurityConfig` and then throws it away:

```cpp
network_info.ldn.security_mode = security_config.security_mode;
// ... no passphrase stored anywhere
```

Without that passphrase the bridge cannot derive the AES key for the 802.11 leg,
so it cannot build the advertisement frames a real console scans for. RyuLdn
does not have this problem: Ryubing's `LdnServer` forwards the whole
`SecurityConfig` alongside `CreateAccessPoint`, so the passphrase arrives for
free. Only the Room transport needs help.

## What the patch changes

`patches/eden-room-passphrase.patch` touches four files, all additive:

| File | Change |
|---|---|
| `src/core/hle/service/ldn/lan_discovery.h` | Adds `std::vector<u8> current_passphrase;` to `LANDiscovery`. |
| `src/core/hle/service/ldn/lan_discovery.cpp` | `CreateNetwork()` now stores the game's passphrase instead of dropping it; `SendBroadcast()` attaches it to the LDN packet it hands to the room member. |
| `src/network/room_member.h` | Adds `std::vector<u8> passphrase;` to `LDNPacket`. |
| `src/network/room_member.cpp` | `SendLdnPacket()` writes it as one more length-prefixed blob after `data`. |

## Why it is wire-compatible

The passphrase is appended **after** `data`, which is the last field stock Eden
reads. A stock parser stops at `data` and never looks at the trailing bytes, so:

- a patched Eden talking to a patched Eden exchanges the passphrase,
- a patched Eden talking to a stock Eden simply sends an extra blob the stock
  side ignores,
- and the bridge accepts both (`passphrase_len` stays `0` for stock peers).

That last property is what makes this a safe addition rather than a fork of the
protocol.

## Applying it

By hand:

```bash
git -C /path/to/eden apply /path/to/switch_ldn/patches/eden-room-passphrase.patch
```

Note the **absolute** patch path: `git -C <checkout>` resolves relative file
arguments against `<checkout>`, not against your shell's cwd, so a relative
path like `patches/...` will fail with *can't open patch*.

Or verify it applies without touching anything:

```bash
scripts/build_eden.sh /path/to/eden
```

`scripts/build_eden.sh` needs no network and no build toolchain — it only runs
`git apply --check` (a textual dry run). It exits 0 whether the patch applies
cleanly to a fresh tree or is already applied, 1 on a genuine base mismatch, and
2 on a usage error. `--check-only` asserts a *fresh* apply.

Tested base: Eden commit `218c670` *(hle: constexpr handler dispatch maps,
introduce version gating, #4480)*, the tree `tests/interop/room/packet.cpp` was
copied from.

If Eden has moved on, the targets to regenerate against are
`src/core/hle/service/ldn/lan_discovery.{cpp,h}` and
`src/network/room_member.{cpp,h}`.
