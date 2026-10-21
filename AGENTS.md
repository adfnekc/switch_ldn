# Agent notes

Conventions for anyone (human or agent) working in this repo.

## Search discipline
- Do NOT use `find`/`ls -R` for source discovery in this repo — use `rg` (ripgrep).
- Use `rg -n <pattern> src tests` or `rg --files -g '*.c'`.

## Documentation map

| Topic | Authority |
|---|---|
| What this is, compatibility, build, run | `README.md` |
| Operating scenarios, hardware, failure modes (Chinese) | `USAGE.md` |
| Architecture, protocol internals, test inventory, open questions | `DESIGN.md` |
| Why consoles see a room but only some can join | `docs/ROOM_VISIBILITY.md` |
| The Eden passphrase patch | `docs/EDEN_PATCH.md` |
| Which emulator sources the interop tests use | `docs/EMULATOR_SOURCES.md` |
| Hardware bring-up, stage by stage | `docs/HARDWARE_CHECKLIST.md` |
| The source-based interop peers | `tests/interop/README.md` |

If a topic is described in more than one place, the table above decides. Do not
add a second copy of the build or run commands — that is exactly how they drifted
out of date before (`DESIGN.md` used to still pass `--title-id`, an option that
had been removed).

## Never drop data or a failure silently

This is the rule that generates most bugs here, so it is worth stating plainly:

- If a build/encode step can fail, check its status. `pk_*` in `src/room.c` sets
  `ok=false` instead of reporting, so an unchecked caller sends truncated data.
- A rejection must reach the peer. Dropping it leaves the emulator spinning on a
  spinner, which is indistinguishable from a silent success.
- Log at `LOG_W`/`LOG_E`, not `LOG_T`: the default level is `LOG_INFO`, so
  `LOG_T` is invisible unless the operator already knows to look for it.
- Never invent a protocol constant you have not confirmed (an error code, an
  enum value). A wrong constant makes the peer misreport, which is worse than a
  visible timeout. `NetworkError` has only two confirmed codes so far.
- Values that look like one thing but are another are the recurring trap.
  `Domain::INET` is 1 and `Protocol::UDP` is 4 — **not** the IP header's 17.
  `Network::MaxMessageSize` (500) is a chat-message limit, not a datagram limit.
  `non-0` checks on an already-cleared slot are another.

## No per-game tables

Passphrase, title id, channel, player limit and versions come from the emulator's
own `CreateNetwork` / `IdSetGameInfo`. There is no table, and `make check` guards
the removed `--passphrase-hex`/`--title-id`/`--dump-adv`/`--only` flags. A
per-game lookup would only be a second source of truth that can disagree.

## Testing

- `make test` is 12 suites, all socket-level, no radio hardware. `make interop`
  drives the bridge (radio stubbed) against source-based emulator peers, and
  `make console-sim` drives the **real** binary with `--radio-socket` against a
  fake console — see `tests/interop/`. All three run in CI.
- Add a test for every fix. Several bugs survived a long time because the test
  asserted something adjacent (counting packets instead of decoding the field,
  passing the same MAC twice so both a bug and its fix would pass).
- Interop cannot cover the console→emulator direction: `radio` is stubbed in
  `tests/bridge_harness.c`, so `radio_rx()` never fires. `make console-sim`
  covers it by driving the real binary over a Unix datagram socket instead.
- Keep the tree warning-free under `-Wall -Wextra`.

## Build deps

`libssl-dev`, `libzstd-dev`, `libnl-3-dev` and `libnl-genl-3-dev`
(the last two for nl80211 management-frame injection).
