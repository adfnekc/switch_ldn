# Hardware bring-up checklist

Everything up to and including stage 4 has been done and tested without a radio.
This is what remains, in the order it has to be attempted. Each stage says what
to look for and, more usefully, **what a failure looks like** — because most of
these failures are quiet.

Prerequisites, all of which you must have before stage 1:

- **a real Linux machine, not WSL2, not a container.** See the box below; this
  is the first thing to rule out because everything else is wasted effort if it
  fails.
- a `RTL8812AU`. The aircrack-ng out-of-tree driver is what this checklist
  assumes; the mainline `rtw88_8812au` module may be enough and is worth trying
  first (see below).
- root on the same machine
- a real Switch **with local wireless play** in a supported game
- `prod.keys` from that same console (the bridge needs `--prodkeys`; nothing
  else about the console is required, and it does not need to be modified)
- the emulator, Ryubing first — it needs no patch and exercises the RyuLdn
  path that has the least moving parts

### Rule out WSL2 / a container first

A USB adapter passed through to WSL2 **does** show up in `lsusb`, and that is as
far as it goes:

```console
$ lsusb | grep 8812
Bus 001 Device 002: ID 0bda:8812 Realtek ... RTL8812AU
$ ip -brief link
lo  UNKNOWN
eth0 UP            # no wlan at all
$ cat /sys/bus/usb/devices/1-1:1.0/uevent | grep MODALIAS
MODALIAS=usb:v0BDAp8812d0000d...   # correct, but nothing is bound to it
```

`/sys/bus/usb/devices/1-1:1.0/driver` does not exist, so no driver owns the
interface. Two things then block you:

1. **The out-of-tree driver cannot be built.** WSL2's headers package ships only
   `include/`: `/lib/modules/$(uname -r)/build` has no `Makefile`, no
   `Module.symvers` and no `scripts/`, all of which an out-of-tree module build
   needs.
2. **`iw`/`hostapd`/`rfkill` are usually absent**, and installing them needs
   root you may not have.

If the kernel already ships a driver for your chip, `modprobe` may be enough —
`rtw88_8812au` is in mainline and claims `usb:v0BDAp8812`, so check
`modinfo -F alias` against `/sys/.../uevent`'s `MODALIAS` before assuming you
need the out-of-tree one. But monitor-mode *injection* from WSL2 is unproven,
and WSL2's networking is NATed, so treat WSL2 as a dead end for stage 4
regardless: it will cost time and cannot answer the question.

`make console-sim` needs none of this and still works under WSL2 — it is the
one hardware-adjacent thing that does.

## Stage 0 — software sanity (no hardware needed)

```bash
make clean && make && make test && make check && make interop
```

All five must pass. `make test` and `make interop` deliberately stub out the
radio, so a green stage 0 tells you nothing about the NIC. It only means a later
failure is the radio, not this code.

## Stage 1 — probe the NIC

```bash
sudo IFACE=wlan0 CHANNEL=1 scripts/setup-ap.sh selfcheck
```

This answers the three hardware risks in one command and decides which
architecture is even possible.

**What you should see, in order:**

| Output | Meaning |
|---|---|
| `iw dev` listing, `iw dev wlan0 info` mode + channel | the card is up |
| a `channels` list containing the channel you asked for | regulatory domain is not blocking it |
| `monitor VIF: OK` | **the whole two-interface design works** |
| `selfcheck wlan0 mode=...` / `freq=...` / `ifindex=N` from `switch_ldn` | the bridge can talk to the interface |

**Failure → what it means:**

| Symptom | Meaning | What to do |
|---|---|---|
| `monitor VIF: UNSUPPORTED` | the 8812AU driver cannot make a monitor VIF (aircrack-ng/rtl8812au #93, #376) | fall back to §3b in `DESIGN.md`: one monitor interface plus a userspace 802.11 MAC FSM. Do not continue past stage 2. |
| `NO CARRIER`, or no channels listed | the card is held by NetworkManager or rfkill | the script already stops NetworkManager and unblocks rfkill; check `rfkill list` |
| only 5 GHz channels listed with `country_code=US` | regulatory domain too restrictive for the channels LDN uses | `iw reg set US` is already tried; try a country code whose domain covers the channel |

A card that gets past `monitor VIF: OK` is viable. A card that fails it is not
worth debugging further on this bridge — `mt7610u`/`mt7612u`/`mt7921au` have
driver-native support and are strongly preferred.

## Stage 2 — bring up the interfaces and hostapd

```bash
sudo IFACE=wlan0 CHANNEL=1 scripts/setup-ap.sh up
cp config/ldn-ap.conf /etc/hostapd/ldn-ap.conf
$EDITOR /etc/hostapd/ldn-ap.conf     # set interface= and channel=
hostapd /etc/hostapd/ldn-ap.conf &
```

`interface=` must match the AP VIF the script created (default `wlan0_ap`), and
`channel=` must match `--channel` you will pass to the bridge and the VIFs.

**Verify before starting the bridge:**

```bash
iw dev                                    # wlan0_ap (type AP) and wlan0_mon (type monitor)
ip link show wlan0_ap                     # state UP
hostapd_cli status # or the hostapd log   # AP-ENABLED
```

If `wlan0_ap` is DOWN or hostapd never reaches `AP-ENABLED`, stop here — a bridge
started against a dead AP will log radio errors for every frame.

## Stage 3 — start the bridge, emulator only

With **no** console involved yet:

```bash
sudo ./switch_ldn --ap-iface wlan0_ap --mon-iface wlan0_mon \
    --channel 1 --prodkeys prod.keys
```

**Expected log, in order:**

1. `AP MAC 02:4a:57:53:44:01` — read off the AP VIF. Note it: a colliding BSSID
   is the one thing this reveals.
2. `bridge running: RyuLdn on 127.0.0.1:30456, Room on 127.0.0.1:24872, ...`
3. Nothing else. **No** advertisement yet — the LDN host only exists once the
   emulator's game creates a network.

Then in Ryubing: `Multiplayer → LDN → Mode: RyuLDN`, server `127.0.0.1:30456`,
and start a game that supports local wireless.

**Expected:** `public network live for real consoles: title=01006f8...` followed
by repeated `host_tick` activity. That line is the milestone: the LDN network
exists, and the advertisement is now being emitted every 100 ms.

**If it does not appear**, the log already says why — see
[USAGE.md](../USAGE.md) under 什么时候会静默失败. `ERROR ... because the LDN crypto
passphrase never arrived` is the RyuLdn-side equivalent of the Eden patch
problem, and `station joined:` never appearing means no console ever
authenticated.

## Stage 4 — action-frame injection, before any console

This is the first genuinely unvalidated step, and it is worth proving alone:

watch the log at debug level while the emulator hosts a network, and confirm the
advertisements are actually going out:

```bash
sudo ./switch_ldn --ap-iface wlan0_ap --mon-iface wlan0_mon \
    --channel 1 --prodkeys prod.keys -v
```

You want to see the advertisement cadence. Cross-check on the air with
`airodump-ng wlan0_mon` — an LDN action frame appears as a vendor-specific
action frame on the channel. **If nothing goes out, nothing downstream can
work**, and this is the first thing to fix.

A second, independent check that needs no console: `tcpdump -i wlan0_mon -e`
should show the frames. If `-i wlan0_mon` only (and not `-i wlan0_ap`) shows
them, injection is working and the split is correct.

## Stage 5 — the console joins

Switch on the console, start **the same game's** local wireless mode, and look
for the room.

**Expected log, in order:**

1. `station joined: xx:xx:... slot=1 ip=169.254.1.1` — the LDN authentication
   succeeded. This is the real milestone: the passphrase, the title id and the
   advertisement all matched.
2. `sent auth success to station 1` at debug level.
3. `SyncNetwork -> RyuLdn guest (N stations)` and/or
   `IdLdnPacket{Connect} -> room member` — the emulator learned about the console.

**Then play.** Both directions of game traffic are implemented
(`ProxyData` for RyuLdn, `IdProxyPacket` for Room), so movement, sync and
voice should all traverse. If they do not, the log will now name what was
dropped rather than staying quiet — see `USAGE.md`.

## Failure diagnosis, in log order

| What you see | Where it failed | Next step |
|---|---|---|
| nothing at all after `bridge running` | stage 2/3: the emulator never reached the bridge | check the port and that the emulator is in the right mode |
| `station joined:` never appears | the console cannot decrypt or authenticate | see stage 5 gates below |
| `station joined:` appears but the emulator never learns | the notification path | should not happen any more; it did before `HostEvent` carried an identity snapshot |
| traffic goes emulator→console but not back | stage 5, Room transport | the uplink is `room_send_proxy_packet()`; check the log for `radio->room` at debug level |
| `room: IdProxyPacket payload is not a zstd frame` | stage 5, downlink | Eden compressed it and the relay failed to decompress — the payload is not a valid zstd frame |

### The console cannot join

Three gates decide who can even see the room, and only the last one is ours —
see [docs/ROOM_VISIBILITY.md](ROOM_VISIBILITY.md) for the full derivation:

1. **decryption** — any console with a valid `prod.keys` can decrypt any game's
   advertisement, so this does not filter.
2. **the game's scan filter** — the game filters on the plaintext title id. If
   the room does not appear in the list at all, this is the cause: the title id
   in the guest's `CreateNetwork` does not match the game you are running.
3. **joining** — needs the passphrase. If the room *is* listed but joining dies,
   this is the cause.

The bridge's own backstop is `host_handle_frame()`: an authentication request
whose session info (title id + scene id) does not match ours is rejected as
malformed (status 2), so a wrong-game console fails loudly rather than hanging.

## Notes on the known risks

- **Channel mismatch.** The guest's `CreateNetwork` can ask for a channel the
  AP was not started on. The bridge logs a warning and does **not** change the
  live radio. Start the bridge on the channel the game uses — set the same
  `--channel`, hostapd `channel=`, and VIF channel.
- **A second console.** `max_num_sta=8` in the hostapd template matches
  `LDN_NODE_MAX`. Two real consoles plus the emulator is the interesting case
  and is what stage 5's `slot=2` would show.
- **Tearing down.** `sudo IFACE=wlan0 ./scripts/setup-ap.sh down` removes both
  VIFs and restarts NetworkManager.
