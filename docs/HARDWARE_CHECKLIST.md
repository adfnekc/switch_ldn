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
  assumes. The mainline `rtw88_8812au` module is worth trying first, but it only
  exists from Linux 6.13, and its frame-injection support is not what stage 4
  needs, so plan on building the out-of-tree one.
- root on the same machine
- a real Switch **with local wireless play** in a supported game
- `prod.keys` from that same console (the bridge needs `--prodkeys`; nothing
  else about the console is required, and it does not need to be modified)
- the emulator, Ryubing first — it needs no patch and exercises the RyuLdn
  path that has the least moving parts

### Rule out WSL2 / a container first — one command

```console
$ dmesg | grep 'Direct firmware load'
[   100005.973177] faux_driver regulatory: Direct firmware load for regulatory.db failed with error -2
```

If that prints **anything**, stop: the kernel cannot read `/lib/firmware` in
this environment, and no Wi-Fi driver can work. Confirm by checking that the
file it complains about is actually on disk:

```console
$ ls -l /lib/firmware/regulatory.db
-rw-r--r-- 1 root root 6380 ... /lib/firmware/regulatory.db
```

The file is there and the kernel says ENOENT anyway. That is the whole test, and
it is worth running before anything else, because every symptom downstream
("modprobe printed nothing", "no wlanX", "device visible but no driver") is a
consequence of it and none of them point at the cause.

Why it happens: `request_firmware()` runs on a workqueue thread, which resolves
paths against the mount namespace of the *init* process rather than the
distro's. Under WSL2 the distro root is mounted after the kernel starts, so the
thread's view does not contain `/lib/firmware`. The usual escape hatch is the
userspace helper, and both halves of it are missing here:

- `CONFIG_FW_LOADER_USER_HELPER_FALLBACK` is not set, so `/sys/module/firmware_class/parameters/`
  contains only `path` - there is no `fallback` knob to turn on;
- and no udev is running (`/run/udev/control` absent, PID 1 is `init(Ubuntu)`),
  so nothing could answer the request even if it were made.

This is why the RTL8812AU gets so close and stops: `rtw88_8812au` loads, binds,
request the firmware, gets ENOENT, and unwinds with `probe ... failed with
error -22`. The `.zst` firmware that Ubuntu ships makes it look worse -
`CONFIG_FW_LOADER_COMPRESS_ZSTD` is absent from the WSL2 kernel too, so only
`.xz` would have been decompressed - but decompressing it by hand does not help
either, because of the namespace problem above.

A real Linux machine has `kthreadd`'s root equal to the real root, so the same
`modprobe` just works. That is the fix: bare metal, or a VM that boots its own
Linux kernel with the USB device passed through.

`make console-sim` needs none of this and still works under WSL2 — it is the one
hardware-adjacent thing that does.

### If it is WSL2: hand the adapter to a real VM

The cheapest way out of the firmware problem above is not a custom WSL2 kernel -
it is to let a guest that boots its own Linux kernel own the USB device. There,
`kthreadd`'s root is the real root, `request_firmware()` finds
`/lib/firmware/...` on the first try, and none of this section applies.

Use **VirtualBox** (with the Extension Pack, needed for USB 2.0+) or **VMware
Workstation**. **Do not use Hyper-V** - its USB "passthrough" is USB/IP again,
which is the arrangement that just failed.

1. Install a normal, **current** distro in the VM - Debian 13, Ubuntu 24.04 or
   similar. It must boot **systemd**, because udev is what serves firmware to
   the kernel on the fallback path. Do not pick RHEL/CentOS 7: see the box
   below, it cannot be made to work without porting the driver by hand.

   Do not expect the mainline driver yet. `rtw88_8812au` only exists from
   **Linux 6.13** onwards (the patches landed in late 2024), so every LTS up to
   Ubuntu 24.04 (6.8), Debian 12 (6.1) and Debian 13 (6.12) has to build the
   aircrack-ng driver. Check with
   `modinfo -F filename rtw88_8812au` before assuming otherwise.
2. VM settings -> USB -> enable the controller (try **xHCI / USB 3.0** first;
   EHCI passthrough is the flakier of the two) and add a filter for
   `0bda:8812` so the adapter attaches whenever it is plugged in.
3. Boot the guest and confirm the device is the guest's, not Windows':

   ```console
   $ lsusb | grep 8812
   Bus 001 Device 003: ID 0bda:8812 Realtek ... RTL8812AU
   ```

   If your kernel is 6.13 or newer, try the mainline module first - it costs one
   command:

   ```console
   $ sudo modprobe rtw88_8812au && ip -brief link
   ... wlan0 ...
   ```

   If no `wlan0` appears, `dmesg | grep -i rtw88` - and check the firmware is
   actually present and *uncompressed* (`ls /lib/firmware/rtw88/rtw8812a_fw.bin`).
   Debian and Ubuntu ship those as `.zst`; a kernel with
   `CONFIG_FW_LOADER_COMPRESS_ZSTD=y` handles that on its own, and if yours does
   not, `sudo zstd -d .../rtw8812a_fw.bin.zst -o .../rtw8812a_fw.bin` fixes it.

   Otherwise build the out-of-tree driver - this is the expected path on any
   LTS, and the one stage 4 needs anyway:

   ```console
   $ sudo apt install build-essential linux-headers-$(uname -r) git
   $ git clone --depth 1 -b v5.13.6 https://github.com/aircrack-ng/rtl8812au
   $ cd rtl8812au && make && sudo make install && sudo modprobe 88XXau
   $ ip -brief link            # wlan0
   ```

   (`make install` runs `depmod`; the module is named `88XXau`, not
   `rtl8812au`.) If the build fails, the error usually names a kernel API that
   moved - pick the oldest branch that knows your kernel rather than patching.
4. Then continue at **Stage 1** below.

#### Do not use a RHEL/CentOS 7 guest

Measured, not guessed. CentOS 7.6's `3.10.0-957.el7` kernel reports
`LINUX_VERSION_CODE` 3.10 but has **backported the 4.x cfg80211 API**, so no
upstream `rtl8812au` branch matches it:

| Branch | Result on 3.10.0-957 |
|---|---|
| `v5.6.4.2` (targets 5.x) | 31 errors: `IEEE80211_NUM_BANDS`, `sme_state`, `cfg80211_connect_bss`, ... |
| `v5.3.4` | 18 errors after renaming `IEEE80211_BAND_*` to `NL80211_BAND_*`: `sme_state`, `STATION_INFO_*`, `cfg80211_ibss_joined`/`roamed` signatures |
| `v4.3.21` (targets 3.x) | same 18-error family from the other direction |

The remaining work is not renaming: `wdev->sme_state` was **removed** in 4.x and
replaced by `wdev->conn`, so the connect/disconnect paths have to be rewritten,
and `STATION_INFO_*` became a `BIT(NL80211_STA_INFO_*)` bitmap. That is a port,
not a patch, on a platform nobody else runs.

For reference, the two build-step obstacles that are mechanical and do get
fixed this way: the Makefile's `-Wno-error=date-time` must be commented out
(gcc 4.8 rejects it, and the kernel adds `-Werror` when gcc is 4.8), and
`call_read_iter` is guarded on `< 4.11` but needs `>= 3.16` as well, since
RHEL's 3.10 has no `read_iter`.

Notes:

- WSL2 and VirtualBox/VMware can coexist, but WSL2 keeps the Windows hypervisor
  loaded, which pushes the VM onto a slower API and occasionally breaks USB
  passthrough. `wsl --shutdown` before starting the VM if the device will not
  attach.
- A VM's USB passthrough is much closer to bare metal than USB/IP, so the
  timing-sensitive part (stage 4's 100 ms injection, stage 5's 700 ms auth
  window) is answered more honestly here than it would be under WSL2.

## Stage 0 — software sanity (no hardware needed)

```bash
make clean && make && make test && make check && make interop
```

All five must pass. `make test` and `make interop` deliberately stub out the
radio, so a green stage 0 tells you nothing about the NIC. It only means a later
failure is the radio, not this code.

## Stage 0.5 — make the interface exist at all

The checklist used to assume a `wlanX` was already there. It often is not, and
the failure is quiet: `modprobe` reports success, no interface appears, and
nothing on the console says why. Always check `dmesg` at this point.

```bash
sudo modprobe rtw88_8812au        # mainline; claims usb:v0BDAp8812
ip -brief link                   # is there a wlanX now?
dmesg | tail -20                 # the only place the reason shows up
```

**The two failure modes seen in practice:**

| `dmesg` says | Meaning | Fix |
|---|---|---|
| `failed to load firmware` / `failed to setup chip efuse info` / `probe with driver rtw88_8812au failed with error -22` | the module loaded, but `/lib/firmware/rtw88/rtw8812a_fw.bin` is missing, so the probe fails and no netdev is created. `modprobe` itself returned success. | `sudo apt install linux-firmware-realtek`, then reload the module (`sudo modprobe -r rtw88_8812au && sudo modprobe rtw88_8812au`). Note that on Ubuntu `linux-firmware` alone is a 1.8 KB metapackage — the Realtek blobs are in `linux-firmware-realtek` (6 MB). |
| nothing about the adapter at all | the USB interface is present but no driver claimed it | `cat /sys/bus/usb/devices/*/uevent \| grep MODALIAS` and compare against `modinfo -F alias` for the driver you expect. `0bda:8812` is claimed by both `rtw88_8812au` (mainline) and the out-of-tree aircrack-ng driver; the two conflict, so only have one available. |

Which driver to aim for: try mainline `rtw88_8812au` first — it is already built
on most kernels, so it costs only a `modprobe`. The aircrack-ng out-of-tree
driver is the fallback when `rtw88`'s monitor/injection is not good enough, and
the checklist below assumes it.

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
| `selfcheck wlan0 mode=managed (2)` / `freq=...` / `ifindex=N` from `switch_ldn` | the bridge can talk to the interface |

`switch_ldn --selfcheck` exits nonzero for an interface that does not exist or
has no wireless extensions, so a script can branch on it instead of reading the
log.

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

## Stage 4 result (measured): no monitor VIF — use nl80211 mgmt_tx

The design assumed two VIFs: an AP managed by hostapd, and a monitor VIF for
injecting the LDN action frames. On the RTL8812AU that second VIF is not
available, and asking for it does not fail gracefully:

```console
$ iw dev wlx... interface add mon0 type monitor
# ...and the machine is gone. ping still answers, ssh never gets a banner.
```

Reproduced three times on Debian 13 / kernel 6.12 / aircrack-ng v5.13.6,
including with the base interface left DOWN. It is the fragility
`aircrack-ng/rtl8812au` issues #93 and #376 describe, so treat any plan that
needs a second VIF on this chip as dead.

**It is not needed.** The driver implements cfg80211's `.mgmt_tx`, so the
advertisement can be injected on the AP interface itself. `scripts/mgmt_tx_probe.c`
proves it end to end:

```console
$ ./mgmt_tx_probe wlx54c9ff02cd3b
sending 37-byte action frame on wlx54c9ff02cd3b (ifindex 4)
command accepted (ACK)
$ dmesg | tail -2
RTW: RTW_Tx:tx_ch=1, no_cck=0, da=ff:ff:ff:ff:ff:ff
RTW: RTW_Tx:OUI_Subtype=222, dialogToken=173
```

Two details decide whether this returns -EINVAL, -ENOTCONN or success:

| Requirement | Why |
|---|---|
| the interface must be in **AP mode** (hostapd running) | in managed mode and unassociated the kernel answers `-ENOTCONN` |
| `NL80211_ATTR_WIPHY_FREQ` **plus** `CHANNEL_WIDTH` **plus** `CENTER_FREQ1` | freq alone is not a parseable chandef (`-EINVAL` from cfg80211); with no freq at all `params->chan` is NULL and the driver returns `-EINVAL` itself |

So the architecture becomes one interface:

- **AP + data**: hostapd on the one interface; the console associates normally
  and Pia traffic is bridged as before.
- **Advertisement TX**: `NL80211_CMD_FRAME` on that same interface.
- **LDN control RX**: `NL80211_CMD_REGISTER_FRAME` for the category-127 action
  frames instead of reading them off a monitor device.

That removes the monitor interface from the design entirely, which is the
smaller of the two fallbacks in DESIGN.md §3b — no 802.11 MAC state machine,
just a different injection API.

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
