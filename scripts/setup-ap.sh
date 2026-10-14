#!/usr/bin/env bash
#
# Bring up the 802.11 side of the bridge.
#
# Layout we are aiming for:
#
#     wlan0  -> hostapd-managed AP (hidden SSID, open auth, no WPA)
#               bridges 802.11 stations into the Linux bridge, so LDN control
#               frames and Pia traffic arrive on an AF_PACKET socket as
#               normal Ethernet frames.
#
#     wlan0  -> monitor VIF on the same radio, used only to inject the
#               100 ms LDN vendor-specific action frames.
#
#    hostapd is *not* modified. The reason we cannot use hostapd alone is that
#    it cannot emit a periodic vendor-specific action frame.
#
# NOTE ON THE RTL8812AU: the aircrack-ng out-of-tree driver is the only one
# with reliable monitor mode + injection on this chip, but its VIF support is
# fragile (aircrack-ng/rtl8812au#93, #376). If the `iw add` below fails, the
# alternatives are (a) patch hostapd to inject the action frame itself, or
# (b) drop hostapd and implement the 802.11 MAC FSM in userspace on a single
# monitor interface (more work, but only one VIF - see DESIGN.md §3b).

set -euo pipefail

IFACE="${IFACE:-wlan0}"
AP_IFACE="${AP_IFACE:-wlan0_ap}"
MON_IFACE="${MON_IFACE:-wlan0_mon}"
CHANNEL="${CHANNEL:-1}"
BAND="${BAND:-2}"
COUNTRY="${COUNTRY:-US}"

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (raw 802.11 needs CAP_NET_ADMIN)" >&2
    exit 1
fi

cmd="${1:-up}"

case "$cmd" in
up)
    # The 8812AU driver refuses injection while NetworkManager holds the card.
    systemctl stop NetworkManager 2>/dev/null || service network-manager stop 2>/dev/null || true
    rfkill unblock all || true

    # No regulatory enforcement: LDN needs channels the driver would otherwise reject.
    iw reg set "$COUNTRY" || true

    ip link set "$IFACE" down

    # --- hostapd interface -------------------------------------------------
    # Hidden network, open authentication. hostapd will still emit its own
    # beacons (with a normal SSID) which the Switches ignore - they scan for
    # the LDN action frame, not the beacon.
    iw dev "$IFACE" interface add "$AP_IFACE" type __ap || true
    iw dev "$AP_IFACE" set channel "$CHANNEL" 2>/dev/null || \
        iw dev "$AP_IFACE" set freq "$(( 2407 + 5 * (CHANNEL - 1) ))"
    ip link set "$AP_IFACE" up

    # --- monitor interface --------------------------------------------------
    iw dev "$IFACE" interface add "$MON_IFACE" type monitor || true
    iw dev "$MON_IFACE" set channel "$CHANNEL" 2>/dev/null || \
        iw dev "$MON_IFACE" set freq "$(( 2407 + 5 * (CHANNEL - 1) ))"
    ip link set "$MON_IFACE" up

    echo "AP iface:    $AP_IFACE"
    echo "Monitor if:  $MON_IFACE"
    echo
    echo "Next: write /etc/hostapd/ldn-ap.conf from config/ldn-ap.conf and run"
    echo "      hostapd /etc/hostapd/ldn-ap.conf &"
    ;;

selfcheck)
    echo "=== $IFACE ==="
    iw dev | sed 's/^/  /'
    iw dev "$IFACE" info 2>/dev/null | sed 's/^/  /'
    iw phy "$IFACE" channels 2>/dev/null | grep -E "^\s+\*|MHz" | head -20 || true

    # Can we create a VIF at all?
    iw dev "$IFACE" interface add __probe_mon type monitor 2>/dev/null && \
        { echo "  monitor VIF: OK"; iw dev __probe_mon del; } || \
        echo "  monitor VIF: UNSUPPORTED (fall back to a single monitor iface)"

    ./switch_ldn --selfcheck "$IFACE"
    ;;

down)
    for v in "$MON_IFACE" "$AP_IFACE"; do
        iw dev "$v" del 2>/dev/null || true
    done
    systemctl start NetworkManager 2>/dev/null || service network-manager start 2>/dev/null || true
    ;;

*)
    echo "usage: $0 {up|down|selfcheck}" >&2
    exit 1
    ;;
esac
