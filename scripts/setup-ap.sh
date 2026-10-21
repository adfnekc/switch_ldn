#!/bin/sh
#
# Bring up the 802.11 side of the bridge.
#
#     $IFACE  ->  hostapd-managed AP (hidden SSID, open auth, no WPA)
#
# One interface is all this needs. The AP interface carries the LDN control and
# Pia traffic as Ethernet (hostapd bridges it), and the advertisements go out
# through nl80211 .mgmt_tx on that same interface - see src/nl80211.h.
#
# A SECOND VIRTUAL INTERFACE IS NOT CREATED, ON PURPOSE.
#
# The original design used an AP VIF plus a monitor VIF for injecting action
# frames. On the RTL8812AU, creating a monitor VIF does not fail: it wedges the
# kernel (ping keeps answering, ssh never gets a banner), measured three times
# on Debian 13 / kernel 6.12 / aircrack-ng v5.13.6, including with the base
# interface down. That is aircrack-ng/rtl8812au #93 and #376. So this script
# never asks the driver for one, and neither does selfcheck.
#
# hostapd is *not* modified. It cannot emit a periodic vendor-specific action
# frame, which is why the bridge injects that itself.

set -eu

IFACE="${IFACE:-wlan0}"
CHANNEL="${CHANNEL:-1}"
COUNTRY="${COUNTRY:-US}"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (raw 802.11 needs CAP_NET_ADMIN)" >&2
    exit 1
fi

cmd="${1:-up}"

case "$cmd" in
up)
    # NetworkManager and rfkill both hold the card away from hostapd.
    systemctl stop NetworkManager 2>/dev/null || service network-manager stop 2>/dev/null || true
    rfkill unblock all 2>/dev/null || true

    # No regulatory enforcement: LDN needs channels the driver would otherwise
    # reject with the default domain.
    iw reg set "$COUNTRY" 2>/dev/null || true

    # Down here, up by hostapd: it owns mode, channel and beaconing.
    ip link set "$IFACE" down
    ip link set "$IFACE" up

    echo "interface: $IFACE (channel $CHANNEL, country $COUNTRY)"
    echo
    echo "Next: hostapd config/ldn-ap.conf &"
    echo "      (set interface= to '$IFACE' and channel= to '$CHANNEL')"
    ;;

selfcheck)
    echo "=== $IFACE ==="
    iw dev 2>/dev/null | sed 's/^/  /'
    iw dev "$IFACE" info 2>/dev/null | sed 's/^/  /'

    # Read-only capability check. Do NOT probe by creating a monitor VIF: on
    # this driver that is the operation that hangs the machine.
    phy=$(iw dev "$IFACE" info 2>/dev/null | awk '/wiphy/{print $2}')
    if [ -n "${phy:-}" ]; then
        echo "  --- supported interface modes (phy$phy) ---"
        iw phy "phy$phy" info 2>/dev/null |
            awk '/Supported interface modes/{f=1;next} f&&/^\t\t \*/{print "  " $0} f&&/^\t[A-Z]/{exit}'
        for want in AP monitor; do
            if iw phy "phy$phy" info 2>/dev/null |
                sed -n '/Supported interface modes/,/^\t[A-Z]/p' | grep -q "\* $want"; then
                echo "  $want: supported"
            else
                echo "  $want: NOT supported"
            fi
        done
    fi

    echo "  --- channels (first few) ---"
    iw phy "${phy:-$IFACE}" channels 2>/dev/null | head -12 || true

    # The bridge's own probe: exits nonzero for a missing interface or one with
    # no wireless extensions.
    if [ -x ./switch_ldn ]; then
        ./switch_ldn --selfcheck "$IFACE" || echo "  switch_ldn --selfcheck FAILED (see above)"
    else
        echo "  ./switch_ldn not built, skipping its probe"
    fi

    cat <<'EOF'

  Note: "monitor: supported" means the driver advertises the mode, which is all
  the bridge needs to know. Do not try it: creating a monitor VIF on the
  RTL8812AU wedges the kernel, and nothing here requires one.
EOF
    ;;

down)
    ip link set "$IFACE" down 2>/dev/null || true
    systemctl start NetworkManager 2>/dev/null || service network-manager start 2>/dev/null || true
    ;;

*)
    echo "usage: $0 {up|down|selfcheck}" >&2
    exit 1
    ;;
esac
