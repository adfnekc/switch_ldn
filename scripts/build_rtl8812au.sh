#!/bin/sh
#
# build_rtl8812au.sh -- apply patches/rtl8812au-linux-6.12.patch to an
# aircrack-ng/rtl8812au checkout and print the build commands.
#
# This exists because the driver does NOT compile on a current kernel without
# the patch, and because the five changes in it were found one compiler error at
# a time on a specific machine. Without this script, bring-up on a new box means
# rediscovering all of them.
#
# The patch is compilation only. Nothing in switch_ldn depends on a patched
# driver *behaviour*: AP mode and nl80211 .mgmt_tx are kernel interfaces, and
# they were measured working on this exact driver (docs/HARDWARE_CHECKLIST.md
# stage 4).
#
# Usage:
#     scripts/build_rtl8812au.sh [--check-only] <path-to-rtl8812au>
#
#   --check-only   only decide whether the patch applies; change nothing.
#
# Exit status:
#     0  patch applied, or was already applied
#     1  the checkout does not look like rtl8812au
#     2  the patch does not apply to this tree (wrong base version)
#
# Tested base: airckack-ng/rtl8812au commit ee6490b ("Turn of CONFIG_MP_INCLUDED"),
# on Debian 13 with kernel 6.12.113+deb13-amd64.

set -eu

check_only=0
if [ "${1-}" = "--check-only" ]; then
    check_only=1
    shift
fi

if [ $# -ne 1 ]; then
    echo "usage: $0 [--check-only] <path-to-rtl8812au>" >&2
    exit 1
fi

root=$1
if [ ! -f "$root/os_dep/linux/ioctl_cfg80211.c" ]; then
    echo "error: $root does not look like an rtl8812au checkout" >&2
    echo "       (os_dep/linux/ioctl_cfg80211.c is missing)" >&2
    exit 1
fi

# Anchor the patch path to this repo, not to the caller's cwd.
here=$(cd "$(dirname "$0")" && pwd)
patch_file=$here/../patches/rtl8812au-linux-6.12.patch
if [ ! -f "$patch_file" ]; then
    echo "error: $patch_file is missing" >&2
    exit 1
fi

# Three states, and they must stay distinguishable: a tree that is already
# patched is not a failure, and reporting it as one is how people end up
# applying the patch twice.
if patch -p1 -d "$root" --dry-run -N -s <"$patch_file" >/tmp/rtl8812au-apply.log 2>&1; then
    state=fresh
elif patch -p1 -d "$root" --dry-run -R -N -s <"$patch_file" >/dev/null 2>&1; then
    state=applied
else
    state=mismatch
fi

case $state in
fresh)
    if [ "$check_only" -eq 1 ]; then
        echo "OK: the patch applies cleanly (nothing written)"
        exit 0
    fi
    patch -p1 -d "$root" -N -s <"$patch_file"
    echo "OK: patch applied to $root"
    ;;
applied)
    echo "OK: $root is already patched"
    ;;
mismatch)
    echo "error: the patch does not apply to $root, and it is not already applied." >&2
    echo "       This is the wrong base version. The patch was written for" >&2
    echo "       aircrack-ng/rtl8812au ee6490b; check out that commit first:" >&2
    echo "         git clone https://github.com/aircrack-ng/rtl8812au" >&2
    echo "         git -C rtl8812au checkout ee6490b" >&2
    echo "       Hunk that failed:" >&2
    sed -n '1,20p' /tmp/rtl8812au-apply.log >&2
    exit 2
    ;;
esac

cat <<'EOS'

Now build and load it:

    cd <path-to-rtl8812au>
    make -j"$(nproc)"
    sudo make install
    sudo modprobe 88XXau        # the module is 88XXau, not rtl8812au

Then check the interface appeared and supports what the bridge needs:

    iw dev
    sudo ./switch_ldn --selfcheck <iface>

Do NOT create a monitor interface. On this driver
`iw dev <iface> interface add mon0 type monitor` hangs the machine; the bridge
injects on the AP interface over nl80211 instead. See
docs/HARDWARE_CHECKLIST.md stage 4.
EOS
