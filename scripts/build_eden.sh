#!/bin/sh
#
# build_eden.sh -- verify that the Eden LDN-passphrase patch applies to an
# Eden / yuzu-family source checkout, WITHOUT any network access or a C++
# build toolchain.  The only external dependency is `git` itself, and only its
# `git apply --check` (a textual patch application), so no compiler, cmake,
# submodules or the internet are involved.
#
# Tested base (see docs/EDEN_PATCH.md): Eden commit 218c6705 (2026-10-13).
#
# Usage:
#     scripts/build_eden.sh [--check-only] <path-to-eden-checkout>
#
#   <path-to-eden-checkout>   Eden repo root; must contain
#                             src/network/room_member.cpp or src/yuzu/main.cpp.
#
#   --check-only              STRICT mode: only run a fresh forward
#                             `git apply --check`.  Fails on an already
#                             patched tree.  (This is the core/default apply
#                             verification.)
#
# With no flag the script performs the default forward check AND, if the tree
# is already patched, reports "ALREADY APPLIED" (via `git apply --reverse
# --check`) so repeated runs are unambiguous instead of reporting a bogus
# failure.
#
# REPO-ROOT ANCHORING (read before editing):
#   We intentionally run from the *switch_ldn* repo root so the patch file
#   (patches/eden-room-passphrase.patch) resolves independently of the caller's
#   current directory.  The script derives that root from its own location.
#
#   IMPORTANT: with `git -C <checkout>`, git resolves *relative* file arguments
#   (including the patch path) against <checkout>, NOT against the shell's cwd.
#   A literal `git -C <checkout> apply ... patches/eden-room-passphrase.patch`
#   therefore looks for the patch inside the checkout and fails with
#   "can't open patch".  To honour the "run from repo root so the relative patch
#   path resolves" intent while actually working, we pass an ABSOLUTE patch path
#   (PATCH_REL anchored to REPO_ROOT) to git.  Do not "simplify" this back to a
#   bare relative path -- it will not resolve.
#
# Exit status:
#   0   PASS - patch applies cleanly (fresh) or is already applied.
#   1   verification failed (patch does not apply to this base).
#   2   usage error (missing/unknown arguments).

set -eu

PATCH_REL="patches/eden-room-passphrase.patch"   # relative to REPO_ROOT

usage() {
    cat <<EOF
Usage: $0 [--check-only] <path-to-eden-checkout>

Verify that $PATCH_REL applies cleanly to an Eden / yuzu-family source
checkout, with NO network access and NO C++ build toolchain (git only).

  <path-to-eden-checkout>   Path to an Eden repo root; must contain
                            src/network/room_member.cpp or src/yuzu/main.cpp.

Options:
  --check-only              Strict fresh-apply check only
                            (fails if the tree is already patched).
  -h, --help                Show this help and exit.

With no flag, an already-patched tree is reported as ALREADY APPLIED
(git apply --reverse --check) instead of a confusing failure.
EOF
}

# --------------------------------------------------------------------------
# git is the ONLY external dependency, and only for its textual patch check.
# --------------------------------------------------------------------------
if ! command -v git >/dev/null 2>&1; then
    echo "error: 'git' is required (used only for 'git apply --check'; no network/build)." >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Argument parsing: optional flags + exactly one positional path.
# --------------------------------------------------------------------------
CHECK_ONLY=0
EDEN_PATH=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --check-only) CHECK_ONLY=1 ;;
        -h|--help)    usage; exit 0 ;;
        --)
            shift
            if [ "$#" -gt 0 ]; then EDEN_PATH="$1"; fi
            break
            ;;
        -*)
            echo "error: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [ -z "$EDEN_PATH" ]; then
                EDEN_PATH="$1"
            else
                echo "error: unexpected extra argument '$1'" >&2
                usage >&2
                exit 2
            fi
            ;;
    esac
    shift
done

if [ -z "$EDEN_PATH" ]; then
    echo "error: missing required <path-to-eden-checkout> argument." >&2
    usage >&2
    exit 2
fi

# --------------------------------------------------------------------------
# Resolve and validate the checkout path (before cd-ing to REPO_ROOT, so a
# relative EDEN_PATH still resolves against the caller's cwd).
# --------------------------------------------------------------------------
if ! EDEN_ABS=$(CDPATH= cd -- "$EDEN_PATH" 2>/dev/null && pwd); then
    echo "error: cannot enter directory '$EDEN_PATH'." >&2
    exit 1
fi

if [ ! -e "$EDEN_ABS/src/network/room_member.cpp" ] && \
   [ ! -e "$EDEN_ABS/src/yuzu/main.cpp" ]; then
    echo "error: '$EDEN_PATH' does not look like an Eden repo root." >&2
    echo "       expected src/network/room_member.cpp or src/yuzu/main.cpp." >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Anchor to the switch_ldn repo root (parent of this script's dir) so the
# patch path resolves no matter where the script is invoked from.
# --------------------------------------------------------------------------
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if [ ! -f "$REPO_ROOT/$PATCH_REL" ]; then
    echo "error: patch '$PATCH_REL' not found under repo root '$REPO_ROOT'." >&2
    exit 1
fi

# Absolute patch path: required because `git -C <checkout>` resolves relative
# arguments against <checkout> (see header note). DO NOT revert to relative.
PATCH="$REPO_ROOT/$PATCH_REL"

# --------------------------------------------------------------------------
# Fresh-applicability check: git apply --check --verbose.
# --------------------------------------------------------------------------
if FORWARD_OUT=$(git -C "$EDEN_ABS" apply --check --verbose "$PATCH" 2>&1); then
    FORWARD_RC=0
else
    FORWARD_RC=$?
fi

if [ "$FORWARD_RC" -eq 0 ]; then
    echo "PASS: $PATCH_REL applies cleanly to $EDEN_ABS"
    if [ "$CHECK_ONLY" -eq 1 ]; then
        echo "     (mode: --check-only, fresh forward apply succeeded)"
    fi
    exit 0
fi

# Forward check did not pass.
if [ "$CHECK_ONLY" -eq 0 ]; then
    # Default mode: distinguish "already applied" from a genuine base mismatch.
    if git -C "$EDEN_ABS" apply --reverse --check "$PATCH" >/dev/null 2>&1; then
        echo "STATUS: $PATCH_REL is ALREADY APPLIED to $EDEN_ABS."
        echo "        A fresh forward check therefore fails (it would patch twice)."
        echo "        This is not an error; nothing to do. To assert a *fresh-tree*"
        echo "        apply instead, run: $0 --check-only $EDEN_PATH"
        exit 0
    fi
fi

# Genuine failure: surface the git apply output plus an actionable hint.
echo "ERROR: '$PATCH_REL' does not apply to $EDEN_ABS (git apply --check rc=$FORWARD_RC)." >&2
printf '%s\n' "$FORWARD_OUT" >&2
echo "" >&2
echo "HINT: the patch context did not match this checkout." >&2
echo "  - Confirm <path> is an Eden/yuzu-family tree at a compatible revision" >&2
echo "    (tested base: 218c6705, see docs/EDEN_PATCH.md)." >&2
echo "  - Inspect the targets: src/core/hle/service/ldn/lan_discovery.{cpp,h}" >&2
echo "    and src/network/room_member.{cpp,h}." >&2
echo "  - Re-generate patches/eden-room-passphrase.patch against the new base if" >&2
echo "    Eden has moved on." >&2
exit "$FORWARD_RC"
