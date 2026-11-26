#!/usr/bin/env bash
# Verifies the build host. Prints "MISSING <name>" per gap, exit 1 if any.
set -u
# sbin is not on the PATH of unprivileged users on Debian
PATH="$PATH:/usr/sbin:/sbin"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$here/BUILDHOST.lock"

rc=0
missing() { echo "MISSING $1"; rc=1; }
have() { command -v "$1" >/dev/null 2>&1; }

# mkosi at the pinned tag
if have mkosi; then
    want="${MKOSI_TAG#v}"
    got="$(mkosi --version 2>/dev/null | awk '{print $NF}' | head -n1)"
    got="${got#v}"
    [ "$got" = "$want" ] || missing "mkosi==${MKOSI_TAG} (found ${got:-none})"
else
    missing mkosi
fi

# go >= GO_MIN
if have go; then
    gov="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
    if [ "$(printf '%s\n%s\n' "$GO_MIN" "$gov" | sort -V | head -n1)" != "$GO_MIN" ]; then
        missing "go>=${GO_MIN} (found ${gov})"
    fi
else
    missing go
fi

for c in qemu-system-x86_64 swtpm sbsign sbverify cert-to-efi-sig-list \
         sign-efi-sig-list openssl pytest systemd-repart ukify veritysetup \
         cryptsetup virt-fw-vars gpg mcopy mkfs.vfat git; do
    have "$c" || missing "$c"
done

[ -e /usr/share/OVMF/OVMF_CODE_4M.secboot.fd ] || missing OVMF_CODE_4M.secboot.fd
[ -e /dev/kvm ] || missing /dev/kvm
[ -e /usr/share/efi-shell-x64/shellx64.efi ] || missing efi-shell-x64

# kernel bindeb-pkg build dependencies
for p in build-essential flex bison bc libelf-dev libssl-dev dwarves rsync cpio kmod zstd; do
    dpkg -s "$p" >/dev/null 2>&1 || missing "pkg:$p"
done

exit "$rc"
