#!/usr/bin/env bash
# Installs everything the enclave build needs on Debian 13. Idempotent.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$here/BUILDHOST.lock"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
    qemu-system-x86 ovmf swtpm swtpm-tools sbsigntool efitools openssl \
    python3-pytest python3-virt-firmware systemd-repart systemd-ukify systemd-boot-tools \
    cryptsetup-bin golang git ca-certificates \
    bubblewrap debian-archive-keyring dosfstools mtools e2fsprogs \
    squashfs-tools erofs-utils systemd-container apt zstd xz-utils kmod \
    cpio uidmap python3 gnupg efi-shell-x64 tpm2-tools \
    build-essential flex bison bc libelf-dev libssl-dev dwarves rsync debhelper dpkg-dev

# VM tests run QEMU with KVM as the build user (takes effect on next login).
build_user="${SUDO_USER:-$(id -un)}"
if [ "$build_user" != root ]; then
    $SUDO usermod -aG kvm "$build_user"
fi

if [ -d /opt/mkosi/.git ]; then
    $SUDO git -C /opt/mkosi fetch --tags --quiet
else
    $SUDO git clone --quiet https://github.com/systemd/mkosi /opt/mkosi
fi
$SUDO git -C /opt/mkosi -c advice.detachedHead=false checkout --quiet "$MKOSI_TAG"
$SUDO ln -sfn /opt/mkosi/bin/mkosi /usr/local/bin/mkosi
