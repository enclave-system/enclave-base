#!/usr/bin/env bash
# Build a hardened enklave kernel flavor as a Debian package.
#
# Usage: build-kernel.sh <client|server> <pki-dir> <out-dir>
#
# Result: <out-dir>/linux-image-enklave-<flavor>_<kver>_amd64.deb
# (a copy of the bindeb-pkg image package, which is natively named
# linux-image-<kver>-enklave-<flavor>), plus the native debs.
# Exits non-zero if the tarball signature or check_config.py fails; the config
# check runs BEFORE the long compile.
#
# Env: CONFIG_ONLY=1 (stop after the config check), ENKLAVE_CACHE (default ~/enklave-cache), ENKLAVE_BUILD_ROOT
# (default ~/enklave-kbuild), JOBS (default 4).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
die() { echo "build-kernel: $*" >&2; exit 1; }

[ $# -eq 3 ] || die "usage: $0 <client|server> <pki-dir> <out-dir>"
flavor="$1"
case "$flavor" in client|server) ;; *) die "flavor must be client or server" ;; esac
pki="$(cd "$2" && pwd)" || die "pki dir not found: $2"
mkdir -p "$3"
out="$(cd "$3" && pwd)"

for f in "$pki/modsign/modsign.pem" "$pki/modsign/modsign.crt" "$pki/verity/verity.crt"; do
    [ -f "$f" ] || die "missing PKI file: $f"
done

ver="$(tr -d '[:space:]' < "$here/VERSION")"
[[ "$ver" =~ ^6\.12\.[0-9]+$ ]] || die "VERSION must be 6.12.y, got '$ver'"

cache="${ENKLAVE_CACHE:-$HOME/enklave-cache}/kernel"
broot="${ENKLAVE_BUILD_ROOT:-$HOME/enklave-kbuild}"
jobs="${JOBS:-4}"
mkdir -p "$cache" "$broot"

# --- Fetch + verify -------------------------------------------------------
GREG=647F28654894E3BD457199BE38DBBDC86092693E
LINUS=ABAF11C65A2970B130ABE3C479BE3E4300411886
tarball="$cache/linux-$ver.tar.xz"
sigfile="$cache/linux-$ver.tar.sign"
base="https://cdn.kernel.org/pub/linux/kernel/v6.x"
if [ ! -s "$tarball" ]; then
    curl -fsSL -o "$tarball.part" "$base/linux-$ver.tar.xz" || die "tarball download failed"
    mv -f "$tarball.part" "$tarball"
fi
[ -s "$sigfile" ] || curl -fsSL -o "$sigfile" "$base/linux-$ver.tar.sign"
[ -s "$tarball" ] || die "tarball download failed"

gnupghome="$cache/gnupg"
mkdir -p "$gnupghome"; chmod 700 "$gnupghome"
gpgk() { gpg --homedir "$gnupghome" --batch --no-default-keyring --keyring "$gnupghome/kernel.kbx" "$@"; }
if ! gpgk --list-keys "$GREG" >/dev/null 2>&1; then
    gpgk --auto-key-locate clear,wkd --locate-keys gregkh@kernel.org torvalds@kernel.org >/dev/null 2>&1 \
        || gpgk --keyserver hkps://keys.openpgp.org --recv-keys "$GREG" "$LINUS" \
        || die "could not import kernel.org signing keys"
fi
# The imported keys must carry the pinned fingerprints.
for fp in $GREG; do
    gpgk --list-keys --with-colons "$fp" 2>/dev/null | grep -q "^fpr:::::::::$fp:" \
        || die "pinned key $fp not in keyring"
done

status="$(xz -cd "$tarball" | gpgk --status-fd 1 --verify "$sigfile" - 2>/dev/null)" \
    || die "GPG verification FAILED for linux-$ver.tar.xz"
# VALIDSIG's last field is the primary key fingerprint; it must be a pinned one.
primary="$(awk '$2=="VALIDSIG"{print $NF}' <<<"$status")"
[ "$primary" = "$GREG" ] || [ "$primary" = "$LINUS" ] \
    || die "signature not made by a pinned kernel.org key (got '${primary:-none}')"
echo "GPG OK: linux-$ver.tar.xz signed by $primary"

# --- Configure ------------------------------------------------------------
src="$broot/linux-$ver-$flavor"
rm -rf "$src"; mkdir -p "$src"
xz -cd "$tarball" | tar -xf - -C "$src" --strip-components=1
cd "$src"

make x86_64_defconfig
KCONFIG_CONFIG=.config scripts/kconfig/merge_config.sh -m .config \
    "$here/config/common.config" "$here/config/$flavor.config"

cat "$pki/modsign/modsign.crt" "$pki/verity/verity.crt" > "$src/enklave-trusted-keys.pem"
scripts/config --set-str MODULE_SIG_KEY "$pki/modsign/modsign.pem"
scripts/config --set-str SYSTEM_TRUSTED_KEYS "$src/enklave-trusted-keys.pem"
scripts/config --set-str LOCALVERSION "-enklave-$flavor"
scripts/config --disable LOCALVERSION_AUTO
make olddefconfig

echo "== check_config ($flavor) =="
python3 "$here/check_config.py" .config "$here/rules/common.rules" "$here/rules/$flavor.rules" \
    || die "config rules FAILED, aborting before compile"

[ -z "${CONFIG_ONLY:-}" ] || { echo "CONFIG_ONLY set: stopping after config check"; exit 0; }

# --- Build ----------------------------------------------------------------
export KBUILD_BUILD_USER=enklave KBUILD_BUILD_HOST=enklave-builder
export DEBEMAIL=build@enklave.invalid DEBFULLNAME="enklave kernel build"
make -j"$jobs" bindeb-pkg

# --- Collect --------------------------------------------------------------
# Re-check the .config that was actually packaged.
python3 "$here/check_config.py" .config "$here/rules/common.rules" "$here/rules/$flavor.rules" \
    || die "final config rules FAILED"
cp -f .config "$out/config-$ver-enklave-$flavor"

rm -f "$out"/linux-image-enklave-"$flavor"_*.deb
shopt -s nullglob
native=("$broot"/linux-image-"$ver"*-enklave-"$flavor"_*_amd64.deb)
[ ${#native[@]} -eq 1 ] || die "expected exactly one native image deb, found ${#native[@]}"
cp -f "$broot"/linux-*"$ver"*-enklave-"$flavor"*.deb "$out"/ 2>/dev/null || true
cp -f "${native[0]}" "$out/linux-image-enklave-${flavor}_${ver}_amd64.deb"
echo "Built: $out/linux-image-enklave-${flavor}_${ver}_amd64.deb"
