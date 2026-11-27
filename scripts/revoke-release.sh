#!/usr/bin/env bash
# Durable revocation of released UKIs: produce a signed UEFI dbx append
# (authenticated variable update, signed with the Secure Boot KEK) holding the
# Authenticode SHA-256 hashes of the given EFI binaries. Once applied, the
# firmware refuses to boot them, even after a TPM clear.
#
# Usage: scripts/revoke-release.sh <pki-dir> <dir>/dbx-<id>.auth <uki.efi> [<uki.efi>...]
#
# Delivery: put the file into the EFI_UPDATES directory of the NEXT release
# (make EFI_UPDATES=<dir> SECURITY_EPOCH=<n+1> ...). That release carries it in
# its verity-protected /usr/lib/enclave/efi-updates/ and applies it itself on
# its first boot. A dbx change alters PCR 7; the release moves the state
# volume's Secure Boot binding across the update on each device (two boots, no
# re-provisioning, no data loss; README "Secure Boot variable
# updates (dbx, db, KEK) and PCR 7"). Do not apply the file by other means
# (efi-updatevar, firmware setup) on a provisioned device: PCR 7 would change
# without the transition and the device would fail closed.
# On a device that is not provisioned yet, importing it in the firmware setup
# before the first boot is fine.
set -euo pipefail
[ "$#" -ge 3 ] || { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
pki="$1" out="$2"; shift 2
case "$(basename "$out")" in
    dbx-*.auth) ;;
    *) echo "revoke-release: the output must be named dbx-<id>.auth (it goes into EFI_UPDATES)" >&2; exit 2 ;;
esac
for f in "$pki/sb/GUID" "$pki/sb/KEK.key" "$pki/sb/KEK.crt"; do
    [ -f "$f" ] || { echo "revoke-release: missing $f" >&2; exit 1; }
done
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
hash-to-efi-sig-list "$@" "$tmp/dbx.esl" | sed 's/^HASH IS /revoke-release: authenticode sha256 /'
sign-efi-sig-list -a -g "$(cat "$pki/sb/GUID")" -k "$pki/sb/KEK.key" -c "$pki/sb/KEK.crt" \
    dbx "$tmp/dbx.esl" "$out" >/dev/null
echo "revoke-release: wrote signed dbx append $out ($# binaries)"
