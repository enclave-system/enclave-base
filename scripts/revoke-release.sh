#!/usr/bin/env bash
# Durable revocation of released UKIs (N3b): produce a signed UEFI dbx append
# (authenticated variable update, signed with the Secure Boot KEK) holding the
# Authenticode SHA-256 hashes of the given EFI binaries. Once applied, the
# firmware refuses to boot them, even after a TPM clear.
#
# Usage: scripts/revoke-release.sh <pki-dir> <out.auth> <uki.efi> [<uki.efi>...]
#
# Delivery (Task 7 integrates it into updates):
#   - on a running system:  efi-updatevar -a -f <out.auth> dbx
#     (or write the .auth to /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f
#      with the APPEND_WRITE attribute)
#   - in firmware setup / provisioning: import as a dbx update
# A dbx change alters PCR 7: ship it together with a release whose
# HEAL_BELOW forces re-provisioning (README "Revoking a vulnerable release").
set -euo pipefail
[ "$#" -ge 3 ] || { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
pki="$1" out="$2"; shift 2
for f in "$pki/sb/GUID" "$pki/sb/KEK.key" "$pki/sb/KEK.crt"; do
    [ -f "$f" ] || { echo "revoke-release: missing $f" >&2; exit 1; }
done
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
hash-to-efi-sig-list "$@" "$tmp/dbx.esl" | sed 's/^HASH IS /revoke-release: authenticode sha256 /'
sign-efi-sig-list -a -g "$(cat "$pki/sb/GUID")" -k "$pki/sb/KEK.key" -c "$pki/sb/KEK.crt" \
    dbx "$tmp/dbx.esl" "$out" >/dev/null
echo "revoke-release: wrote signed dbx append $out ($# binaries)"
