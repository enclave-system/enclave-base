# enklave-base

Foundation repo of the enklave ecosystem: minimal, signed, immutable Linux
images for a hardened custom OS, built with mkosi on Debian 13 (trixie).

Specification (outside this repo):
`docs\superpowers\specs\2026-11-26-enklave-design.md`

**Build runs only on the Linux build host** (Debian 13). Windows is used
for editing and committing only.

Build host setup:

    sudo scripts/bootstrap-buildhost.sh   # idempotent
    scripts/check-buildhost.sh            # silent, exit 0 = ready

Pinned tool versions live in `BUILDHOST.lock`.

## PKI

`pki/enklave-pki init <dir>` generates all signing keys (Secure Boot, dm-verity,
module signing, config signing, update GPG, PCR policy). Protecting that
directory is the operator's job:

- Generate the production PKI on an offline machine.
- Keep the directory mode 0700 on encrypted, offline media.
- Never copy secret keys to the build host or into the repo.
- The dev PKI (`~/enklave-pki-dev` on the build host) is for development only.

- `enklave-pki init --dev <dir>` marks a development PKI (`DEV-KEYS`). Test-profile
  images are signed only with a dev PKI, production images never (the build
  refuses; `ENKLAVE_DEV_PROD=1` allows unshippable development builds).

## Persistent state, /var and the TPM

The root file system is a tmpfs; `/var` is volatile. The **only persistent
storage** is the state volume mounted at `/var/lib/enklave` (1 GiB partition
`enklave-var` on the disk that carries `/usr`):

- LUKS2 `aes-xts-plain64` (512-bit), `hmac-sha256` integrity, argon2id keyslot.
- The 64-byte volume key lives only in TPM NV index `0x01800E02`, read once per
  boot and then read-locked.
- State lives in `/var/lib/enklave/data` and is written only through
  `enklave-varauth state-exec -- CMD ...` (CMD works on a staged copy,
  `$ENKLAVE_STATE_DIR`; the result is committed atomically). Every commit
  updates an HMAC manifest (path, type, mode, owner, hash of every entry; key
  derived from the volume key) whose version is bound to the TPM NV counter
  `0x01800E03`. Boot fails closed on any spliced, older or foreign content
  (dm-integrity authenticates sectors but not their version). A crash during a
  commit is rolled forward or back at the next boot.
  Example: `enklave-varauth state-exec -- enklave-cfg apply --root '{}/config' ...`.

### TPM policy and ownership

Every enklave TPM object and the owner, endorsement and lockout hierarchies are
governed by

    P = PolicyAuthorize(PCR key, "enklave-var-v1:<role>:<profile>") + PolicyPCR(7 = current, 12 = 0)

The authorized part is the release's signed approved policy
(`/EFI/enklave/policy/<uki>.json` on the ESP, made by `enklave-sign-policy`):
PCR 11 of exactly that UKI in the phase `enter-initrd:leave-initrd`, and its
**security epoch** not revoked in the bits index `0x01800E04`. Role and profile
are part of the policyRef, so a test-profile UKI cannot open a production
volume and one role cannot open another's.

There is no administrative secret: on the first boot the hierarchies get
policy P, random discarded authValues and `TPM2_Clear` is disabled, *before*
any index that protects data exists. A platform hierarchy usable from the OS
is disabled on every boot. All commands that carry secrets (volume key,
authValues) use salted sessions with parameter encryption; the salt key
(`0x81000E01`) is pinned by Name in record `0x01800E01`. Any partial or
unexpected TPM state fails closed (power off).

Limit: an active TPM-bus attacker present already at provisioning could
substitute the salt key; detecting that needs TPM endorsement-certificate
validation against the TPM vendor CA (not included). Provision devices in a
trusted environment.

### Security epochs: revoking a vulnerable release

Rules:

1. **Every security fix raises `SECURITY_EPOCH`.** Any older release of the
   same epoch can read the state volume, so a fixed release with an unchanged
   epoch revokes nothing.
2. Revocation takes effect when the new release first boots on a device: it
   sets the bits of all older epochs (set-only, irreversible). Until then — and
   on devices whose TPM gets cleared physically — old UKIs still boot. Close
   that gap with a UEFI dbx update: `scripts/revoke-release.sh <pki> dbx.auth
   <old-uki.efi>...` produces a KEK-signed dbx append (delivery: Task 7 /
   `efi-updatevar -a -f dbx.auth dbx`). A dbx change alters PCR 7, so ship it
   in a release with `HEAL_BELOW` set (the state volume is re-provisioned).
3. If a vulnerable epoch may have leaked the volume key or TPM authorization,
   also set `HEAL_BELOW` (see below).
4. Epoch budget: 64 epochs (0–63). When it is exhausted, re-provision the
   fleet (factory reset clears the epoch index); plan epochs per security
   release, not per build.

Pre-scheme UKIs (empty policyRef, builds ≤ 2fd8d34) never satisfy P.

### Healing after a compromise

`HEAL_BELOW=N` (baked into the verity-protected `release.json`) makes a
release re-provision every state volume provisioned under an epoch < N on its
first boot: hierarchy policies and authValues are rotated, the salt key is
re-created, the volume key, record and counter are destroyed and recreated,
and the state volume is wiped (clients re-enroll via the console). A key or
authorization obtained under a revoked epoch is useless afterwards.

### Recovery: tainted PCR 12

systemd-stub measures credentials (`*.cred`), addons and command line
overrides found on the (unauthenticated) ESP into PCR 12; the state volume is
bound to PCR 12 = 0, so a stray or planted file such as
`\loader\credentials\*.cred` or `\EFI\Linux\<uki>.efi.extra.d\*` makes the
machine power off at every boot. Remove the files from the ESP (from another
system) and boot again.

### Impact of key and firmware changes

- **PCR signing key:** the hierarchies and indices are bound to it. A new key
  requires a factory reset; revoke releases with epochs, not new keys.
- **Secure Boot db/dbx/KEK/PK or firmware changes affecting PCR 7:** the
  policies bind the current PCR 7, so they require re-provisioning: ship them
  with a healing release, or apply them before the first boot.

### Factory reset

Clear the TPM in the firmware setup (physical presence; this wipes all owner
objects and re-enables Clear) and delete the `enklave-var` partition; the next
boot provisions a fresh state volume. An interrupted provisioning fails closed
and needs the same procedure (or a release with `HEAL_BELOW` > 0).
