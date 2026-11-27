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

- A build signed with a dev PKI carries a marker that is measured and visible
  at runtime: `"dev_keys":true` in the verity-protected
  `/usr/lib/enklave/release.json` (covered by PCR 11 through the usr root
  hash) and in the release's policy JSON. Such an image prints
  `[DEV KEYS: development build, never ship]` on the serial port at every boot
  and the selftest reports the check `dev_keys`. Production acceptance runs
  `enklave-selftest --forbid-dev-keys`, which fails for a dev-signed build.
  `enklave-sign-policy` refuses to sign an image whose marker does not match
  the PKI.

## Persistent state, /var and the TPM

The root file system is a tmpfs; `/var` is volatile. The **only persistent
storage** is the state volume mounted at `/var/lib/enklave` (1 GiB partition
`enklave-var` on the disk that carries `/usr`):

- LUKS2 `aes-xts-plain64` (512-bit), `hmac-sha256` integrity, argon2id keyslot.
- The 64-byte volume key lives only in TPM NV index `0x01800E02`, read once per
  boot and then read-locked.
- The volume is mounted **read-only**. No process, root included, can write
  the state through the mount.
- State lives in `/var/lib/enklave/data` and is written only through
  `enklave-varauth state-exec -- CMD ...`: it re-executes itself in a private
  mount namespace, makes the volume writable there only, lets CMD work on a
  staged copy (`$ENKLAVE_STATE_DIR`) and commits the result atomically. Every
  commit updates an HMAC manifest (path, type, mode, owner, hash of every
  entry; key derived from the volume key) whose version is bound to the TPM NV
  counter `0x01800E03`. Boot fails closed on any spliced, older or foreign
  content (dm-integrity authenticates sectors but not their version). A crash
  during a commit is rolled forward or back at the next boot.
  Example: `enklave-varauth state-exec -- enklave-cfg apply --root '{}/config' ...`.

Limit of the read-only mount: a root process that keeps `CAP_SYS_ADMIN` can
create its own mount namespace and remount, or open the block device. Nothing
in the base image does. Role services must run without `CAP_SYS_ADMIN`
(systemd `CapabilityBoundingSet=`); a write that bypasses `state-exec` can only
make the next boot fail closed, it can never forge state.

### TPM policy and ownership

The volume key, the record, the administration of the counter and the owner,
endorsement and lockout hierarchies are governed by

    P = PolicyAuthorizeNV(V)
    V = PolicyAuthorize(PCR key, "enklave-var-v1:<role>:<profile>") + PolicyPCR(7 = recorded, 12 = 0)

`V` is the NV index `0x01800E05`. It holds the PCR-bound part of the policy
and can be written only through the owner hierarchy, that is, under P itself.
The Name of `V` (and with it P) is bound to the PCR signing key, role and
profile.

Two indices have their own policies:

- The revocation bits `0x01800E04`: bits can be set by any approved UKI of the
  same role and profile (`PolicyAuthorize` alone) and never cleared.
- The counter `0x01800E03`: read and incremented at runtime with an authValue
  derived from the volume key; that authValue can be set under P only.

The authorized part is the release's signed approved policy
(`/EFI/enklave/policy/<uki>.json` on the ESP, made by `enklave-sign-policy`):
PCR 11 of exactly that UKI in the phase `enter-initrd:leave-initrd`, and its
**security epoch** not revoked in the bits index `0x01800E04`. Role and profile
are part of the policyRef, so a test-profile UKI cannot open a production
volume and one role cannot open another's.

There is no administrative secret. The first boot on a fresh TPM runs in this
order:

1. The TPM's endorsement key is authenticated (next section) and persisted as
   the salt key `0x81000E01`.
2. The two indices that hold no secret and that P refers to are defined with
   the still-empty owner auth: the revocation bits `0x01800E04` and `V`
   `0x01800E05` (holding the Secure Boot state of this boot).
3. The hierarchies are locked: policy P, random discarded authValues,
   `TPM2_Clear` disabled.
4. Only then the indices that protect data are created, each authorized by P:
   the volume key `0x01800E02`, the counter `0x01800E03` and the record
   `0x01800E01` (PCR 15 of the volume, provisioning epoch, Name of the salt
   key).

A platform hierarchy usable from the OS is disabled on every boot. All
commands that carry secrets (volume key, authValues) use sessions salted to
the endorsement key with parameter encryption. Any partial or unexpected TPM
state fails closed (power off).

The TPM must implement `TPM2_PolicyAuthorizeNV` (TPM 2.0 library revision 1.38
or later); the first boot refuses older TPMs.

**Dictionary-attack lockout is disabled.** The endorsement key is a
DA-protected object: once it has been used as a salt key, the TPM counts every
power loss without an orderly shutdown as a failed authorization, and anyone
can add failures with wrong authValues. A TPM in lockout refuses salted
sessions, so a few power cuts would make the device fail closed (seen on
swtpm after three). Every boot therefore resets the failure counter and sets
the recovery time to 0 through the lockout hierarchy (policy P), before its
first salted session. Nothing is lost: no enklave secret is a guessable
authValue (all are 256-bit random values, all indices are `NO_DA`). The
selftest check `tpm_locked` fails if the lockout is still enabled.

### TPM authenticity: endorsement key certificate

The salt key is the TPM's endorsement key (EK, TCG default template, ECC P-256
or RSA 2048). Its public area is never taken on trust from the TPM bus. On
**every boot** (first provisioning, healing and normal boots):

- the EK certificate is read from the TPM (NV `0x01C0000A` ECC, `0x01C00002`
  RSA; intermediate certificates from NV `0x01C00100`–`0x01C001FF`) and must
  chain to a TPM vendor CA in `/usr/share/enklave/tpm-ek-ca` (AMD, Atmel,
  Infineon, Intel, NationZ, Nuvoton, Qualcomm, STMicro; provenance in
  `SOURCE`, hashes in `SHA256SUMS`);
- the EK public area is rebuilt locally from the default template and the
  certificate's public key; the key in the TPM must be exactly that key;
- sessions are started from a locally built key reference, so the TPM tools
  never ask the TPM for the public key again.

A TPM without a valid certificate (missing, foreign CA, expired, certificate
of another key) **fails closed**; nothing is provisioned. Certificate validity
is checked against the clock; a clock earlier than the build time of the
release (dead RTC battery) is replaced by the build time.

Not accepted on purpose:

- **Virtual TPMs.** The Microsoft CA that certifies Hyper-V/Azure virtual TPMs
  is not shipped.
- **The test CA.** `enklave-pki ek-test-ca` creates a CA for the emulated TPMs
  of the VM tests (`swtpm_setup --create-ek-cert`). Its certificates go into
  test-profile images only (`/usr/share/enklave/tpm-ek-ca-test`); the build
  asserts that production images do not contain them, and the runtime reads
  them in the test profile only.
- **SHA-1 signed EK certificates** of TPMs from before 2016.

**Signed allowlist.** For a TPM without an EK certificate in NV (AMD fTPM,
Intel PTT on some platforms, virtual TPMs of development VMs), a release can
carry the EK Names of individual devices: build with
`EK_ALLOWLIST=<file>` (one Name per line, `#` comments). The file ends up in
the verity-protected `/usr/lib/enklave/ek-allowlist` and is signed with the
release. Get the Names on the device before provisioning, from a trusted
provisioning system with tpm2-tools: `enklave-varauth ek-name`, or
`tpm2_createek -G ecc -c ek.ctx -u ek.pub` and the `name` line of
`tpm2_readpublic -c ek.ctx`. An allowlist entry is only as good as the moment
it was read.

### Security epochs: revoking a vulnerable release

Rules:

1. **Every security fix raises `SECURITY_EPOCH`.** Any older release of the
   same epoch can read the state volume, so a fixed release with an unchanged
   epoch revokes nothing.
2. Revocation by epoch takes effect when the new release first boots on a
   device: it sets the bits of all older epochs (set-only, irreversible).
   Until then, and on a device whose TPM gets cleared physically, old UKIs
   still boot.
3. **Close that gap with a dbx update in the same release:**

       scripts/revoke-release.sh <pki> updates/dbx-epoch<N>.auth <old-uki.efi>...
       make EFI_UPDATES=updates SECURITY_EPOCH=<N+1> ...

   The release carries the KEK-signed dbx append in
   `/usr/lib/enklave/efi-updates/` and applies it itself (next section). The
   firmware then refuses the old UKIs, also after a TPM clear.
4. If a vulnerable epoch may have leaked the volume key or TPM authorization,
   also set `HEAL_BELOW` (see below).
5. Epoch budget: 64 epochs (0–63). When it is exhausted, re-provision the
   fleet (factory reset clears the epoch index); plan epochs per security
   release, not per build.

Pre-scheme UKIs (empty policyRef, builds ≤ 2fd8d34) never satisfy P.

### Secure Boot variable updates (dbx, db, KEK) and PCR 7

A dbx, db or KEK change alters PCR 7 from the next boot on, to a value that
depends on the device's firmware. The binding to PCR 7 therefore lives in `V`
and is moved by the release, per device, without ever accepting an unknown
Secure Boot configuration:

1. **Boot A** (new release, old PCR 7 still valid). After the state volume is
   verified, the release finds that its `efi-updates/*.auth` are not yet in
   the firmware. It stores the PCR 7 events of this boot in the state volume,
   rewrites `V` to bind **PCR 0, 2, 4 and 12** (firmware code, option
   ROMs/drivers, every EFI binary on the boot path, no ESP credentials) and
   only then hands the signed update to the firmware. From this moment the
   old PCR 7 is no longer accepted. Status: `pending`.
2. **Boot B** (same UKI, new PCR 7). The same firmware and boot chain started,
   so only genuine code is running. It replays the TCG event log against
   PCR 7 and requires the new PCR 7 events to be identical to the stored ones
   except for the content of the updated variables: Secure Boot still on,
   PK/KEK/db and the signing authority unchanged. Then `V` is rewritten to
   the new PCR 7 + 12. Status: `current`.

Properties:

- **No brick.** A power loss at any point leaves `V` satisfiable by the same
  boot chain; the next boot continues. If the firmware rejects the update, the
  device returns to its PCR 7 binding and reports `failed`. If the firmware's
  event log cannot carry the transition (it does not replay to PCR 7, or the
  variable is not measured exactly once), nothing is changed and the device
  reports `blocked`.
- **No window.** During the transition the device accepts only the same
  firmware, boot loader and UKI. A different Secure Boot configuration (Secure
  Boot off, other keys, other signing authority) is refused in boot B; another
  boot chain satisfies neither binding. The old PCR 7 is never accepted again.
- **Per device.** Nothing is signed per device class: each device records its
  own PCR 7 at provisioning and after each signed update.

The status is in `/run/enklave/efi-updates`, on the serial port and in the
selftest check `efi_updates`. Validate each release with a dbx update on one
device of every hardware class first; `failed` or `blocked` means the durable
revocation is **not** in place on that class.

Operational rules:

- Between boot A and boot B the device must boot the **same UKI**. Do not
  install another update while `efi-updates` says `pending` (Task 7 enforces
  this). If another UKI was booted, boot the previous one again.
- Supported updates are appends to dbx, db and KEK, signed for the enrolled
  KEK/PK. Changing the certificate that signs the boot chain (a new db key
  used for the UKI) changes PCR 7 without a variable update and is not
  supported in place: it requires a factory reset.

### Healing after a compromise

`HEAL_BELOW=N` (baked into the verity-protected `release.json`) makes a
release re-provision every state volume provisioned under an epoch < N on its
first boot: hierarchy policies and authValues are rotated, the salt key is
re-created from the endorsement seed, the volume key, record and counter are
destroyed and recreated, and the state volume is wiped. A key or authorization
obtained under a revoked epoch is useless afterwards.

- The re-created salt key is authenticated like on a first boot (EK
  certificate or signed allowlist) and must have the Name recorded at
  provisioning. Another endorsement key fails closed and nothing is wiped.
- **The wipe applies to every role alike**, including `backup` and
  `fileserver`. What is lost is exactly the state volume `/var/lib/enklave`:
  enrollment and configuration, which are restored through the console
  (re-enrollment). The data volumes of backup and file servers are separate
  volumes and are not touched by healing; their keys must not be kept in the
  state volume alone (Task of the role repos), otherwise healing makes the
  data unreadable.
- A release with both `HEAL_BELOW` and a dbx update heals in boot A and
  completes the PCR 7 transition in boot B.

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
- **dbx/db/KEK appends shipped by a release:** handled, see above.
- **Any other change of PCR 7** (Secure Boot keys changed in the firmware
  setup, a firmware update that measures differently, a new signing
  certificate for the UKI): the device fails closed. Restore the previous
  state or factory-reset.
- **Firmware or boot loader updates while a PCR 7 transition is pending:** not
  allowed (they change PCR 0/2/4).

### Factory reset and interrupted provisioning

Factory reset: clear the TPM in the firmware setup (physical presence; this
wipes all owner objects and re-enables Clear) and delete the `enklave-var`
partition; the next boot provisions a fresh state volume.

An interrupted first boot fails closed at every later boot. Recovery depends
on where it stopped:

| Interrupted | TPM state | Recovery |
|---|---|---|
| before the lock-down (salt key or the indices `0x01800E04`/`0x01800E05` exist, hierarchies not locked) | no secret exists | factory reset (a healing release does **not** help: it never administers an unlocked TPM) |
| after the lock-down (hierarchies locked, any of volume key, volume, counter, record missing) | locked, partial | boot a release with `HEAL_BELOW` > 0, or factory reset |

### Accepted limits (hardware requirements)

These cannot be closed from the operating system:

- **Physical access to the TPM bus.** Salted sessions and the EK check stop a
  passive sniffer and an interposer that substitutes keys. They cannot stop an
  attacker who controls the bus of a discrete TPM completely: such an attacker
  can reset the TPM and replay the measurements of a genuine boot, and then
  satisfies any PCR policy himself. Use a firmware TPM (Intel PTT, AMD fTPM,
  Pluton), which has no external bus, where this attacker is in scope.
- **Platform auth in the clear.** Firmware sets the platform hierarchy auth
  before the OS starts, on common firmware with an unencrypted password
  session. A bus sniffer learns it and can clear the TPM. Impact: denial of
  service (the state volume is lost, nothing is disclosed); after the clear
  old UKIs are stopped only by dbx. Prefer a firmware TPM or firmware that
  protects the platform auth.
- **Revocation by epoch does not survive a TPM clear.** A cleared TPM has no
  memory of revoked epochs. The durable revocation is the dbx update shipped
  with the release (above); its delivery in updates is part of Task 7.
