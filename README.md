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

- Three profiles exist, and the profile is part of every TPM policy (so the
  state of one can never be opened by another):
  - `prod`: production configuration, production keys. The build refuses to
    sign it with a dev PKI.
  - `dev`: the production configuration signed with a dev PKI
    (`make ENKLAVE_DEV_PROD=1 ref`). For development VMs only.
  - `test`: the test profile (selftest, serial console). Dev PKI only.
- `enklave-pki init --dev <dir>` marks a development PKI (`DEV-KEYS`).
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
- The volume is mounted **read-only**.
- State lives in `/var/lib/enklave/data`. Every commit updates an HMAC
  manifest (path, type, mode, owner, hash of every entry; key derived from
  the volume key) whose version is bound to the TPM NV counter `0x01800E03`.
  Boot fails closed on any spliced, older or foreign content (dm-integrity
  authenticates sectors but not their version). A crash during a commit is
  rolled forward or back at the next boot.

### The state service: who may write and how to read

`enklave-state.service` (`enklave-varauth state-serve`) is the only writer
and the only holder of the state keys at runtime:

- **Keys.** The unlock step leaves the manifest key and the counter
  authorization in `/run/enklave/state.key`. The state service reads and
  deletes the file before it reports ready, and `local-fs.target` requires
  the service, so no ordinary service ever runs while the file exists.
  Afterwards the keys exist in that process only. `kernel.yama.ptrace_scope=3`
  and `lockdown=confidentiality` keep other processes, root included, from
  reading its memory.
- **Writers are defined by the image.** A commit is not "run this command".
  The caller names a writer, and the command of a writer is fixed in the
  verity-protected `/usr/lib/enklave/state-writers.d/<id>.json`
  (`{"unit": "<x>.service", "exec": [...]}`). The caller can pass input on
  stdin; checking that input is the writer's job (`enklave-cfg`, for example,
  accepts signed bundles only).
- **Callers are authorized.** The service takes the caller's identity from
  the kernel (`SO_PEERCRED`, `SO_PEERPIDFD`): uid 0, and the process must run
  in the systemd unit the writer is reserved for (cgroup of the peer). A
  root shell, another service or a transient unit (`systemd-run`) is refused.
- **The volume is writable only inside the service** (`PrivateMounts=yes`),
  for the duration of one commit.
- **Reads are authenticated.** `enklave-varauth state-read <path>` (package
  `varauth`, `StateCall`) returns a file only after checking the manifest
  MAC, the manifest version against the TPM counter and the file's hash.
  Consumers read state this way; the base image's own consumers do (the
  selftest). A write that bypassed the service is therefore detected at the
  next read, not only at the next boot.

Usage: `enklave-varauth state-exec <writer> < input`,
`enklave-varauth state-read <path>`, `enklave-varauth state-status`.

What this does and does not guarantee:

- A process without the state keys cannot produce state that the system
  accepts. Bypassing the mount (own mount namespace, block device) only
  yields content that every authenticated read and the next boot refuse.
- The keys can leave the service only through a kernel compromise. A root
  process cannot attach to it, read its memory, or read kernel memory.
- A root process **can** still replace how an allowed unit is started: systemd
  honours unit drop-ins from `/etc` and `/run` (both tmpfs), and its private
  socket accepts any request from uid 0. systemd has no switch that forbids
  this to root, so it cannot be closed in the base image. Such a process can
  then *trigger* a writer with input of its choice; it still cannot make the
  service run anything but the image's writer commands. Therefore:
  - writers must validate their input (signatures), and
  - **role services must not run as root and must have no access to the
    systemd bus or private socket** (`User=`, `PrivateUsers=`,
    `ProtectSystem=strict`, no `CAP_SYS_ADMIN`). This is a requirement for
    the role repos; the base image itself has no login, no interactive root
    and starts no service outside its own verity-protected units.

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

- `T` `0x01800E06`, the transition state, is written through the owner
  hierarchy like `V` (under P only).
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

1. The platform is checked: the TPM implements `TPM2_PolicyAuthorizeNV`, and
   the firmware's event log replays to PCR 7 and measures db, dbx and KEK
   exactly once each (otherwise the device could not take a signed dbx update
   later; it is not enrolled).
2. The TPM's endorsement key is authenticated (next section) and persisted as
   the salt key `0x81000E01`.
3. The three indices that hold no secret are defined with the still-empty
   owner auth: the revocation bits `0x01800E04`, `V` `0x01800E05` (holding
   the Secure Boot state of this boot) and `T` `0x01800E06` (state of a
   Secure Boot variable update in transit, idle).
4. The hierarchies are locked: policy P, random discarded authValues,
   `TPM2_Clear` disabled.
5. Only then the indices that protect data are created, each authorized by P:
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
first salted session.

This is a decision, not an oversight. The alternative, a `noDA` salt key that
is bound to the EK with MakeCredential/ActivateCredential, does not avoid it:
ActivateCredential uses the EK's private key too, so the TPM counts power
losses in exactly the same way, and it would have to run on every boot (the
binding must be re-checked on every boot, or an interposer swaps the salt
key). The lockout would still have to be reset under policy P each boot. What
makes disabling it sound is an invariant, and the invariant is enforced: no
secret in this TPM is a guessable authValue. All enklave authValues are
256-bit random values and all enklave indices are `NO_DA`; the selftest check
`tpm_locked` fails if the lockout is still enabled **or if the TPM holds any
object enklave does not account for** (anything outside the enklave indices,
the salt key, the vendor's EK certificates and keys, and the storage root
key that systemd creates with an empty authValue).

### TPM authenticity: endorsement key certificate

The salt key is the TPM's endorsement key (EK, TCG default template, ECC P-256
or RSA 2048). Its public area is never taken on trust from the TPM bus. On
**every boot** (first provisioning, healing and normal boots):

- the EK certificate is read from the TPM (NV `0x01C0000A` ECC, `0x01C00002`
  RSA; intermediate certificates from NV `0x01C00100`–`0x01C001FF`) and must
  chain to a TPM vendor CA in `/usr/share/enklave/tpm-ek-ca` (AMD, Atmel,
  Infineon, Intel, NationZ, Nuvoton, Qualcomm, STMicro; provenance in
  `SOURCE`, hashes in `SHA256SUMS`);
- the certificate must be an EK certificate as the TCG EK Credential Profile
  defines it: extended key usage `tcg-kp-EKCertificate` (2.23.133.8.1), not
  excluded by an issuing CA that restricts its usages, and a subjectAltName
  that names the TPM manufacturer, model and version;
- the EK public area is rebuilt locally from the default template and the
  certificate's public key; the key in the TPM must be exactly that key;
- sessions are started from a locally built key reference, so the TPM tools
  never ask the TPM for the public key again.

A TPM without a valid certificate (missing, foreign CA, expired, not an EK
certificate, certificate of another key) **fails closed**; nothing is
provisioned. Certificate validity is checked against the clock; a clock
earlier than the build time of the release (dead RTC battery) is replaced by
the build time.

Name constraints on issuing CAs are not added: the trust anchors are the
vendors' dedicated EK issuing CAs themselves, and what they may issue is
restricted by the two checks above (usage and TPM attributes), which
`crypto/x509` name constraints cannot express for a directoryName.

Not accepted on purpose:

- **Virtual TPMs.** The Microsoft CA that certifies Hyper-V/Azure virtual TPMs
  is not shipped.
- **The test CA.** `enklave-pki ek-test-ca` creates a CA for the emulated TPMs
  of the VM tests (`swtpm_setup --create-ek-cert`). Its certificates go into
  test-profile images only (`/usr/share/enklave/tpm-ek-ca-test`); the build
  asserts that other images do not contain them, and the runtime reads them
  in the test profile only.
- **SHA-1 signed EK certificates** of TPMs from before 2016.

**Firmware TPM required (`REQUIRE_FTPM=1`, `require_ftpm` in the signed
`release.json`).** When set, provisioning also refuses EK certificates of
discrete-TPM vendors (Atmel, Infineon, NationZ, Nuvoton, STMicro) and accepts
only firmware-TPM vendors (AMD fTPM and Pluton, Intel PTT, Qualcomm). A
discrete TPM has a bus that can be tapped and reset; a firmware TPM has none.
Default: **off in this base repo** (the reference role runs in VMs and on
servers whose TPM is discrete); **role repos set it, and the client role must
set it**, because notebooks are the devices an attacker gets physical access
to.

**TPMs without an EK certificate: per-device admission.** Some firmware TPMs
keep no certificate in NV (AMD fTPM, Intel PTT on some platforms), and the
emulated TPMs of development VMs have none that a non-test image trusts.
Such a device is admitted individually, by a signature, never by a list in
the image:

- `make EK_ADMIT=<file>` (one EK Name per line) lets `enklave-sign-policy`
  sign, for each Name, one additional policy for the policyRef
  derived from `enklave-var-v1:<role>:<profile>` and that Name (a digest:
  `ek1:<base64>`). It is stored next to the
  release's policy on the ESP. No image contains an allowlist (asserted by
  the build).
- The device computes the Name of its own EK, looks for the policy signed
  for exactly that ref, and binds all its TPM objects to that ref.
- **An admission cannot be used elsewhere.** On another device it names a key
  that TPM does not hold, so no salted session works. A device that was
  provisioned through an EK certificate is bound to the base ref: if an
  interposer hides its certificate and presents an admitted key, the device
  ends up under another ref, whose policy opens none of its objects.
- **A TPM with a valid certificate is never matched against admissions.**
- **Emulated TPMs** (their private key is a file) may be admitted for the
  `dev` and `test` profiles only. The tool cannot tell an emulated TPM's Name
  from a real one, so for `prod` this is an operator rule, and
  `enklave-sign-policy` prints a warning whenever it signs an admission with
  production keys: read the Name on the real device, before provisioning, in
  a trusted environment (`enklave-varauth ek-name`, or
  `tpm2_createek -G ecc -c ek.ctx -u ek.pub` and the `name` line of
  `tpm2_readpublic -c ek.ctx`).
- `require_ftpm` does not apply to admissions: the operator vouches for the
  device.

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

A dbx, db or KEK change alters PCR 7 from the next boot on. The binding to
PCR 7 therefore lives in `V` and is moved by the release, per device, without
ever accepting a Secure Boot state it has not pinned in advance:

1. **Boot A** (new release, old PCR 7 still valid). After the state volume is
   verified, the release finds that its `efi-updates/*.auth` are not yet in
   the firmware. From the event log of this boot it computes two digests:
   the Secure Boot state as it is, and that state with exactly the signatures
   of the signed update added to the updated variable. It writes both into
   the NV index `T` (`0x01800E06`, writable under P only), rewrites `V` to
   bind **PCR 0, 2, 4 and 12** (firmware code, option ROMs/drivers, every EFI
   binary on the boot path, no ESP credentials), hands the update to the
   firmware and marks `T` "applied". Status: `pending`.
2. **Boot B** (same UKI). **Before the volume key is read**, the boot replays
   the event log against PCR 7 and computes the digest of the Secure Boot
   state of this boot. It must equal one of the two digests in `T`:
   - the state before the update (the firmware has not taken it yet), or
   - that state plus exactly the signed update: nothing dropped from dbx,
     nothing else added, Secure Boot on, PK, KEK, db and the signing
     authority unchanged.

   Anything else is refused at this point; the volume key stays in the TPM.
   If the update is in the firmware, `V` is rewritten to the new PCR 7 + 12
   and `T` is cleared. Status: `current`.

Properties:

- **No window.** While `V` binds the boot chain, the Secure Boot state is not
  free: only the two pinned states unlock. Secure Boot off, another key, a
  dropped dbx entry or a disabled protection that the firmware measures into
  PCR 7 all fail before the key is read.
- **One shot.** If an update that was marked applied is missing again (the
  variable store was rolled back, e.g. by rewriting the SPI flash), the
  device returns to its old PCR 7 binding, remembers "rolled back" in `T`
  and does **not** open the transition again for this update, however often
  the rollback is repeated. Status: `failed`.
- **No brick.** A power loss before the firmware took the update is retried
  (the state is then exactly the old one). If the firmware rejects the
  update, the device returns to its PCR 7 binding and reports `failed`.
- **Firmware that cannot carry this is not enrolled.** First provisioning and
  healing require the event log to replay to PCR 7 and to measure db, dbx
  and KEK exactly once each as signature lists. A device that passed cannot
  end up unable to take a revocation later (status `blocked`) unless its
  firmware is changed.
- **Per device.** Nothing is signed per device class: each device records its
  own PCR 7 at provisioning and after each signed update.

The status is in `/run/enklave/efi-updates`, on the serial port and in the
selftest check `efi_updates`. `failed` means the durable revocation is **not**
in place on that device.

Operational rules:

- Between boot A and boot B the device must boot the **same UKI**. Do not
  install another update while `efi-updates` says `pending` (Task 7 enforces
  this). If another UKI was booted, boot the previous one again.
- Supported updates are appends to dbx, db and KEK, signed for the enrolled
  KEK/PK. Changing the certificate that signs the boot chain (a new db key
  used for the UKI) changes PCR 7 without a variable update and is not
  supported in place: it requires a factory reset.

### Why PCR 1 is not bound

PCR 1 holds the firmware's configuration data: boot order and boot entries,
SMBIOS and ACPI tables, and whatever setup options a vendor chooses to
measure. It is bound neither in the steady state nor during a transition:

- It changes for harmless reasons (a boot entry rewritten by the firmware, a
  memory module replaced, a firmware setting touched), and its content is
  vendor specific. Binding it would make devices fail closed at random.
- What an attacker gains from changing those settings is covered elsewhere.
  Booting other code (boot order, external media, network boot) changes
  PCR 4 or PCR 7 and the Secure Boot guard; unsigned option ROMs and drivers
  change PCR 2. Disabling Secure Boot or its keys changes PCR 7. "DMA
  protection disabled" is measured into PCR 7 by firmware that follows the
  TCG PC Client Platform Firmware Profile.
- What is **not** covered by any PCR enklave binds: a firmware that lets
  someone switch off the IOMMU (VT-d/AMD-Vi) or enable a debug interface and
  measures that into PCR 1 only, or not at all. This is not left to PCR 1.
  The kernel is built and started to enforce DMA remapping
  (`iommu=force intel_iommu=on amd_iommu=force_isolation`,
  `CONFIG_IOMMU_DEFAULT_DMA_STRICT`), and the firmware setup must be locked
  with a supervisor password (hardware requirement, see below).

### Healing after a compromise

`HEAL_BELOW=N` (baked into the verity-protected `release.json`) makes a
release re-provision every state volume provisioned under an epoch < N on its
first boot: hierarchy policies and authValues are rotated, the salt key is
re-created from the endorsement seed, the volume key, record and counter are
destroyed and recreated, and the state volume is wiped. A key or authorization
obtained under a revoked epoch is useless afterwards.

- The re-created salt key is authenticated like on a first boot (EK
  certificate or the signed admission of the device) and must have the Name recorded at
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
  satisfies any PCR policy himself. The enforceable countermeasure is
  `REQUIRE_FTPM=1` (above): such a release provisions firmware TPMs only.
- **Platform auth in the clear.** Firmware sets the platform hierarchy auth
  before the OS starts, on common firmware with an unencrypted password
  session. A bus sniffer learns it and can clear the TPM. Impact: denial of
  service (the state volume is lost, nothing is disclosed); after the clear
  old UKIs are stopped only by dbx. `REQUIRE_FTPM=1` removes the bus.
- **Revocation by epoch does not survive a TPM clear.** A cleared TPM has no
  memory of revoked epochs. The durable revocation is the dbx update shipped
  with the release (above); its delivery in updates is part of Task 7.
- **Firmware setup.** Settings that the firmware does not measure into a PCR
  enklave binds (see "Why PCR 1 is not bound") must be protected by a
  supervisor password.
