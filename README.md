# enclave-base

The base image of [Enclave](https://github.com/enclave-system): a minimal,
signed, immutable and amnesic Linux operating system for high-security
devices, built with mkosi on Debian 13 (trixie).

Every Enclave role (reference image, client, server roles) is built on top of
this repository. It provides the hardened kernel, the image layout, the
Secure Boot and measured-boot chain, and the only piece of persistent state a
device has: a small encrypted volume whose key is released by the TPM to a
genuine, non-revoked release only.

## Architecture

- **Kernel.** Linux 6.12 LTS (`kernel/VERSION`), built from the signed
  kernel.org tarball in two flavors, `server` and `client`
  (`kernel/build-kernel.sh`). Hardening is enforced by a rule check
  (`kernel/check_config.py`, `kernel/rules/`) that runs before and after the
  compile: forced lockdown (`confidentiality`), mandatory module signatures,
  strict IOMMU, no debugfs, no debug info. The package is named
  `linux-image-<version>-enclave-<flavor>`.
- **UKI.** Kernel, initrd and the fixed command line are one Unified Kernel
  Image, booted by systemd-boot. The UKI carries a signed PCR 11 policy for
  the boot phase `enter-initrd:leave-initrd` (`mkosi/tools/ukify`). The
  command line cannot be changed and credentials from the ESP, SMBIOS or
  fw_cfg are never imported.
- **Secure Boot.** The UKI and systemd-boot are signed with the Enclave db
  key. Keys are enrolled by the owner (`pki/enclave-pki ovmf-vars` for VMs),
  never auto-enrolled from the ESP. Without Secure Boot the device powers off.
- **dm-verity.** There is no root partition: `/` is a tmpfs, `/usr` is an
  erofs partition protected by a signed dm-verity root hash, with A/B slots
  for systemd-sysupdate. `/etc` is populated from `/usr/share/factory/etc` at
  every boot. Nothing written at runtime survives a reboot, except:
- **/var with TPM.** One 1 GiB LUKS2 partition (`enclave-var`), created on
  the first boot and mounted read-only at `/var/lib/enclave`. Its key lives
  only in a TPM NV index, released under a policy bound to the PCR signing
  key, the role, the profile, PCR 7 (Secure Boot state), PCR 11 (the UKI)
  and PCR 12. The TPM's endorsement key is authenticated against the TPM
  vendor CAs on every boot.
- **State store.** Content of the state volume is authenticated by an HMAC
  manifest whose version is bound to a TPM NV counter, so spliced, older or
  foreign content is refused. Only the state service writes it, through
  writers defined by the image, and only with input the image declares
  (none, or a bundle signed with the config-signing key).
- **Revocation epochs.** Every release carries a security epoch. The first
  boot of a newer release revokes all older epochs in a set-only TPM bit
  field, so older UKIs can no longer open the state volume. `HEAL_BELOW`
  re-provisions devices whose state may have leaked.
- **dbx updates.** A release can ship signed Secure Boot variable updates
  (dbx, db, KEK appends) and applies them itself. The TPM binding of PCR 7 is
  moved across the update per device, enforced by the TPM at every moment,
  so revocation by dbx works without re-provisioning and without a window.
- **Network.** nftables drops everything by default in every direction (role
  repos add their rules); the kernels are built without IPv6.

The details, the exact guarantees and the accepted limits are in
[Security model](#security-model) below.

## Repository layout

| Path | Content |
|---|---|
| `kernel/` | Kernel version, config fragments, hardening rules, build script and its tests |
| `mkosi/` | The base image: mkosi configuration, partition layout, units, nftables, test profile |
| `ref/` | The reference role `ref`: the base image without role content |
| `go/` | `enclave-varauth` (unlock, provisioning, state service), `enclave-selftest`, `enclave-cfg` (config bundles), `enclave-sign-policy` (release signing) |
| `pki/` | `enclave-pki`: key generation, OVMF variable stores, test TPM CA |
| `scripts/` | Build host bootstrap and check, `revoke-release.sh` (signed dbx appends) |
| `SECURITY_EPOCH`, `HEAL_BELOW` | Security epoch of this release line and the healing threshold |

## Building

Builds run on a Linux build host with Debian 13, KVM and passwordless sudo.
Tool versions are pinned in `BUILDHOST.lock`.

    sudo scripts/bootstrap-buildhost.sh   # idempotent
    scripts/check-buildhost.sh            # silent, exit 0 = ready

Create a PKI once (see [PKI](#pki)). For development:

    pki/enclave-pki init --dev ~/enclave-pki-dev
    pki/enclave-pki ek-test-ca ~/enclave-pki-dev     # CA for emulated test TPMs
    export ENCLAVE_PKI_DIR=~/enclave-pki-dev

Make targets:

| Target | Result |
|---|---|
| `make kernel-server`, `make kernel-client` | Kernel debs in `$(KERNEL_OUT)` (default `~/enclave-out`); about 25 minutes each, never rebuilt if present |
| `make go` | The Go tools in `out/bin` |
| `make ref` | Reference image, profile `prod` (production PKI) or `dev` (`ENCLAVE_DEV_PROD=1` with a dev PKI), in `out/ref` |
| `make ref-test` | Reference image with the test profile (selftest, serial console), in `out/ref-test` |
| `make test-unit` | Go vet and tests with the race detector, Python tests |
| `make test-vm` | Tests that need a VM |
| `make clean` | Removes the image outputs and the staging trees |

Variables: `ENCLAVE_PKI_DIR` (PKI directory), `KERNEL_OUT`,
`SECURITY_EPOCH`, `HEAL_BELOW`, `EFI_UPDATES` (signed `.auth` files to apply),
`EK_CERTS` (EK certificates fetched from the TPM vendor), `EK_ADMIT`
(per-device admissions, dev and test only), `REQUIRE_FTPM=1` (firmware TPMs
only), `ENCLAVE_DEV_PROD=1`, `REF_OUT`, `REF_TEST_OUT`.

An image directory holds the disk image (`enclave-ref_<version>.raw`), the
signed UKI (`.efi`) and the signed policy (`.policy.json`), which
`enclave-sign-policy` also writes to the ESP of the image. Check the
signature with `sbverify --cert $ENCLAVE_PKI_DIR/sb/db.crt <uki>.efi`.

## Testing

    make test-unit

runs `go vet`, `go test ./... -race` and the Python tests of the PKI tool and
the kernel config check. A test-profile image (`make ref-test`) runs
`enclave-selftest` at every boot and prints one JSON line per check on the
serial console, ending in `{"check":"done","ok":true}`. It is booted in QEMU
with OVMF (Secure Boot keys enrolled with `pki/enclave-pki ovmf-vars`), swtpm
(EK certificate from the test CA) and a virtual IOMMU (`-device intel-iommu`).
The attacks the design defends against (swapped or spliced state volumes,
snapshot rollback, test UKI against a production state, foreign TPM
objects, Secure Boot changes during an update, power cuts) are exercised in
such VMs. The test profile has pause points and test hooks that exist only
in test-profile images.

Before a hardware model is approved, run the
[hardware bring-up checklist](#hardware-bring-up-checklist).

## Security model

This section states what the base image guarantees, how, and where the
guarantees end. Everything here is enforced in code and fails closed.

### PKI

`pki/enclave-pki init <dir>` generates all signing keys (Secure Boot, dm-verity,
module signing, config signing, update GPG, PCR policy). Protecting that
directory is the operator's job:

- Generate the production PKI on an offline machine.
- Keep the directory mode 0700 on encrypted, offline media.
- Never copy secret keys to the build host or into the repo.
- The dev PKI (`~/enclave-pki-dev` on the build host) is for development only.

- Three profiles exist, and the profile is part of every TPM policy (so the
  state of one can never be opened by another):
  - `prod`: production configuration, production keys. The build refuses to
    sign it with a dev PKI.
  - `dev`: the production configuration signed with a dev PKI
    (`make ENCLAVE_DEV_PROD=1 ref`). For development VMs only.
  - `test`: the test profile (selftest, serial console). Dev PKI only.
- `enclave-pki init --dev <dir>` marks a development PKI (`DEV-KEYS`).
- A build signed with a dev PKI carries a marker that is measured and visible
  at runtime: `"dev_keys":true` in the verity-protected
  `/usr/lib/enclave/release.json` (covered by PCR 11 through the usr root
  hash) and in the release's policy JSON. Such an image prints
  `[DEV KEYS: development build, never ship]` on the serial port at every boot
  and the selftest reports the check `dev_keys`. Production acceptance runs
  `enclave-selftest --forbid-dev-keys`, which fails for a dev-signed build.
  `enclave-sign-policy` refuses to sign an image whose marker does not match
  the PKI.

### Persistent state, /var and the TPM

The root file system is a tmpfs; `/var` is volatile. The **only persistent
storage** is the state volume mounted at `/var/lib/enclave` (1 GiB partition
`enclave-var` on the disk that carries `/usr`):

- LUKS2 `aes-xts-plain64` (512-bit), `hmac-sha256` integrity, argon2id keyslot.
- The 64-byte volume key lives only in TPM NV index `0x01800E02`, read once per
  boot and then read-locked.
- The volume is mounted **read-only**.
- State lives in `/var/lib/enclave/data`. Every commit updates an HMAC
  manifest (path, type, mode, owner, hash of every entry; key derived from
  the volume key) whose version is bound to the TPM NV counter `0x01800E03`.
  Boot fails closed on any spliced, older or foreign content (dm-integrity
  authenticates sectors but not their version). A crash during a commit is
  rolled forward or back at the next boot.

#### The state service: who may write and how to read

`enclave-state.service` (`enclave-varauth state-serve`) is the only writer
and the only holder of the state keys at runtime:

- **Keys.** The unlock step leaves the manifest key and the counter
  authorization in `/run/enclave/state.key`. The state service reads and
  deletes the file before it reports ready, and `local-fs.target` requires
  the service, so no ordinary service ever runs while the file exists.
  Afterwards the keys exist in that process only. The process is not
  dumpable (`PR_SET_DUMPABLE` 0, `LimitCORE=0`), and
  `kernel.yama.ptrace_scope=3` with `lockdown=confidentiality` keeps other
  processes, root included, from reading its memory.
- **Writers are defined by the image.** A commit is not "run this command".
  The caller names a writer, and the command of a writer is fixed in the
  verity-protected `/usr/lib/enclave/state-writers.d/<id>.json`:
  `{"unit": "<x>.service", "input": "<kind>", "exec": [...]}`.
- **Input is verified by the service, not by the writer.** Every writer
  declares what it consumes:
  - `"input": "none"`: the writer gets nothing from the caller. What it
    writes is decided by the image alone.
  - `"input": "signed-bundle"`: the caller passes a 64-byte Ed25519 signature
    followed by an enclave bundle (`enclave-cfg build`, `sign`). Before
    anything runs, the service checks the signature against the
    config-signing key of the image, that the bundle is for this role, and
    that its version is **higher than the last version this writer
    accepted**. That last version is stored inside the authenticated state
    (covered by the manifest MAC and the TPM counter), so it cannot be turned
    back. The writer then gets the verified bundle (`$ENCLAVE_INPUT_BUNDLE`,
    `$ENCLAVE_INPUT_SIG`, `$ENCLAVE_INPUT_VERSION`, and on stdin).
    A bundle is bound to the role and to its version, not to a writer, so an
    image defines at most one signed-bundle writer (enforced by the service
    and the image build); otherwise a bundle signed for one writer could be
    handed to another.

  A writer without one of these declarations is refused by the service and
  by the image build (`mkosi.finalize`). The test profile alone may declare
  `"unverified"`.
- **Callers are separated by unit.** The service takes the caller's identity
  from the kernel (`SO_PEERCRED`, `SO_PEERPIDFD`): uid 0, and the process must
  be in the cgroup `/system.slice/<unit>` of the unit the writer is reserved
  for. The whole cgroup path is compared; a cgroup that merely carries the
  unit's name somewhere else does not count. Another service, a root shell or
  a transient unit (`systemd-run`) is refused.
- **The volume is writable only inside the service** (`PrivateMounts=yes`),
  for the duration of one commit.
- **Reads are authenticated.** `enclave-varauth state-read <path>` (package
  `varauth`, `StateCall`) returns a file only after checking the manifest
  MAC, the manifest version against the TPM counter and the file's hash.
  Consumers read state this way; the base image's own consumers do (the
  selftest). A write that bypassed the service is therefore detected at the
  next read, not only at the next boot.

Usage: `enclave-varauth state-exec <writer> < input`,
`enclave-varauth state-read <path>`, `enclave-varauth state-status`.

What this guarantees, exactly:

- **No process can forge state content that the system accepts**, root
  included. There are three ways to try, and each ends the same way:
  1. Writing the volume directly (own mount namespace, block device): the
     process has no state keys, so every authenticated read and the next
     boot refuse the result.
  2. Calling the service from the wrong place: refused (unit separation).
  3. Calling the service from the right place. The unit separation is **not**
     a boundary against root: a root process can move itself into the cgroup
     of the reserved unit, or have systemd start that unit differently
     (systemd honours drop-ins from `/etc` and `/run` and requests from
     uid 0; it has no switch that forbids this to root). Such a process can
     **trigger** a writer. It cannot choose what the writer consumes: a
     writer either takes no input, or only a bundle signed with the
     config-signing key, for this role, newer than the last one. Replaying an
     old signed bundle is refused by the version check.
- What root can therefore do is run an image-defined writer once more with
  no input, or deliver a genuine, newer signed bundle earlier than its
  intended transport would have. Neither puts content into the state that
  the signer did not sign or the image did not define.
- The keys can leave the service only through a kernel compromise.

Requirement for the role repos: a writer with `"input": "none"` must not
derive what it writes from anything a local process controls (files in
`/run`, environment, network input); such data needs a signed bundle. Role
services should still not run as root (`User=`, `ProtectSystem=strict`, no
`CAP_SYS_ADMIN`); the guarantees above do not depend on it.

#### TPM policy and ownership

The volume key, the record, the administration of the counter and the owner,
endorsement and lockout hierarchies are governed by

    P = PolicyAuthorizeNV(V)
    V = PolicyAuthorize(PCR key, "enclave-var-v1:<role>:<profile>") + PolicyPCR(7 = recorded, 12 = 0)
        (during a signed Secure Boot update: a PolicyOR over two to four such
        digests, each for one exact PCR 7 value)

`V` is the NV index `0x01800E05`. It holds the PCR-bound part of the policy
and can be written only through the owner hierarchy, that is, under P itself.
The Name of `V` (and with it P) is bound to the PCR signing key, role and
profile.

Two indices have their own policies:

- `T` `0x01800E06`, the record of Secure Boot variable updates (the exact
  states `V` admits during an update, and the monotonic per-update record),
  is written through the owner hierarchy like `V` (under P only).
- The revocation bits `0x01800E04`: bits can be set by any approved UKI of the
  same role and profile (`PolicyAuthorize` alone) and never cleared.
- The counter `0x01800E03`: read and incremented at runtime with an authValue
  derived from the volume key; that authValue can be set under P only.

The authorized part is the release's signed approved policy
(`/EFI/enclave/policy/<uki>.json` on the ESP, made by `enclave-sign-policy`):
PCR 11 of exactly that UKI in the phase `enter-initrd:leave-initrd`, and its
**security epoch** not revoked in the bits index `0x01800E04`. Role and profile
are part of the policyRef, so a test-profile UKI cannot open a production
volume and one role cannot open another's.

There is no administrative secret. The first boot on a fresh TPM runs in this
order:

1. The platform is checked. DMA remapping is active (IOMMU, see "Why PCR 1
   is not bound"). The TPM implements `TPM2_PolicyAuthorizeNV` and holds no
   object that is not enclave's or the vendor's. The firmware's event log
   replays to PCR 7 and measures db, dbx and KEK exactly once each and
   verbatim (otherwise the device could not take a signed dbx update later
   under an exact PCR 7 binding; it is not enrolled).
2. The TPM's endorsement key is authenticated (next section) and persisted as
   the salt key `0x81000E01`.
3. The three indices that hold no secret are defined with the still-empty
   owner auth: the revocation bits `0x01800E04`, `V` `0x01800E05` (holding
   the Secure Boot state of this boot) and `T` `0x01800E06` (record of
   Secure Boot variable updates, empty).
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
secret in this TPM is a guessable authValue. All enclave authValues are
256-bit random values and all enclave indices are `NO_DA`. **Every unlock, in
every profile, fails closed before it touches the lockout if the TPM holds
any object enclave does not account for** (anything outside the enclave
indices, the salt key, the vendor's EK certificates and keys, and the storage
root key that systemd creates with an empty authValue); first provisioning
does the same. The selftest check `tpm_locked` reports the same condition and
that the lockout is disabled.

#### TPM authenticity: endorsement key certificate

The salt key is the TPM's endorsement key (EK, TCG default template, ECC P-256
or RSA 2048). Its public area is never taken on trust from the TPM bus. On
**every boot** (first provisioning, healing and normal boots):

- the EK certificate is read from the TPM (NV `0x01C0000A` ECC, `0x01C00002`
  RSA; intermediate certificates from NV `0x01C00100`–`0x01C001FF`), or, for
  TPMs that do not carry it, from `ESP:/EFI/enclave/ekcert/` (below), and
  must chain to a TPM vendor CA in `/usr/share/enclave/tpm-ek-ca` (AMD, Atmel,
  Infineon, Intel, NationZ, Nuvoton, Qualcomm, STMicro; provenance in
  `SOURCE`, hashes in `SHA256SUMS`);
- the certificate must be an EK certificate as the TCG EK Credential Profile
  defines it. This is mandatory: extended key usage `tcg-kp-EKCertificate`
  (2.23.133.8.1), not excluded by an issuing CA that restricts its usages;
  or, only if the certificate carries no extended key usage at all, a
  certificate policy from the TCG arc (2.23.133). A certificate with other
  usages only, or with neither mark, is refused. In addition the
  subjectAltName must name the TPM manufacturer, model and version;
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
- **The test CA.** `enclave-pki ek-test-ca` creates a CA for the emulated TPMs
  of the VM tests (`swtpm_setup --create-ek-cert`). Its certificates go into
  test-profile images only (`/usr/share/enclave/tpm-ek-ca-test`); the build
  asserts that other images do not contain them, and the runtime reads them
  in the test profile only.
- **SHA-1 signed EK certificates** of TPMs from before 2016.

**Firmware TPM required (`REQUIRE_FTPM=1`, `require_ftpm` in the signed
`release.json`).** When set, only EK certificates of firmware-TPM vendors are
accepted (AMD fTPM and Pluton, Intel PTT, Qualcomm); certificates of
discrete-TPM vendors (Atmel, Infineon, NationZ, Nuvoton, STMicro) are
refused, from the TPM and from the ESP alike, and so is every device without
a vendor certificate (an admission proves nothing about the kind of TPM). A
discrete TPM has a bus that can be tapped and reset; a firmware TPM has none.

- Role `client` **must** be built with it. `enclave-sign-policy` refuses to
  sign, `mkosi.finalize` refuses to build and the unlock step refuses to run
  a client release without it. Only test-profile builds (emulated TPMs in
  VMs) are exempt.
- For other roles it is a per-role decision; default off in this base repo
  (the reference role runs in VMs and on servers whose TPM is discrete).

**TPMs that do not carry their EK certificate: certificate on the ESP.** Some
firmware TPMs keep no certificate in NV (AMD fTPM, Intel PTT on some
platforms); the vendor publishes it through a web service keyed by the EK
public key. Fetch it once per device, out of band (`enclave-varauth ek-name`
prints the EK Names; `tpm2_createek -G ecc -c ek.ctx -u ek.pub` gives the
public key the vendor service asks for), and ship it with the release:

    make EK_CERTS=<dir with *.cer / *.pem> ...

`enclave-sign-policy` copies the files to `ESP:/EFI/enclave/ekcert/`. The
location gives them no authority. The device verifies each one exactly like
a certificate from NV (vendor CA, EK usage, TPM attributes, `require_ftpm`),
and its endorsement key must be the key of one of the verified certificates.
A device authenticated this way uses the same policyRef as one with the
certificate in NV. A directory with the certificates of a whole fleet works:
every device finds its own.

**Production accepts vendor-certified endorsement keys only.** This is
enforced in code: `enclave-sign-policy` refuses to sign a per-device
admission for a `prod` image, and a `prod` release ignores any admission it
finds. The reason: whoever signs an admission cannot tell the Name of an
emulated TPM (whose private key is a file) from the Name of a real one. A
vendor certificate can.

**Per-device admission (dev and test builds only).** The emulated TPMs of
development VMs have no certificate that a non-test image trusts. Such a
device is admitted individually, by a signature, never by a list in the
image:

- `make EK_ADMIT=<file>` (one EK Name per line) lets `enclave-sign-policy`
  sign, for each Name, one additional policy for the policyRef derived from
  `enclave-var-v1:<role>:<profile>` and that Name (a digest: `ek1:<base64>`).
  It is stored next to the release's policy on the ESP. No image contains an
  allowlist (asserted by the build).
- The device computes the Name of its own EK, looks for the policy signed
  for exactly that ref, and binds all its TPM objects to that ref.
- **An admission cannot be used elsewhere.** On another device it names a key
  that TPM does not hold, so no salted session works. A device that was
  provisioned through an EK certificate is bound to the base ref: if an
  interposer hides its certificate and presents an admitted key, the device
  ends up under another ref, whose policy opens none of its objects.
- A TPM with a valid certificate is never matched against admissions.
- Not available with `require_ftpm`.

#### Security epochs: revoking a vulnerable release

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
   `/usr/lib/enclave/efi-updates/` and applies it itself (next section). The
   firmware then refuses the old UKIs, also after a TPM clear.
4. If a vulnerable epoch may have leaked the volume key or TPM authorization,
   also set `HEAL_BELOW` (see below).
5. Epoch budget: 64 epochs (0–63). When it is exhausted, re-provision the
   fleet (factory reset clears the epoch index); plan epochs per security
   release, not per build.

UKIs from before the policyRef scheme (empty policyRef) never satisfy P.

#### Secure Boot variable updates (dbx, db, KEK) and PCR 7

A dbx, db or KEK change alters PCR 7 from the next boot on. The binding to
PCR 7 therefore lives in `V` and is moved by the release, per device. **PCR 7
is bound at every moment, and the TPM enforces it**: `V` holds either the
exact PCR 7 + 12 of the device, or, while a signed update is in transit, a
`PolicyOR` over a short list of exact PCR 7 + 12 values.

**Boot A** (new release, old PCR 7 still valid). After the state volume is
verified, the release takes its `efi-updates/*.auth` that are not yet in the
firmware, one at a time:

1. It computes the PCR 7 value of the next boot in advance: the events of
   this boot, with the measurement of the updated variable replaced by the
   measurement of "current content plus the update". Two forms are computed,
   because firmware stores an append in one of two ways: edk2 drops entries
   the variable already holds, other firmware appends the update as it is.
2. It records the transition in the NV index `T` (`0x01800E06`, writable
   under P only) and sets `V` to the list: the state before the transition,
   the current state, and the computed ones.
3. It hands the update to the firmware and **reads the variable back**.
   - Unchanged: the firmware refused the update. Nothing is pending for it.
   - Changed: the variable must hold exactly its old signatures plus the
     update's. `V` is narrowed to two values: the state before the
     transition and the exact value computed from what was read back.

Status: `pending`. What `T` and `V` record is always what was read back from
the firmware, never what was sent. If the firmware takes only some of the
updates (for example a full dbx), the next boot is still one of the listed
states.

**Boot B.** The TPM releases the volume key only if PCR 7 + 12 of this boot
is one of the values in `V`; any other Secure Boot state gets no policy
session. Independently, and also **before the volume key is read**, the boot
replays the event log against PCR 7 and compares the Secure Boot state with
the states `T` pins (before the update, or that state plus exactly the signed
update: nothing dropped from dbx, nothing else added, Secure Boot on, PK,
KEK, db and the signing authority unchanged). Then:

- New state: `V` is set to it alone. Status: `current`.
- Old state, and the firmware had held the update in boot A: the variable
  store was rolled back. `V` returns to the old state alone. Status:
  `failed`.

Properties:

- **Enforced by the TPM, not by a check.** During the transition a boot with
  Secure Boot off, another key, a dropped dbx entry or any other PCR 7 value
  cannot build a policy session that `V` accepts. An attacker who patches the
  software check out of memory, or who answers `TPM2_PCR_Read` falsely on the
  bus, gains nothing: the TPM compares its own PCR 7.
- **One shot, and the record is monotonic.** `T` keeps a record per update
  (16-byte digest of the `.auth` file): how often the transition was armed
  for it, and whether the firmware variable ever held it. An update that the
  firmware held and lost again (the variable store was rolled back, e.g. by
  rewriting the SPI flash) is **never armed again**, by this or any other
  release. An update that was armed and never taken (power cut before the
  firmware wrote it) is armed at most three times. An entry is removed only
  while the firmware holds the update and `V` is bound to that state. A
  release without updates does not touch the record; a release with more
  updates adds entries and keeps the others.
- **No brick.** A power loss at any point leaves the firmware in one of the
  listed states: before the write the old one, after it one of the computed
  ones. A refused update changes nothing. A partially accepted set of
  updates is recorded as accepted. One case cannot be closed from the
  operating system: firmware that stores an append in a form that is neither
  of the two computed ones, **and** a power loss in the milliseconds between
  the firmware's write and the narrowing of `V` in the same boot. The TPM
  cannot be told to accept a value nobody knows yet; accepting unknown
  values would reopen the window that the exact binding closes. Without the
  power loss such firmware is handled (the exact value is read back and
  recorded); with it the device fails closed and needs a factory reset.
- **Firmware that cannot carry this is not enrolled.** First provisioning and
  healing require: the event log replays to PCR 7; db, dbx and KEK are
  measured exactly once each as signature lists; each is measured verbatim
  (the measurement is the digest of the variable as the variable store
  returns it), so that the next PCR 7 can be computed. A device that passed
  cannot end up unable to take a revocation later (status `blocked`) unless
  its firmware is changed.
- **Per device.** Nothing is signed per device class: each device records its
  own PCR 7 at provisioning and after each signed update.

**Status, visible in production.** Every boot writes
`/run/enclave-status/secure-boot-updates.json` (world-readable:
`{"status": "current|pending|failed|blocked", "ok": bool, "detail": ...}`),
for the console to collect. `failed` and `blocked` are also logged as a
critical journal message (`SECURE BOOT UPDATE NOT IN PLACE`) and on the
serial port; the selftest check `efi_updates` reports them in test builds.
`failed` or `blocked` means the durable revocation is **not** in place on
that device. After a detected rollback the device keeps running on its
verified old Secure Boot state: nothing is disclosed, and it is reported.

Operational rules:

- Supported updates are appends to dbx, db and KEK, signed for the enrolled
  KEK/PK. Changing the certificate that signs the boot chain (a new db key
  used for the UKI) changes PCR 7 without a variable update and is not
  supported in place: it requires a factory reset.
- Any release of the same role, profile and a non-revoked epoch can complete
  a pending transition; the same UKI is not required.

#### Why PCR 1 is not bound, and what is enforced instead

PCR 1 holds the firmware's configuration data: boot order and boot entries,
SMBIOS and ACPI tables, and whatever setup options a vendor chooses to
measure. It is not bound:

- It changes for harmless reasons (a boot entry rewritten by the firmware, a
  memory module replaced, a firmware setting touched), and its content is
  vendor specific. Binding it would make devices fail closed at random.
- What an attacker gains from changing those settings is covered elsewhere.
  Booting other code (boot order, external media, network boot) is stopped
  by Secure Boot and changes PCR 11 of the UKI. Disabling Secure Boot or
  changing its keys changes PCR 7.
- The setting that matters and that firmware may measure into PCR 1 only, or
  not at all, is the IOMMU (VT-d / AMD-Vi). **This is enforced directly**:
  before the volume key is read, and before a device is provisioned, the
  unlock step requires that the firmware describes an IOMMU (ACPI DMAR or
  IVRS), that the kernel runs it (`/sys/class/iommu`), and that every device
  group is translated (no identity/passthrough domain). Otherwise it fails
  closed. The kernel is built and started to demand DMA remapping
  (`iommu=force intel_iommu=on amd_iommu=force_isolation`,
  `CONFIG_IOMMU_DEFAULT_DMA_STRICT`); the check is what refuses the key when
  the platform does not deliver it.
- Debug interfaces and other vendor settings that no PCR and no kernel
  interface reports must be locked with a supervisor password on the
  firmware setup (hardware requirement, see below).

#### Healing after a compromise

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
  `fileserver`. What is lost is exactly the state volume `/var/lib/enclave`:
  enrollment and configuration, which are restored through the console
  (re-enrollment). The data volumes of backup and file servers are separate
  volumes and are not touched by healing; their keys must not be kept in the
  state volume alone (a requirement for the role repos), otherwise healing
  makes the data unreadable.
- A release with both `HEAL_BELOW` and a dbx update heals in boot A and
  completes the PCR 7 transition in boot B.

#### Recovery: tainted PCR 12

systemd-stub measures credentials (`*.cred`), addons and command line
overrides found on the (unauthenticated) ESP into PCR 12; the state volume is
bound to PCR 12 = 0, so a stray or planted file such as
`\loader\credentials\*.cred` or `\EFI\Linux\<uki>.efi.extra.d\*` makes the
machine power off at every boot. Remove the files from the ESP (from another
system) and boot again.

#### Impact of key and firmware changes

- **PCR signing key:** the hierarchies and indices are bound to it. A new key
  requires a factory reset; revoke releases with epochs, not new keys.
- **dbx/db/KEK appends shipped by a release:** handled, see above.
- **Any other change of PCR 7** (Secure Boot keys changed in the firmware
  setup, a firmware update that measures differently, a new signing
  certificate for the UKI): the device fails closed. Restore the previous
  state or factory-reset.
- **Firmware updates** that change how or what the firmware measures into
  PCR 7: the device fails closed, also while a transition is pending.

#### Factory reset and interrupted provisioning

Factory reset: clear the TPM in the firmware setup (physical presence; this
wipes all owner objects and re-enables Clear) and delete the `enclave-var`
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
  with the release (above); delivering it with system updates is the job of
  the update mechanism.
- **Firmware setup.** Settings that neither a bound PCR nor the kernel
  reports (debug interfaces, vendor options; see "Why PCR 1 is not bound")
  must be protected by a supervisor password. The IOMMU is not among them:
  it is checked on every boot.

### Hardware bring-up checklist

Everything above is proven on QEMU, OVMF and swtpm. Before a hardware model
is approved, check on one device (a test-profile build prints the reasons on
the serial port; each item fails closed if it does not hold):

1. **EK certificate.** The TPM carries one in NV, or the vendor service
   delivers one. It chains to a CA in `/usr/share/enclave/tpm-ek-ca`, and it
   is marked as an EK certificate (extended key usage 2.23.133.8.1, or no
   extended key usage and a TCG certificate policy) with TPM manufacturer,
   model and version in the subjectAltName. If a vendor's certificates
   carry neither mark, the model is not supported; do not relax the check.
2. **TPM.** `TPM2_PolicyAuthorizeNV` present; an NV index of 496 bytes can be
   defined; the dictionary-attack recovery time can be set to 0; no foreign
   NV index or persistent key is present after a TPM clear.
3. **Event log.** Replays to PCR 7; db, dbx and KEK measured once each,
   verbatim.
4. **Variable update.** A signed dbx append is stored in one of the two
   computed forms (status goes `pending`, then `current`, and the `pending`
   status carries no note "not predicted").
5. **IOMMU.** ACPI DMAR or IVRS present with VT-d / AMD-Vi enabled; all IOMMU
   groups of type `DMA`.
6. **PCR 7 stable** across reboots and across a firmware setup visit without
   changes.

## License

Apache License 2.0, see [LICENSE](LICENSE). Redistributions and derivative
works must keep the [NOTICE](NOTICE) file.
