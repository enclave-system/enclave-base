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

## Encrypted /var and the TPM

`/var` is the only persistent state.

**Volume.** On first boot it is created on the disk that carries `/usr` as LUKS2:
- `aes-xts-plain64`, 512-bit key
- `hmac-sha256` integrity, so tampered sectors fail to read
- argon2id keyslot

**Key.** The 64-byte key lives only in TPM NV index `0x01800E02`. That index can be read only with policy P:

    P = PolicyAuthorize(PCR signing key, "enklave-var-v1") + PolicyPCR(7 = current, 12 = 0)

The authorized part must be a policy signed at build time by `enklave-sign-policy`. It binds:
- PCR 11 to this UKI's value in the phase `enter-initrd:leave-initrd`;
- the UKI's **security epoch** (`SECURITY_EPOCH`) to "not revoked" in the bits index `0x01800E04`.

The signed policy ships on the ESP as `/EFI/enklave/policy/<uki>.json`. Updates must ship it together with the UKI.

**Every boot.**
- The key is read once and then read-locked.
- The volume key measurement (PCR 15) must equal the write-locked record `0x01800E01`.
- The anti-rollback value in `/var/lib/enklave/rollback-counter` must equal the NV counter `0x01800E03`. Both are then advanced.

**After provisioning.** On the first boot only, once every index has been written and locked:
- owner, endorsement and lockout get random, discarded authorization values;
- `TPM2_Clear` is disabled.

The indices can therefore not be deleted or re-created from the OS.

Every failure powers the machine off. There is no emergency or rescue shell.

### Revoking a vulnerable release

A UKI with a security bug in the window before `sysinit` could otherwise keep satisfying the policies, because it is signed with the same PCR key. To revoke it:

1. Fix the bug and raise `SECURITY_EPOCH` (e.g. `0` → `1`).
2. Build and sign the release. `make ref` signs its approved policy for the new epoch.
3. Ship it. On its first boot `enklave-varauth` sets the bits of all older epochs in `0x01800E04` (TPM_NT_BITS, set-only).
   - From then on, UKIs of an older epoch can no longer read the `/var` key, write any enklave index or advance the counter.
   - UKIs from before this scheme (empty policyRef, e.g. builds ≤ 2fd8d34) never could.
4. Optionally also remove the vulnerable UKI from the ESP / sysupdate source.

Epochs 0–63 are available. Raising the epoch does not touch `/var` data.

### Recovery: tainted PCR 12

systemd-stub measures credentials (`*.cred`), addons and command line overrides found on the (unauthenticated) ESP into PCR 12.

`/var` is bound to PCR 12 = 0. A stray or planted file such as `\loader\credentials\*.cred` or `\EFI\Linux\<uki>.efi.extra.d\*` therefore makes `/var` unreadable, and the machine powers off at every boot.

To recover:
1. Remove the ESP disk or boot another trusted system.
2. Delete the extra files from the ESP.
3. Boot again. Nothing else changes.

### Impact of key and firmware changes

- **New PCR signing key.** The NV policies are pinned to the PCR signing key through PolicyAuthorize. A UKI signed with a different key cannot open an existing `/var`. A key change therefore means re-provisioning (factory reset). Use epochs, not new keys, to revoke releases.
- **Secure Boot db/dbx/KEK/PK changes.** These change PCR 7, and P binds the current PCR 7. They also need a factory reset, unless they are applied before the first boot.
- **Firmware updates** that change PCR 7 (rare; SB variables only) have the same effect.

### Factory reset

Factory reset is a deliberate, physical-presence operation:
1. Clear the TPM in the firmware setup. This also wipes the owner hierarchy and the enklave indices.
2. Delete the `enklave-var` partition.

The next boot provisions a fresh, empty `/var`. `systemd-repart` never honours factory-reset requests (`--factory-reset=no`, `FactoryReset=no`).

An interrupted first boot fails closed and needs the same procedure:
- interrupted before the indices were written: delete the partition, and undefine the indices with the still-empty owner auth;
- interrupted after the indices were written but before the hierarchy lock-down: the next boot completes the lock-down.
