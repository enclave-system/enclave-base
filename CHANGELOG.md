# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Hardened Linux 6.12 LTS kernel in two flavors (`server`, `client`), built
  from the GPG-verified kernel.org tarball, with a configuration rule check
  that runs before and after the compile.
- mkosi base image on Debian 13 (trixie): amnesic tmpfs root, erofs `/usr`
  with a signed dm-verity root hash and A/B slots, `/etc` from the factory
  tree, systemd-boot and a Unified Kernel Image with a signed PCR 11 policy.
- Reference role `ref` with a production configuration (`make ref`) and a
  test profile with selftest and serial console (`make ref-test`).
- Persistent state volume `/var/lib/enclave`: LUKS2 with integrity, key held
  in TPM NV only, created on the first boot, mounted read-only.
- State store with an HMAC manifest bound to a TPM NV counter, crash-safe
  commits, and a state service that runs only image-defined writers with
  declared input (none, or a signed and versioned bundle).
- `enclave-varauth` (unlock, provisioning, healing, state service),
  `enclave-selftest`, `enclave-cfg` (signed configuration bundles) and
  `enclave-sign-policy` (signed release policies).
- `pki/enclave-pki`: offline generation of all signing keys, OVMF variable
  stores with enrolled keys, and a CA for emulated test TPMs.
- Security epochs (`SECURITY_EPOCH`) with set-only revocation in the TPM, and
  healing of possibly compromised devices (`HEAL_BELOW`).
- Signed Secure Boot variable updates (dbx, db, KEK appends) applied by the
  release itself (`EFI_UPDATES`, `scripts/revoke-release.sh`).
- Optional EK certificates fetched from the TPM vendor (`EK_CERTS`) and
  per-device admissions for development VMs (`EK_ADMIT`).
- Build host bootstrap and check scripts with pinned tool versions.

### Security

- Secure Boot is mandatory; the kernel command line is fixed, with forced
  lockdown, mandatory module signatures, strict IOMMU and no credential
  import from unauthenticated sources.
- The volume key is released by the TPM only under a policy bound to the PCR
  signing key, role, profile, PCR 7, PCR 11 and PCR 12; a test-profile UKI
  can never open a production state volume.
- The TPM endorsement key is authenticated against the TPM vendor CAs on
  every boot; all commands that carry secrets use salted, encrypted sessions.
  Production accepts vendor-certified endorsement keys only, and
  `REQUIRE_FTPM=1` restricts a release to firmware TPMs.
- TPM hierarchies are locked under the release policy with no administrative
  secret; the unlock fails closed on foreign TPM objects, a missing IOMMU,
  a tainted PCR 12 or any partial TPM state.
- State that is swapped, spliced, rolled back or foreign is refused at boot
  and at every authenticated read.
- The PCR 7 binding is moved across a signed Secure Boot update by the TPM
  itself (exact values only), with a monotonic per-update record that keeps
  a rolled-back variable store from reopening the transition.
- Default-drop firewall in every direction; kernels built without IPv6.
- Development builds are marked (`DEV KEYS`) in the measured image and
  refused by the production checks; the test CA never enters non-test images.
