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
