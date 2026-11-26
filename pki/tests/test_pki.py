import hashlib
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

# mkfs.vfat lives in /usr/sbin, not on the PATH of unprivileged users on Debian
os.environ["PATH"] += ":/usr/sbin:/sbin"

TOOL = Path(__file__).resolve().parent.parent / "enklave-pki"

DIRS = ["sb", "verity", "modsign", "config", "ca", "update", "pcr"]
FILES = [
    "sb/PK.key", "sb/PK.crt", "sb/KEK.key", "sb/KEK.crt", "sb/db.key", "sb/db.crt",
    "sb/PK.auth", "sb/KEK.auth", "sb/db.auth", "sb/GUID",
    "verity/verity.key", "verity/verity.crt",
    "modsign/modsign.pem", "modsign/modsign.crt",
    "config/config-signing.key", "config/config-signing.pub",
    "ca/ca.key", "ca/ca.crt",
    "update/update.gpg", "update/update.pub.gpg",
    "pcr/pcr-signing.key", "pcr/pcr-signing.pub",
]
SECRET = [
    "sb/PK.key", "sb/KEK.key", "sb/db.key", "verity/verity.key", "modsign/modsign.pem",
    "config/config-signing.key", "ca/ca.key", "update/update.gpg", "pcr/pcr-signing.key",
]


def run(*args, check=True, **kw):
    return subprocess.run([str(a) for a in args], check=check, capture_output=True, text=True, **kw)


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki") / "keys"
    run(TOOL, "init", d)
    return d


def test_init_creates_all_files(pki):
    for f in FILES:
        assert (pki / f).is_file(), f
    for d in DIRS:
        assert mode(pki / d) == 0o700, d
    assert mode(pki) == 0o700
    for f in SECRET:
        assert mode(pki / f) == 0o600, f


def text(crt):
    return run("openssl", "x509", "-noout", "-text", "-in", crt).stdout


def test_key_algorithms(pki):
    for c, bits in [("sb/PK", 2048), ("sb/KEK", 2048), ("sb/db", 2048),
                    ("verity/verity", 4096), ("modsign/modsign", 4096)]:
        t = text(pki / f"{c}.crt")
        assert "rsaEncryption" in t, c
        assert f"Public-Key: ({bits} bit)" in t, c
    t = text(pki / "ca/ca.crt")  # OpenSSL 3 prints the same curve as secp384r1
    assert "prime384v1" in t or "secp384r1" in t
    # modsign.pem holds key and cert
    pem = (pki / "modsign/modsign.pem").read_text()
    assert "PRIVATE KEY" in pem and "BEGIN CERTIFICATE" in pem
    # pcr signing key is RSA 2048
    t = run("openssl", "pkey", "-in", pki / "pcr/pcr-signing.key", "-noout", "-text").stdout
    assert "Private-Key: (2048 bit" in t
    t = run("openssl", "pkey", "-pubin", "-in", pki / "pcr/pcr-signing.pub", "-noout", "-text").stdout
    assert "Public-Key: (2048 bit)" in t
    # ed25519 raw
    pub = (pki / "config/config-signing.pub").read_bytes()
    key = (pki / "config/config-signing.key").read_bytes()
    assert len(pub) == 32 and len(key) == 64
    assert key[32:] == pub


def sha_tree(d):
    return {str(p.relative_to(d)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(d.rglob("*")) if p.is_file()}


def test_init_refuses_existing_dir(tmp_path):
    d = tmp_path / "k"
    run(TOOL, "init", d)
    before = sha_tree(d)
    r = run(TOOL, "init", d, check=False)
    assert r.returncode != 0
    assert sha_tree(d) == before


# ---------- VM test ----------
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
SHELL_EFI = "/usr/share/efi-shell-x64/shellx64.efi"


def make_esp(path, efi):
    run("truncate", "-s", "64M", path)
    run("mkfs.vfat", "-F", "32", path)
    run("mmd", "-i", path, "::/EFI", "::/EFI/BOOT")
    run("mcopy", "-i", path, efi, "::/EFI/BOOT/BOOTX64.EFI")
    # the shell runs startup.nsh and prints a marker, then powers off
    nsh = Path(str(path) + ".nsh")
    nsh.write_text("echo ENKLAVE-SHELL-RAN\nreset -s\n")
    run("mcopy", "-i", path, nsh, "::/startup.nsh")


def boot(vars_fd, esp, log, timeout=90):
    cmd = ["qemu-system-x86_64", "-machine", "q35,smm=on", "-m", "512",
           "-global", "driver=cfi.pflash01,property=secure,value=on",
           "-drive", f"if=pflash,format=raw,unit=0,file={OVMF_CODE},readonly=on",
           "-drive", f"if=pflash,format=raw,unit=1,file={vars_fd}",
           "-drive", f"format=raw,file={esp},if=virtio",
           "-display", "none", "-serial", f"file:{log}", "-monitor", "none", "-no-reboot"]
    if os.access("/dev/kvm", os.W_OK):
        cmd += ["-enable-kvm", "-cpu", "host"]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + timeout
    out = ""
    while time.time() < deadline and p.poll() is None:
        time.sleep(2)
        out = Path(log).read_text(errors="replace") if Path(log).exists() else ""
        if "ENKLAVE-SHELL-RAN" in out:
            break
    p.kill()
    p.wait()
    return Path(log).read_text(errors="replace") if Path(log).exists() else out


@pytest.mark.vm
def test_ovmf_vars_secureboot_user_mode(tmp_path):
    keys = tmp_path / "keys"
    run(TOOL, "init", keys)
    vars_fd = tmp_path / "VARS.fd"
    run(TOOL, "ovmf-vars", keys, vars_fd)

    signed = tmp_path / "Shell.signed.efi"
    run("sbsign", "--key", keys / "sb/db.key", "--cert", keys / "sb/db.crt",
        "--output", signed, SHELL_EFI)

    results = {}
    for name, efi in [("signed", signed), ("unsigned", SHELL_EFI)]:
        esp = tmp_path / f"{name}.img"
        make_esp(esp, efi)
        v = tmp_path / f"VARS.{name}.fd"
        shutil.copy(vars_fd, v)
        results[name] = boot(v, esp, tmp_path / f"{name}.log", timeout=90 if name == "signed" else 45)

    assert "ENKLAVE-SHELL-RAN" in results["signed"], results["signed"][-2000:]
    assert "ENKLAVE-SHELL-RAN" not in results["unsigned"], results["unsigned"][-2000:]


def test_init_leaves_no_temp_files(tmp_path):
    tdir = tmp_path / "tmp"
    tdir.mkdir()
    run(TOOL, "init", tmp_path / "k", env={**os.environ, "TMPDIR": str(tdir)})
    assert list(tdir.iterdir()) == []
    ps = run("ps", "-eo", "args").stdout
    assert not [l for l in ps.splitlines() if "gpg-agent" in l and str(tdir) in l]
