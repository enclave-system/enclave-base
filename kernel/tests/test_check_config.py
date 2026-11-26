import subprocess
import sys
from pathlib import Path

KERNEL = Path(__file__).resolve().parent.parent
CHECK = KERNEL / "check_config.py"


def run(config_text, rules_text, tmp_path):
    cfg = tmp_path / ".config"
    rules = tmp_path / "x.rules"
    cfg.write_text(config_text)
    rules.write_text(rules_text)
    return subprocess.run(
        [sys.executable, str(CHECK), str(cfg), str(rules)],
        capture_output=True, text=True,
    )


def test_passes_when_all_rules_met(tmp_path):
    r = run("CONFIG_A=y\n# CONFIG_B is not set\nCONFIG_C=m\n",
            "# comment\nCONFIG_A=y\n!CONFIG_B\n!CONFIG_D\nCONFIG_C=m\n", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_fails_on_forbidden_symbol_set(tmp_path):
    r = run("CONFIG_USB_STORAGE=m\n", "!CONFIG_USB_STORAGE\n", tmp_path)
    assert r.returncode == 1
    assert "CONFIG_USB_STORAGE" in r.stdout + r.stderr


def test_fails_on_required_missing(tmp_path):
    r = run("# CONFIG_A is not set\n", "CONFIG_A=y\nCONFIG_Z=y\n", tmp_path)
    assert r.returncode == 1
    assert "CONFIG_A" in r.stdout + r.stderr
    assert "CONFIG_Z" in r.stdout + r.stderr


def test_wrong_value_fails(tmp_path):
    r = run("CONFIG_A=m\n", "CONFIG_A=y\n", tmp_path)
    assert r.returncode == 1


def test_real_rules_files_parse(tmp_path):
    rules = sorted((KERNEL / "rules").glob("*.rules"))
    assert {p.name for p in rules} >= {"common.rules", "client.rules", "server.rules"}
    r = subprocess.run([sys.executable, str(CHECK), "--parse-only", *map(str, rules)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def _rules(name):
    return (KERNEL / "rules" / name).read_text().splitlines()


def test_mitigation_and_hardening_symbols_pinned():
    lines = set(_rules("common.rules"))
    for want in (
        "CONFIG_CPU_MITIGATIONS=y", "CONFIG_MITIGATION_RETPOLINE=y",
        "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION=y", "CONFIG_MITIGATION_RETHUNK=y",
        "CONFIG_MITIGATION_IBRS_ENTRY=y", "CONFIG_SHUFFLE_PAGE_ALLOCATOR=y",
        "CONFIG_SLAB_FREELIST_HARDENED=y", "CONFIG_SLAB_FREELIST_RANDOM=y",
        "CONFIG_RANDOM_KMALLOC_CACHES=y", "CONFIG_VMAP_STACK=y",
        "CONFIG_INTEL_IOMMU_DEFAULT_ON=y", "CONFIG_IOMMU_DEFAULT_DMA_STRICT=y",
        "CONFIG_SECURITY_YAMA=y", "CONFIG_LEGACY_VSYSCALL_NONE=y",
        "CONFIG_ZERO_CALL_USED_REGS=y", "CONFIG_STRICT_MODULE_RWX=y",
        "CONFIG_RANDOMIZE_MEMORY=y", "CONFIG_BUG_ON_DATA_CORRUPTION=y",
        'CONFIG_LSM="lockdown,yama,integrity,apparmor,bpf"',
    ):
        assert want in lines, want


def test_fragments_use_no_legacy_names():
    legacy = {"CONFIG_RETPOLINE", "CONFIG_PAGE_TABLE_ISOLATION"}
    for frag in (KERNEL / "config").glob("*.config"):
        for line in frag.read_text().splitlines():
            sym = line.split("=")[0].strip()
            assert sym not in legacy, f"{frag.name}: {line}"


def test_quoted_string_value_rule(tmp_path):
    ok = run('CONFIG_LSM="a,b"\n', 'CONFIG_LSM="a,b"\n', tmp_path)
    assert ok.returncode == 0
    bad = run('CONFIG_LSM="b,a"\n', 'CONFIG_LSM="a,b"\n', tmp_path)
    assert bad.returncode == 1 and "CONFIG_LSM" in bad.stdout
