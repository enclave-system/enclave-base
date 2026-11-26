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
