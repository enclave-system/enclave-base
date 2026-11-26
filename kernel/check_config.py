#!/usr/bin/env python3
"""Check a kernel .config against rule files.

Usage: check_config.py <.config> <rules...>
       check_config.py --parse-only <rules...>

Rule lines:  CONFIG_X=y   (must be set to exactly this value)
             !CONFIG_X    (must not be set)
Blank lines and '#' comments are ignored. Exit 0 = ok, 1 = rule violation or
parse error, 2 = usage error.
"""
import re
import sys

SYM = r"CONFIG_[A-Za-z0-9_]+"
REQ_RE = re.compile(rf"^({SYM})=(.+)$")
FORBID_RE = re.compile(rf"^!({SYM})$")
CFG_RE = re.compile(rf"^({SYM})=(.*)$")


def parse_rules(path):
    """Return (rules, errors); rules = [(kind, symbol, value, where)]."""
    rules, errors = [], []
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            where = f"{path}:{n}"
            m = FORBID_RE.match(line)
            if m:
                rules.append(("forbid", m.group(1), None, where))
                continue
            m = REQ_RE.match(line)
            if m:
                rules.append(("require", m.group(1), m.group(2), where))
                continue
            errors.append(f"{where}: unparseable rule: {line!r}")
    return rules, errors


def load_config(path):
    cfg = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            m = CFG_RE.match(raw.strip())
            if m and m.group(2) != "n":
                cfg[m.group(1)] = m.group(2)
    return cfg


def main(argv):
    parse_only = bool(argv) and argv[0] == "--parse-only"
    if parse_only:
        argv = argv[1:]
    if (not parse_only and len(argv) < 2) or (parse_only and not argv):
        print(__doc__, file=sys.stderr)
        return 2
    cfg_path, rule_paths = (None, argv) if parse_only else (argv[0], argv[1:])

    rules, errors = [], []
    for rp in rule_paths:
        try:
            r, e = parse_rules(rp)
        except OSError as exc:
            errors.append(f"{rp}: {exc}")
            continue
        rules += r
        errors += e
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        return 1
    if parse_only:
        print(f"OK: {len(rules)} rules parsed")
        return 0

    try:
        cfg = load_config(cfg_path)
    except OSError as exc:
        print(f"ERROR {cfg_path}: {exc}")
        return 1
    bad = 0
    for kind, sym, val, where in rules:
        got = cfg.get(sym)
        if kind == "forbid" and got is not None:
            print(f"FAIL {sym}={got} is set but forbidden ({where})")
            bad += 1
        elif kind == "require" and got != val:
            print(f"FAIL {sym} required {val}, found {got if got is not None else 'unset'} ({where})")
            bad += 1
    if bad:
        print(f"{bad} rule violation(s)")
        return 1
    print(f"OK: {len(rules)} rules satisfied")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
