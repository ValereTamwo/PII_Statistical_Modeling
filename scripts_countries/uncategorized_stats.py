#!/usr/bin/env python3
"""
Categorized vs UNCATEGORIZED item counts per country / auth mode / storage
type, written to a JSON file.

Categorized = every item in a real category file under data/user_countries
(excludes UNCATEGORIZED, INTERNAL_IDB_KEYS and DIRECT_PII_KEYS, the latter
being key-name matches that usually overlap another category).
UNCATEGORIZED = items in UNCATEGORIZED.json (data/user_countries_raws, or
data/user_countries if not yet relocated). For IndexedDB, entries already
resolved in a category file are counted separately as
'stale_duplicates_in_file' and are NOT counted as uncategorized.

Usage:
    python3 scripts_countries/uncategorized_stats.py [--users A,B] [--output PATH]
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from countries_config import add_users_arg, resolve_users

PROJECT_ROOT = Path(__file__).resolve().parent.parent
USER_DIR = PROJECT_ROOT / "data" / "user_countries"
RAW_DIR = PROJECT_ROOT / "data" / "user_countries_raws"
DEFAULT_OUTPUT = PROJECT_ROOT / "results_countries" / "uncategorized_stats.json"

STORAGES = ["cookies", "localstorage", "sessionstorage", "indexeddb"]
AUTH_MODES = ["AUTH", "NOTAUTH"]
NON_CATEGORY_FILES = {"UNCATEGORIZED", "INTERNAL_IDB_KEYS", "DIRECT_PII_KEYS"}


def load_json(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def item_key(item: dict):
    fp = item.get("field_path", "") or ""
    m = re.match(r"\[(\d+)\]", fp)
    return (item.get("source_file", ""), int(m.group(1)) if m else 0, fp)


def resolved_idb_keys(idb_dir: Path) -> set:
    keys = set()
    if not idb_dir.exists():
        return keys
    for f in idb_dir.glob("*.json"):
        if f.stem in NON_CATEGORY_FILES:
            continue
        for it in load_json(f):
            keys.add(item_key(it))
    return keys


def count_config(user: str, auth: str, storage: str) -> dict:
    counts = defaultdict(int)
    d = USER_DIR / auth / user / "PARTIAL" / storage
    rd = RAW_DIR / auth / user / "PARTIAL" / storage

    if d.exists():
        for f in d.rglob("*.json"):
            n = len(load_json(f))
            if f.stem == "DIRECT_PII_KEYS":
                counts["direct_pii_keys"] += n
            elif f.stem == "UNCATEGORIZED":
                counts["_uncat_unmoved"] += n
            elif f.stem == "INTERNAL_IDB_KEYS":
                counts["internal_idb_keys"] += n
            else:
                counts["categorized"] += n

    resolved = resolved_idb_keys(d) if storage == "indexeddb" else set()

    uncat_files = []
    if rd.exists():
        for f in rd.rglob("*.json"):
            if f.stem == "UNCATEGORIZED":
                uncat_files.append(f)
            elif f.stem == "INTERNAL_IDB_KEYS":
                counts["internal_idb_keys"] += len(load_json(f))
    if d.exists():
        uncat_files.extend(d.rglob("UNCATEGORIZED.json"))

    for f in uncat_files:
        for it in load_json(f):
            if storage == "indexeddb" and item_key(it) in resolved:
                counts["stale_duplicates_in_file"] += 1
            else:
                counts["uncategorized"] += 1

    counts.pop("_uncat_unmoved", None)
    return dict(counts)


def finalize(c: dict) -> dict:
    out = {
        "categorized": c.get("categorized", 0),
        "uncategorized": c.get("uncategorized", 0),
        "stale_duplicates_in_file": c.get("stale_duplicates_in_file", 0),
        "internal_idb_keys": c.get("internal_idb_keys", 0),
        "direct_pii_keys": c.get("direct_pii_keys", 0),
    }
    out["total"] = out["categorized"] + out["uncategorized"]
    out["uncategorized_pct"] = round(100 * out["uncategorized"] / out["total"], 2) if out["total"] else 0.0
    return out


def add_into(acc: dict, c: dict):
    for k in ("categorized", "uncategorized", "stale_duplicates_in_file",
              "internal_idb_keys", "direct_pii_keys"):
        acc[k] += c.get(k, 0)


def compute(users):
    per_cfg = {}
    for u in users:
        for auth in AUTH_MODES:
            for s in STORAGES:
                per_cfg[(u, auth, s)] = count_config(u, auth, s)

    def agg(select):
        acc = defaultdict(int)
        for key, c in per_cfg.items():
            if select(key):
                add_into(acc, c)
        return finalize(acc)

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "users": list(users),
        "totals": agg(lambda k: True),
        "by_storage": {s: agg(lambda k, s=s: k[2] == s) for s in STORAGES},
        "by_auth": {a: agg(lambda k, a=a: k[1] == a) for a in AUTH_MODES},
        "by_user": {
            u: {
                "totals": agg(lambda k, u=u: k[0] == u),
                "by_storage": {s: agg(lambda k, u=u, s=s: k[0] == u and k[2] == s) for s in STORAGES},
                "by_auth": {a: agg(lambda k, u=u, a=a: k[0] == u and k[1] == a) for a in AUTH_MODES},
            }
            for u in users
        },
    }


def main(users=None, output=None):
    users = users or resolve_users(None)
    output = Path(output) if output else DEFAULT_OUTPUT
    stats = compute(users)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    t = stats["totals"]
    print(f"Users: {users}")
    print(f"Categorized  : {t['categorized']:,}")
    print(f"Uncategorized: {t['uncategorized']:,} ({t['uncategorized_pct']}%)")
    print(f"Total        : {t['total']:,}")
    print(f"Stale duplicates still in UNCATEGORIZED.json: {t['stale_duplicates_in_file']:,}")
    print(f"Written to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    parser.add_argument("--output", default=None, help=f"Output JSON (default: {DEFAULT_OUTPUT})")
    args = parser.parse_args()
    main(users=resolve_users(args.users), output=args.output)
