#!/usr/bin/env python3
"""
Removes stale duplicates from IndexedDB UNCATEGORIZED.json files
(data/user_countries_raws/.../indexeddb/UNCATEGORIZED.json).

redistribute_ai_categorizations.py appends AI-categorized fields to the
category files but, by inheritance from the FR original, leaves them in
UNCATEGORIZED.json. This drops every UNCATEGORIZED entry that is already
resolved in a real category file of the same config, matched on
(source_file, record index, field_path).

Dry-run by default; nothing is written without --apply.

Usage:
    python3 scripts_countries/clean_uncategorized_duplicates.py [--users A,B] [--apply]
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from countries_config import add_users_arg, resolve_users
from uncategorized_stats import (
    USER_DIR, RAW_DIR, AUTH_MODES, load_json, item_key, resolved_idb_keys,
)


def main(users=None, apply=False):
    users = users or resolve_users(None)
    print(f"Mode: {'APPLY' if apply else 'DRY-RUN'} | users: {users}\n")

    total_before = total_removed = 0
    for u in users:
        for auth in AUTH_MODES:
            raw_file = RAW_DIR / auth / u / "PARTIAL" / "indexeddb" / "UNCATEGORIZED.json"
            if not raw_file.exists():
                continue
            resolved = resolved_idb_keys(USER_DIR / auth / u / "PARTIAL" / "indexeddb")
            items = load_json(raw_file)
            kept = [it for it in items if item_key(it) not in resolved]
            removed = len(items) - len(kept)
            total_before += len(items)
            total_removed += removed
            print(f"{auth}/{u}: {len(items):,} -> {len(kept):,} (removed {removed:,})")
            if apply and removed:
                with open(raw_file, "w", encoding="utf-8") as f:
                    json.dump(kept, f, indent=2, ensure_ascii=False)

    print(f"\nTotal: {total_before:,} -> {total_before - total_removed:,} (removed {total_removed:,})")
    if not apply:
        print("Dry-run only. Re-run with --apply to write.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    parser.add_argument("--apply", action="store_true", help="Write the cleaned files")
    args = parser.parse_args()
    main(users=resolve_users(args.users), apply=args.apply)
