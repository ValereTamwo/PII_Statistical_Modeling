#!/usr/bin/env python3
"""
DRY-RUN reviewer for regex_post_ai_correction.py.

Read-only: scans every config's UNCATEGORIZED.json, applies
POST_AI_CORRECTION_RULES, and reports per-rule match counts + a few sample
field_path/value pairs so the rules can be reviewed against real data
before anything is written. Does NOT modify UNCATEGORIZED.json or any
category file - that happens later, in the redistribution step, only after
this review is approved.
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent))
from regex_post_ai_correction import get_rules, match_item

USERS = ["IT_0573", "PT_0838", "LU_0634", "DE_0018", "SE_0964", "ES_0290"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=str(Path(__file__).resolve().parent.parent / "data"),
                         help="Path to the data/ directory (override to point at the real dataset "
                              "when running from a worktree that doesn't have it).")
    parser.add_argument("--samples", type=int, default=3, help="Sample matches to print per rule.")
    args = parser.parse_args()

    base = Path(args.data_dir)
    raws_base = base / "user_countries_raws"

    per_rule_count = Counter()
    per_rule_samples = defaultdict(list)
    total_uncat = 0
    total_matched = 0

    for auth in ["AUTH", "NOTAUTH"]:
        for user in USERS:
            uncat_path = raws_base / auth / user / "PARTIAL" / "indexeddb" / "UNCATEGORIZED.json"
            if not uncat_path.exists():
                continue
            items = json.load(open(uncat_path, "r", encoding="utf-8"))
            total_uncat += len(items)
            for it in items:
                fp = it.get("field_path")
                if not fp:
                    continue
                m = match_item(fp, it.get("value"))
                if m:
                    total_matched += 1
                    per_rule_count[m["rule_id"]] += 1
                    if len(per_rule_samples[m["rule_id"]]) < args.samples:
                        per_rule_samples[m["rule_id"]].append({
                            "auth": auth, "user": user,
                            "source_file": it.get("source_file"),
                            "field_path": fp,
                            "value": str(it.get("value"))[:120],
                        })

    print("=" * 90)
    print("DRY-RUN REVIEW - POST-AI REGEX CORRECTION (no files modified)")
    print("=" * 90)

    for rule in get_rules():
        rid = rule["rule_id"]
        n = per_rule_count.get(rid, 0)
        print(f"\n[{rid}] -> {rule['category']}.{rule['subcategory']}  "
              f"(site evidence: {rule['site_evidence']})")
        print(f"   path_pattern : {rule['path_pattern']}")
        if rule.get("value_pattern"):
            print(f"   value_pattern: {rule['value_pattern']}")
        print(f"   MATCHES: {n}")
        for s in per_rule_samples.get(rid, []):
            print(f"     - {s['auth']}/{s['user']} {s['source_file']}  {s['field_path']} = {s['value']}")

    print("\n" + "=" * 90)
    print(f"Total still UNCATEGORIZED (all configs): {total_uncat}")
    print(f"Total matched by these rules           : {total_matched} "
          f"({100*total_matched/total_uncat:.1f}% of UNCATEGORIZED)" if total_uncat else "")
    print("=" * 90)


if __name__ == "__main__":
    main()
