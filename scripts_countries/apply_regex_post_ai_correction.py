#!/usr/bin/env python3
"""
APPLY POST-AI REGEX CORRECTION - indexeddb, country extension.

Final catch-all pass, run once both AI passes (ai_parallel_indexededdb.py +
ai_indexeddb_correction.py) are done. Applies the narrow, site-audited
rules in regex_post_ai_correction.py directly against whatever is still
sitting in UNCATEGORIZED.json: for each item, POST_AI_CORRECTION_RULES is
matched against its own field_path/value (see dry_run_regex_post_ai_correction.py
for a read-only preview of these matches before running this for real).

Simpler than the AI correction's redistribution step: there is no LLM
echo of field_path to reconcile (the earlier record_id/field_path
mismatch bug from the AI correction pass cannot occur here), so a match is
applied directly to the same item object, in place - no cross-file lookup
needed.

After this runs, whatever remains in UNCATEGORIZED.json is treated as
final/accepted uncategorized data - no further correction passes are
planned on top of this one.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent))
from regex_post_ai_correction import match_item

USERS = ["IT_0573", "PT_0838", "LU_0634", "DE_0018", "SE_0964", "ES_0290"]


def apply_correction_for_config(idb_dir: Path, raws_uncat_file: Path):
    if not raws_uncat_file.exists():
        return None

    with open(raws_uncat_file, "r", encoding="utf-8") as f:
        raw_items = json.load(f)

    items_by_category = defaultdict(list)
    remaining = []
    stats = {
        "total_items": len(raw_items),
        "matched": 0,
        "categories_distribution": Counter(),
        "rules_distribution": Counter(),
    }

    for item in raw_items:
        fp = item.get("field_path")
        value = item.get("value")

        if not fp:
            remaining.append(item)
            continue

        m = match_item(fp, value)
        if not m:
            remaining.append(item)
            continue

        enriched = item.copy()
        enriched["ai_categorized"] = False
        enriched["matched_subcategory"] = m["subcategory"]
        enriched["match_type"] = "regex_post_ai_correction"
        enriched["rule_id"] = m["rule_id"]

        items_by_category[m["category"]].append(enriched)
        stats["matched"] += 1
        stats["categories_distribution"][m["category"]] += 1
        stats["rules_distribution"][m["rule_id"]] += 1

    for category, new_items in items_by_category.items():
        category_file = idb_dir / f"{category}.json"

        existing_items = []
        if category_file.exists():
            try:
                with open(category_file, "r", encoding="utf-8") as f:
                    existing_items = json.load(f)
            except Exception:
                existing_items = []

        all_items = existing_items + new_items

        with open(category_file, "w", encoding="utf-8") as f:
            json.dump(all_items, f, indent=2, ensure_ascii=False)

        print(f"     {category}: +{len(new_items)} items (total: {len(all_items)})")

    with open(raws_uncat_file, "w", encoding="utf-8") as f:
        json.dump(remaining, f, indent=2, ensure_ascii=False)

    print(f"     UNCATEGORIZED.json: {len(raw_items)} -> {len(remaining)} "
          f"(removed {stats['matched']})")

    return stats


def main():
    base_dir = Path(__file__).resolve().parent.parent / "data"
    user_base = base_dir / "user_countries"
    raws_base = base_dir / "user_countries_raws"

    print("=" * 80)
    print("APPLY POST-AI REGEX CORRECTION - INDEXEDDB - country extension")
    print("=" * 80)

    total_stats = {
        "total_items": 0,
        "matched": 0,
        "categories_distribution": Counter(),
        "rules_distribution": Counter(),
    }

    for auth in ["AUTH", "NOTAUTH"]:
        for user in USERS:
            idb_dir = user_base / auth / user / "PARTIAL" / "indexeddb"
            raws_uncat_file = raws_base / auth / user / "PARTIAL" / "indexeddb" / "UNCATEGORIZED.json"

            if not raws_uncat_file.exists():
                continue

            print(f"\n {auth}/{user}/PARTIAL")

            stats = apply_correction_for_config(idb_dir, raws_uncat_file)

            if stats:
                total_stats["total_items"] += stats["total_items"]
                total_stats["matched"] += stats["matched"]
                total_stats["categories_distribution"].update(stats["categories_distribution"])
                total_stats["rules_distribution"].update(stats["rules_distribution"])

    print("\n" + "=" * 80)
    print("GLOBAL SUMMARY")
    print("=" * 80)
    print(f"Total UNCATEGORIZED items scanned: {total_stats['total_items']}")
    print(f"Total matched and recategorized  : {total_stats['matched']}")
    print(f"Remaining uncategorized          : {total_stats['total_items'] - total_stats['matched']}")

    if total_stats["categories_distribution"]:
        print(f"\nCategory distribution:")
        for cat, count in total_stats["categories_distribution"].most_common():
            print(f"  {cat}: {count}")

    if total_stats["rules_distribution"]:
        print(f"\nRule distribution:")
        for rule_id, count in total_stats["rules_distribution"].most_common():
            print(f"  {rule_id}: {count}")

    print("\n APPLY COMPLETE")


if __name__ == "__main__":
    main()
