#!/usr/bin/env python3
"""
AI CATEGORIZATION CORRECTION REDISTRIBUTION FOR INDEXEDDB - country extension.

Separate from redistribute_ai_categorizations.py (untouched). Reads
ai_categorizations_correction.json (produced by ai_indexeddb_correction.py)
and:
  1. Merges newly-recategorized fields into
     data/user_countries/.../indexeddb/{CATEGORY}.json, same as the
     original redistribute script.
  2. UNLIKE the original script, actually removes the corrected fields
     from data/user_countries_raws/.../indexeddb/UNCATEGORIZED.json -
     both the ones that got a real category (so they stop being
     double-counted, which is the bug the original script left behind)
     and, for cleanliness, nothing is removed for fields the correction
     pass still could not categorize (they legitimately stay put, having
     now actually been reviewed).
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent))
from aggregate_indexeddb import extract_record_index_from_path, generate_record_id

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from countries_config import add_users_arg, resolve_users


def redistribute_correction(
    correction_file: Path,
    user_indexeddb_dir: Path,
    raws_uncat_file: Path,
):
    if not correction_file.exists():
        print(f"  Warning: correction file not found: {correction_file}")
        return None

    with open(correction_file, "r", encoding="utf-8") as f:
        corrections = json.load(f)

    if not raws_uncat_file.exists():
        print(f"  Warning: UNCATEGORIZED.json not found: {raws_uncat_file}")
        return None

    with open(raws_uncat_file, "r", encoding="utf-8") as f:
        raw_items = json.load(f)

    # Key every raw item by (record_id, field_path) - safer than bare
    # field_path, which is only unique within one source_file/record.
    field_to_item = {}
    for item in raw_items:
        fp = item.get("field_path")
        if not fp:
            continue
        rid = generate_record_id(item.get("source_file", ""), extract_record_index_from_path(fp))
        field_to_item[(rid, fp)] = item

    def resolve_original_item(record_id: str, field_path: str):
        """
        Looks up the raw item for (record_id, field_path), with a fallback
        for a common model quirk: when every field in a record's prompt
        section shares the same leading '[N].' prefix, the model often
        echoes field_path back WITHOUT that prefix (treating it as implied
        by the record_id header) instead of the exact string it was given.
        Recover by re-attaching the index parsed from record_id itself.
        """
        item = field_to_item.get((record_id, field_path))
        if item is not None:
            return item
        if "#" in record_id:
            idx_str = record_id.rsplit("#", 1)[-1]
            return field_to_item.get((record_id, f"[{idx_str}].{field_path}"))
        return None

    items_by_category = defaultdict(list)
    resolved_keys = set()   # fields that got a real category -> remove from UNCATEGORIZED.json
    reviewed_keys = set()   # fields the correction pass looked at, regardless of verdict

    stats = {
        "total_fields_processed": 0,
        "fields_recategorized": 0,
        "fields_still_uncategorized": 0,
        "categories_distribution": Counter(),
    }

    for record_cat in corrections:
        record_id = record_cat.get("record_id", "")

        for field_analysis in record_cat.get("fields", []):
            field_path = field_analysis.get("field_path", "")
            category_raw = field_analysis.get("category", "UNCATEGORIZED")
            confidence = field_analysis.get("confidence", 0.0)
            explanation = field_analysis.get("explanation", "")

            stats["total_fields_processed"] += 1
            reviewed_keys.add((record_id, field_path))

            original_item = resolve_original_item(record_id, field_path)
            if not original_item:
                continue

            if "." in category_raw:
                main_category, subcategory = category_raw.split(".", 1)
            else:
                main_category = category_raw
                subcategory = "ai_correction_pass"

            if main_category == "UNCATEGORIZED":
                stats["fields_still_uncategorized"] += 1
                continue

            enriched_item = original_item.copy()
            enriched_item["ai_categorized"] = True
            enriched_item["ai_confidence"] = confidence
            enriched_item["ai_explanation"] = explanation
            enriched_item["record_id"] = record_id
            enriched_item["matched_subcategory"] = subcategory
            enriched_item["match_type"] = "ai_correction_pass"

            items_by_category[main_category].append(enriched_item)
            # Use the raw item's TRUE field_path (which may carry the
            # leading '[N].' prefix the model stripped from field_path
            # above) so the UNCATEGORIZED.json removal pass below - which
            # matches on raw items' own field_path - actually finds it.
            resolved_keys.add((record_id, original_item.get("field_path", field_path)))
            stats["fields_recategorized"] += 1
            stats["categories_distribution"][main_category] += 1

    for category, new_items in items_by_category.items():
        category_file = user_indexeddb_dir / f"{category}.json"

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

    if resolved_keys:
        remaining_raw_items = []
        for item in raw_items:
            fp = item.get("field_path")
            rid = generate_record_id(item.get("source_file", ""), extract_record_index_from_path(fp)) if fp else None
            if (rid, fp) in resolved_keys:
                continue
            remaining_raw_items.append(item)

        with open(raws_uncat_file, "w", encoding="utf-8") as f:
            json.dump(remaining_raw_items, f, indent=2, ensure_ascii=False)

        print(f"     UNCATEGORIZED.json: removed {len(resolved_keys)} now-resolved fields "
              f"({len(raw_items)} -> {len(remaining_raw_items)})")
    else:
        print(f"     UNCATEGORIZED.json: unchanged (no fields were newly resolved)")

    still_uncat_after_review = len(reviewed_keys) - len(resolved_keys)
    print(f"     {still_uncat_after_review} fields reviewed by the correction pass and confirmed UNCATEGORIZED")

    return stats


def main(users=None):
    base_dir = Path(__file__).resolve().parent.parent / "data"
    ai_complete_base = base_dir / "aggregates_ai_complete_countries" / "indexeddb"
    user_base = base_dir / "user_countries"
    raws_base = base_dir / "user_countries_raws"

    print("=" * 80)
    print("AI CORRECTION REDISTRIBUTION - INDEXEDDB - country extension")
    print("=" * 80)

    users = users or resolve_users(None)
    print(f"Scoped to users: {users}")

    total_stats = {
        "total_fields_processed": 0,
        "fields_recategorized": 0,
        "fields_still_uncategorized": 0,
        "categories_distribution": Counter(),
    }

    for auth in ["AUTH", "NOTAUTH"]:
        for user in users:
            for policy in ["PARTIAL"]:
                correction_file = ai_complete_base / auth / user / policy / "ai_categorizations_correction.json"
                user_dir = user_base / auth / user / policy / "indexeddb"
                raws_uncat_file = raws_base / auth / user / policy / "indexeddb" / "UNCATEGORIZED.json"

                if not correction_file.exists():
                    continue

                print(f"\n {auth}/{user}/{policy}")

                stats = redistribute_correction(correction_file, user_dir, raws_uncat_file)

                if stats:
                    total_stats["total_fields_processed"] += stats["total_fields_processed"]
                    total_stats["fields_recategorized"] += stats["fields_recategorized"]
                    total_stats["fields_still_uncategorized"] += stats["fields_still_uncategorized"]
                    total_stats["categories_distribution"].update(stats["categories_distribution"])

                    print(f"  OK {stats['fields_recategorized']} fields recategorized")
                    print(f"  OK {stats['fields_still_uncategorized']} fields remain UNCATEGORIZED")

    print("\n" + "=" * 80)
    print("GLOBAL SUMMARY")
    print("=" * 80)
    print(f"Total fields processed: {total_stats['total_fields_processed']}")
    print(f"Fields recategorized: {total_stats['fields_recategorized']}")
    print(f"Fields still UNCATEGORIZED: {total_stats['fields_still_uncategorized']}")

    if total_stats['categories_distribution']:
        print(f"\nCategory distribution:")
        for cat, count in total_stats['categories_distribution'].most_common():
            print(f"  {cat}: {count}")

    print("\n CORRECTION REDISTRIBUTION COMPLETE")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
