#!/usr/bin/env python3
"""
AI CATEGORIZATION REDISTRIBUTION FOR INDEXEDDB - country extension.

Adapted from scripts/redistribute_ai_categorizations.py: identical logic,
but reads data/aggregates_ai_complete_countries/indexeddb/ and writes into
data/user_countries/.../indexeddb/{CATEGORY}.json for the 6 new-country
personas (single PARTIAL policy). Does NOT modify UNCATEGORIZED.json.
"""

import json
from pathlib import Path
from typing import Dict
from collections import defaultdict, Counter

def redistribute_ai_categorizations(
    ai_categorizations_file: Path,
    user_indexeddb_dir: Path
):
    """
    Redistributes AI categorizations into category-specific files.
    Appends items to data/user_countries/.../indexeddb/{CATEGORY}.json
    without modifying UNCATEGORIZED.json.
    """
    if not ai_categorizations_file.exists():
        print(f"  Warning: AI categorizations file not found: {ai_categorizations_file}")
        return None

    with open(ai_categorizations_file, "r", encoding="utf-8") as f:
        all_categorizations = json.load(f)

    uncategorized_file = user_indexeddb_dir / "UNCATEGORIZED.json"
    if not uncategorized_file.exists():
        print(f"  Warning: UNCATEGORIZED.json not found")
        return None

    with open(uncategorized_file, "r", encoding="utf-8") as f:
        uncategorized_items = json.load(f)

    field_to_item = {item.get("field_path"): item for item in uncategorized_items}

    items_by_category = defaultdict(list)

    stats = {
        "total_fields_processed": 0,
        "fields_recategorized": 0,
        "fields_still_uncategorized": 0,
        "categories_distribution": Counter()
    }

    for record_cat in all_categorizations:
        record_id = record_cat.get("record_id", "")

        for field_analysis in record_cat.get("fields", []):
            field_path = field_analysis.get("field_path", "")
            category_raw = field_analysis.get("category", "UNCATEGORIZED")
            confidence = field_analysis.get("confidence", 0.0)
            explanation = field_analysis.get("explanation", "")

            stats["total_fields_processed"] += 1

            original_item = field_to_item.get(field_path)
            if not original_item:
                continue

            if "." in category_raw:
                main_category, subcategory = category_raw.split(".", 1)
            else:
                main_category = category_raw
                subcategory = "ai_context_aware"

            if main_category == "UNCATEGORIZED":
                stats["fields_still_uncategorized"] += 1
                continue

            enriched_item = original_item.copy()
            enriched_item["ai_categorized"] = True
            enriched_item["ai_confidence"] = confidence
            enriched_item["ai_explanation"] = explanation
            enriched_item["record_id"] = record_id
            enriched_item["matched_subcategory"] = subcategory
            enriched_item["match_type"] = "ai_analysis"

            items_by_category[main_category].append(enriched_item)
            stats["fields_recategorized"] += 1
            stats["categories_distribution"][main_category] += 1

    for category, new_items in items_by_category.items():
        category_file = user_indexeddb_dir / f"{category}.json"

        existing_items = []
        if category_file.exists():
            try:
                with open(category_file, "r", encoding="utf-8") as f:
                    existing_items = json.load(f)
            except:
                existing_items = []

        all_items = existing_items + new_items

        with open(category_file, "w", encoding="utf-8") as f:
            json.dump(all_items, f, indent=2, ensure_ascii=False)

        print(f"     {category}: +{len(new_items)} items (total: {len(all_items)})")

    print(f"     UNCATEGORIZED.json: unchanged ({stats['fields_still_uncategorized']} items remain)")

    return stats

# =====================================================================
# MAIN
# =====================================================================

def main():
    base_dir = Path(__file__).resolve().parent.parent / "data"
    aggregates_ai_base = base_dir / "aggregates_ai_complete_countries" / "indexeddb"
    user_base = base_dir / "user_countries"

    print("=" * 80)
    print("AI CATEGORIZATION REDISTRIBUTION - INDEXEDDB - country extension")
    print("=" * 80)

    users = ["IT_0573", "PT_0838", "LU_0634", "DE_0018", "SE_0964", "ES_0290"]

    total_stats = {
        "total_fields_processed": 0,
        "fields_recategorized": 0,
        "fields_still_uncategorized": 0,
        "categories_distribution": Counter()
    }

    for auth in ["AUTH", "NOTAUTH"]:
        for user in users:
            for policy in ["PARTIAL"]:
                ai_cat_file = aggregates_ai_base / auth / user / policy / "ai_categorizations.json"
                user_dir = user_base / auth / user / policy / "indexeddb"

                if not ai_cat_file.exists():
                    continue

                print(f"\n {auth}/{user}/{policy}")

                stats = redistribute_ai_categorizations(
                    ai_cat_file,
                    user_dir
                )

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
    print(f"Fields UNCATEGORIZED: {total_stats['fields_still_uncategorized']}")

    if total_stats['categories_distribution']:
        print(f"\nCategory distribution:")
        for cat, count in total_stats['categories_distribution'].most_common():
            print(f"  {cat}: {count}")

    print("\n REDISTRIBUTION COMPLETE")

if __name__ == "__main__":
    main()
