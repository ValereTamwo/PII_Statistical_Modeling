#!/usr/bin/env python3
"""
INDEXEDDB AGGREGATION SYSTEM - country extension.

Adapted from scripts/aggregate_indexeddb.py: identical logic (record IDs,
PII cards, field_path aggregates, hierarchical reconstruction, global
stats), but reads data/user_countries/.../indexeddb instead of
data/user/.../indexeddb, covers the 6 new-country personas (single PARTIAL
policy), and writes to data/aggregates_countries/indexeddb/ - fully
separate from the FR pipeline's data/aggregates/indexeddb/.
"""

import re
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any
import json


def extract_record_index_from_path(field_path: str) -> int:
    match = re.match(r'\[(\d+)\]', field_path)
    if match:
        return int(match.group(1))
    return 0


def generate_record_id(source_file: str, record_index: int) -> str:
    return f"{source_file}#{record_index}"


def load_categorized_data(indexeddb_dir: Path) -> Dict[str, List[Dict]]:
    categorized_data = {}

    if not indexeddb_dir.exists():
        return categorized_data

    for json_file in indexeddb_dir.glob("*.json"):
        category = json_file.stem
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                items = json.load(f)
                if items:
                    categorized_data[category] = items
        except Exception as e:
            print(f"  Error loading {json_file}: {e}")

    return categorized_data


def build_records_with_pii_cards(categorized_data: Dict[str, List[Dict]]) -> List[Dict]:
    records_map = defaultdict(lambda: {
        'categories': set(),
        'details': defaultdict(set),
        'fields': [],
        'source_file': None
    })

    for category, items in categorized_data.items():
        if category in ['UNCATEGORIZED', 'INTERNAL_IDB_KEYS', 'INFRASTRUCTURE']:
            continue

        for item in items:
            source_file = item.get('source_file', 'unknown')
            field_path = item.get('field_path', '')
            record_index = extract_record_index_from_path(field_path)
            record_id = generate_record_id(source_file, record_index)

            records_map[record_id]['categories'].add(category)

            subcategory = item.get('matched_subcategory', 'unknown')
            records_map[record_id]['details'][category].add(subcategory)

            records_map[record_id]['fields'].append({
                'field_path': field_path,
                'category': category,
                'subcategory': subcategory
            })

            records_map[record_id]['source_file'] = source_file

    records_with_cards = []
    for record_id, data in sorted(records_map.items()):
        card = {
            'record_id': record_id,
            'source_file': data['source_file'],
            'pii_categories': sorted(list(data['categories'])),
            'pii_details': {
                cat: sorted(list(subcats))
                for cat, subcats in sorted(data['details'].items())
            },
            'field_count': len(data['fields']),
            'fields': data['fields']
        }
        records_with_cards.append(card)

    return records_with_cards


def build_field_path_aggregates(categorized_data: Dict[str, List[Dict]]) -> Dict[str, Dict]:
    field_path_map = defaultdict(lambda: {
        'categories': set(),
        'subcategories': set(),
        'occurrences': 0,
        'source_files': set(),
        'example_value': None
    })

    for category, items in categorized_data.items():
        for item in items:
            field_path = item.get('field_path', '')
            source_file = item.get('source_file', 'unknown')

            field_path_map[field_path]['occurrences'] += 1
            field_path_map[field_path]['source_files'].add(source_file)

            if category not in ['UNCATEGORIZED', 'INTERNAL_IDB_KEYS', 'INFRASTRUCTURE']:
                field_path_map[field_path]['categories'].add(category)
                subcategory = item.get('matched_subcategory', 'unknown')
                field_path_map[field_path]['subcategories'].add(subcategory)

            if field_path_map[field_path]['example_value'] is None:
                value = item.get('value')
                if isinstance(value, str) and len(value) > 100:
                    value = value[:100] + "..."
                field_path_map[field_path]['example_value'] = value

    aggregates = {}
    for field_path, data in sorted(field_path_map.items()):
        aggregates[field_path] = {
            'categories': sorted(list(data['categories'])) if data['categories'] else ['UNCATEGORIZED'],
            'subcategories': sorted(list(data['subcategories'])),
            'occurrences': data['occurrences'],
            'source_files': sorted(list(data['source_files'])),
            'example_value': data['example_value']
        }

    return aggregates


def build_hierarchical_reconstruction(categorized_data: Dict[str, List[Dict]]) -> Dict[str, Any]:
    hierarchy = defaultdict(lambda: defaultdict(dict))

    for category, items in categorized_data.items():
        for item in items:
            source_file = item.get('source_file', 'unknown')
            field_path = item.get('field_path', '')
            record_index = extract_record_index_from_path(field_path)

            hierarchy[source_file][record_index][field_path] = {
                'category': category,
                'subcategory': item.get('matched_subcategory', 'unknown'),
                'value': item.get('value'),
                'name': item.get('name', field_path.split('.')[-1])
            }

    reconstruction = {}
    for source_file, records in sorted(hierarchy.items()):
        reconstruction[source_file] = {
            'total_records': len(records),
            'records': {
                f"record_{idx}": {
                    'record_id': generate_record_id(source_file, idx),
                    'fields': fields
                }
                for idx, fields in sorted(records.items())
            }
        }

    return reconstruction


def compute_global_statistics(
    records_with_cards: List[Dict],
    field_path_aggregates: Dict[str, Dict],
    categorized_data: Dict[str, List[Dict]]
) -> Dict[str, Any]:
    pii_distribution = Counter()
    for category, items in categorized_data.items():
        if category not in ['UNCATEGORIZED', 'INTERNAL_IDB_KEYS']:
            pii_distribution[category] = len(items)

    records_with_multiple_pii = sum(
        1 for record in records_with_cards
        if len(record['pii_categories']) > 1
    )

    total_pii_instances = sum(
        len(record['pii_categories'])
        for record in records_with_cards
    )

    avg_pii_per_record = (
        total_pii_instances / len(records_with_cards)
        if records_with_cards else 0
    )

    field_paths_with_pii = sum(
        1 for fp_data in field_path_aggregates.values()
        if fp_data['categories'] != ['UNCATEGORIZED']
    )

    top_field_paths = sorted(
        field_path_aggregates.items(),
        key=lambda x: x[1]['occurrences'],
        reverse=True
    )[:20]

    statistics = {
        'total_records': len(records_with_cards),
        'total_unique_field_paths': len(field_path_aggregates),
        'field_paths_with_pii': field_paths_with_pii,
        'field_paths_uncategorized': len(field_path_aggregates) - field_paths_with_pii,
        'pii_categories_distribution': dict(pii_distribution),
        'records_with_multiple_pii': records_with_multiple_pii,
        'average_pii_per_record': round(avg_pii_per_record, 2),
        'total_pii_instances': total_pii_instances,
        'top_20_most_frequent_field_paths': [
            {
                'field_path': fp,
                'occurrences': data['occurrences'],
                'categories': data['categories']
            }
            for fp, data in top_field_paths
        ],
        'unique_source_files': len(set(
            item.get('source_file', 'unknown')
            for items in categorized_data.values()
            for item in items
        ))
    }

    return statistics


def process_indexeddb_aggregates(user_dir: Path, output_dir: Path):
    print(f"Processing {user_dir}")

    categorized_data = load_categorized_data(user_dir)

    if not categorized_data:
        print(f"  No data found in {user_dir}")
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Building PII cards...")
    records_with_cards = build_records_with_pii_cards(categorized_data)

    print(f"  Building field_path aggregates...")
    field_path_aggregates = build_field_path_aggregates(categorized_data)

    print(f"  Building hierarchical reconstruction...")
    hierarchical_reconstruction = build_hierarchical_reconstruction(categorized_data)

    print(f"  Computing global statistics...")
    global_statistics = compute_global_statistics(
        records_with_cards,
        field_path_aggregates,
        categorized_data
    )

    print(f"  Saving results...")

    with open(output_dir / 'records_with_pii_cards.json', 'w', encoding='utf-8') as f:
        json.dump(records_with_cards, f, indent=2, ensure_ascii=False)

    with open(output_dir / 'field_path_aggregates.json', 'w', encoding='utf-8') as f:
        json.dump(field_path_aggregates, f, indent=2, ensure_ascii=False)

    with open(output_dir / 'hierarchical_reconstruction.json', 'w', encoding='utf-8') as f:
        json.dump(hierarchical_reconstruction, f, indent=2, ensure_ascii=False)

    with open(output_dir / 'global_statistics.json', 'w', encoding='utf-8') as f:
        json.dump(global_statistics, f, indent=2, ensure_ascii=False)

    print(f"  {len(records_with_cards)} records processed")
    print(f"  {len(field_path_aggregates)} unique field_paths")
    print(f"  {global_statistics['total_pii_instances']} PII instances")


def main():
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    user_base_dir = base_dir / 'user_countries'
    aggregates_base_dir = base_dir / 'aggregates_countries' / 'indexeddb'

    users = ('IT_0573', 'PT_0838', 'LU_0634', 'DE_0018', 'SE_0964', 'ES_0290')

    print("=== INDEXEDDB AGGREGATION SYSTEM (country extension) ===\n")

    for auth in ('AUTH', 'NOTAUTH'):
        for user in users:
            user_dir = user_base_dir / auth / user / 'PARTIAL' / 'indexeddb'
            output_dir = aggregates_base_dir / auth / user / 'PARTIAL'

            if user_dir.exists():
                process_indexeddb_aggregates(user_dir, output_dir)

    print("\n=== AGGREGATION COMPLETE ===")


if __name__ == '__main__':
    main()
