#!/usr/bin/env python3
"""
Consolidated web storage analysis (localStorage, sessionStorage, IndexedDB) -
country extension.

Adapted from analysis/storage_analysis/storage_consolidated_analysis.py:
identical metrics (PII distribution, persistence, size, content/vendor/
entropy privacy metrics, unified risk score), but reads data/user_countries/
instead of data/user/, covers the 6 new-country personas (single PARTIAL
policy, AUTH/NOTAUTH naming), and writes to results_countries/.

Reuses analysis/privacy_metrics.py and analysis/unified_risk_metrics.py
directly (no FR-specific hardcoding in those modules - no need to
duplicate them).

Fix vs. the FR version: create_unified_pii_type() there reads
item['matches'][0]['subcategory'], a field that does not exist in the
actual categorized JSON (real field is 'matched_subcategory') - so every
DIRECT_PII storage item in the FR results is mislabeled pii_type='unknown'.
This version reads 'matched_subcategory' directly, per user's explicit
choice to fix rather than replicate that bug for the country pipeline.
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

# Reuse the FR pipeline's generic analysis modules directly (no duplication)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import analysis.privacy_metrics as pm
from countries_config import add_users_arg, resolve_users


def load_all_storage_items(input_dir: Path, storage_type: str) -> Tuple[List[Dict], List[Dict]]:
    """
    Loads all storage items and splits them into 2 groups.

    Returns:
        (direct_pii_items, other_items)
    """
    direct_pii_items = []
    other_items = []

    category_files = sorted(input_dir.glob('*.json'))

    for category_file in category_files:
        category_name = category_file.stem

        with open(category_file, 'r', encoding='utf-8') as f:
            items = json.load(f)

        for item in items:
            item['_category'] = category_name
            item['_storage_type'] = storage_type

        if category_name == 'DIRECT_PII':
            direct_pii_items.extend(items)
        else:
            other_items.extend(items)

    return direct_pii_items, other_items


def create_unified_pii_type(item: Dict) -> str:
    """
    Creates a unified PII type for a storage item.

    - If DIRECT_PII: returns the subcategory (email, gender, etc.)
    - Else: returns the category name (BEHAVIORAL_DATA, etc.)
    """
    category = item.get('_category', 'unknown')

    if category == 'DIRECT_PII':
        return item.get('matched_subcategory', 'unknown')
    else:
        return category


def calculate_storage_size(item: Dict) -> int:
    """Approximate storage item size in bytes (name + value in UTF-8)."""
    value = item.get('value', '')
    name = item.get('name', '')

    return len(str(name).encode('utf-8')) + len(str(value).encode('utf-8'))


def get_persistence_type(storage_type: str) -> str:
    """Returns the persistence type for a storage type."""
    persistence_map = {
        'localstorage': 'Persistent',
        'indexeddb': 'Persistent',
        'sessionstorage': 'Session'
    }
    return persistence_map.get(storage_type.lower(), 'Unknown')


def analyze_storage_consolidated(direct_pii_items: List[Dict], other_items: List[Dict],
                                 storage_type: str) -> Dict:
    """Consolidated analysis of all storage items."""
    all_items = direct_pii_items + other_items
    total = len(all_items)

    print(f"\n Consolidated Analysis - {storage_type.upper()}")
    print(f"   DIRECT_PII: {len(direct_pii_items)} items")
    print(f"   Others: {len(other_items)} items")
    print(f"   TOTAL: {total} items\n")

    pii_distribution = Counter()
    pii_by_category = defaultdict(Counter)

    persistence_dist = Counter()
    persistence_by_pii = defaultdict(Counter)

    size_by_pii = defaultdict(list)
    total_size_by_pii = defaultdict(int)

    content_hierarchy = defaultdict(lambda: defaultdict(int))
    content_types = Counter()
    vendor_counts = Counter()
    category_vendor_flows = []

    entropy_data = []
    entropy_by_pii = defaultdict(list)

    risk_levels = Counter()
    risk_by_pii = defaultdict(Counter)

    for item in all_items:
        pii_type = create_unified_pii_type(item)
        pii_distribution[pii_type] += 1

        category = item.get('_category', 'unknown')
        pii_by_category[category][pii_type] += 1

        persistence = get_persistence_type(storage_type)
        persistence_dist[persistence] += 1
        persistence_by_pii[pii_type][persistence] += 1

        size = calculate_storage_size(item)
        size_by_pii[pii_type].append(size)
        total_size_by_pii[pii_type] += size

        value = item.get('value', '')

        entropy = pm.calculate_entropy(str(value))
        entropy_data.append((entropy, pii_type))
        entropy_by_pii[pii_type].append(entropy)

        decoded_value, decode_method, decode_success = pm.decode_value(str(value))
        data_type = pm.detect_data_type(str(value), decoded_value if decode_success else None)

        content_hierarchy[data_type][pii_type] += 1
        content_types[data_type] += 1

        if storage_type == 'indexeddb':
            source_file = item.get('source_file', '')
            if source_file:
                cleaned = source_file.replace('https_', '').replace('http_', '')
                domain_part = cleaned.split('_')[0]
                domain = domain_part.replace('.json', '').replace('.indexeddb', '').replace('.leveldb', '')
                vendor = pm.extract_vendor_from_domain(domain)
            else:
                vendor = 'Unknown'
        else:
            initial_url = item.get('initial_url', '')
            if initial_url:
                from urllib.parse import urlparse
                parsed = urlparse(initial_url)
                domain = parsed.netloc
                vendor = pm.extract_vendor_from_domain(domain) if domain else 'Unknown'
            else:
                vendor = 'Unknown'

        vendor_counts[vendor] += 1
        category_vendor_flows.append((pii_type, vendor, 1))

        from analysis.unified_risk_metrics import calculate_unified_risk_score

        risk_result = calculate_unified_risk_score(item, storage_type)

        item['_unified_risk'] = risk_result

        risk_level = risk_result['risk_category']

        risk_levels[risk_level] += 1
        risk_by_pii[pii_type][risk_level] += 1

    flow_aggregated = defaultdict(int)
    for cat, vendor, count in category_vendor_flows:
        flow_aggregated[(cat, vendor)] += count
    category_vendor_flows_agg = [(cat, vendor, count) for (cat, vendor), count in flow_aggregated.items()]

    return {
        'storage_type': storage_type,
        'total_items': total,
        'direct_pii_count': len(direct_pii_items),
        'other_count': len(other_items),

        'pii_distribution': dict(pii_distribution),
        'pii_by_category': {k: dict(v) for k, v in pii_by_category.items()},

        'persistence_distribution': dict(persistence_dist),
        'persistence_by_pii': {k: dict(v) for k, v in persistence_by_pii.items()},

        'size_by_pii': {k: {'total': total_size_by_pii[k],
                            'average': total_size_by_pii[k] / len(v) if v else 0,
                            'count': len(v)}
                        for k, v in size_by_pii.items()},

        'content_hierarchy': {k: dict(v) for k, v in content_hierarchy.items()},
        'content_types': dict(content_types),
        'vendor_counts': dict(vendor_counts),
        'category_vendor_flows': category_vendor_flows_agg,
        'entropy_by_pii': {k: v for k, v in entropy_by_pii.items()},

        'risk_levels': dict(risk_levels),
        'risk_by_pii': {k: dict(v) for k, v in risk_by_pii.items()},
    }


def main(users=None):
    """Main script (country extension)."""
    base_dir = Path(__file__).resolve().parent.parent.parent / 'data'
    output_base = Path(__file__).resolve().parent.parent.parent / 'results_countries'

    if not base_dir.exists():
        print(f" Directory {base_dir} not found")
        return

    users = users or resolve_users(None)
    auth_statuses = ('AUTH', 'NOTAUTH')
    policies = ('PARTIAL',)
    storage_types = ('localstorage', 'sessionstorage', 'indexeddb')

    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                for storage_type in storage_types:
                    storage_base_dir = base_dir / 'user_countries' / auth_status / user / policy / storage_type

                    if not storage_base_dir.exists():
                        continue

                    for lifecycle in ['added', 'modified', 'removed']:
                        input_dir = storage_base_dir / lifecycle

                        output_lifecycle = 'deleted' if lifecycle == 'removed' else lifecycle
                        output_dir = output_base / auth_status / user / policy / storage_type / output_lifecycle

                        if not input_dir.exists():
                            # No lifecycle subdirs for indexeddb (flat category files)
                            if lifecycle == 'added' and storage_type == 'indexeddb' and storage_base_dir.exists():
                                input_dir = storage_base_dir
                            else:
                                continue

                        if not any(input_dir.glob('*.json')):
                            continue

                        output_dir.mkdir(parents=True, exist_ok=True)

                        print(f"\n{'='*70}")
                        print(f" Configuration: {user} / {auth_status} / {policy} / {storage_type} / {lifecycle}")
                        print(f"{'='*70}")

                        direct_pii_items, other_items = load_all_storage_items(input_dir, storage_type)

                        if len(direct_pii_items) == 0 and len(other_items) == 0:
                            print(f"  No items found, skipping.")
                            continue

                        analysis_results = analyze_storage_consolidated(
                            direct_pii_items, other_items, storage_type
                        )

                        output_path = output_dir / 'consolidated' / 'analysis.json'
                        output_path.parent.mkdir(parents=True, exist_ok=True)

                        with open(output_path, 'w', encoding='utf-8') as f:
                            json.dump(analysis_results, f, indent=2, ensure_ascii=False)

                        print(f" Results saved: {output_path}")
                        print(f"\n Analysis {lifecycle} completed!")

    print("\n" + "=" * 70)
    print(" Consolidated storage analysis completed successfully!")
    print("=" * 70)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
