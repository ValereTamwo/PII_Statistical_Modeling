#!/usr/bin/env python3
"""
Cookie lifecycle analysis - country extension.

Adapted from analysis/lifecycle_analysis.py: identical timeline-building and
metrics (duration/entropy evolution, PII transitions, volatility), but reads
data/user_countries/ instead of data/user/, covers the 6 new-country
personas (single PARTIAL policy, AUTH/NOTAUTH naming), and writes to
results_countries/.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Tuple, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'analysis'))
import privacy_metrics as pm


def create_cookie_key(cookie: Dict) -> str:
    """Creates a unique key for a cookie. Format: name|domain|path"""
    name = cookie.get('name', '')
    domain = cookie.get('domain', '')
    path = cookie.get('path', '/')
    return f"{name}|{domain}|{path}"


def load_cookies_by_key(input_dir: Path) -> Dict[str, List[Dict]]:
    """Loads all cookies and indexes them by key."""
    cookies_by_key = defaultdict(list)

    category_files = sorted(input_dir.glob('*.json'))

    for category_file in category_files:
        category_name = category_file.stem

        with open(category_file, 'r', encoding='utf-8') as f:
            cookies = json.load(f)

        for cookie in cookies:
            cookie['_category'] = category_name
            key = create_cookie_key(cookie)
            cookies_by_key[key].append(cookie)

    return cookies_by_key


def build_cookie_timeline(cookie_key: str, added_cookies: List[Dict], modified_cookies: List[Dict], removed_cookies: List[Dict] = None) -> Dict:
    """Builds the complete timeline of a cookie."""
    events = []

    for cookie in added_cookies:
        task_id = int(cookie.get('task_id', 0))

        expires = cookie.get('expires', -1)
        if expires > 0:
            now = datetime.now().timestamp()
            duration = (expires - now) / (24 * 3600)
        else:
            duration = 0

        value = cookie.get('value', '')
        entropy = pm.calculate_entropy(value)

        category = cookie.get('_category', 'unknown')
        subcategory = cookie.get('matched_subcategory', '')

        if subcategory:
            pii_category = f"{category}::{subcategory}"
        else:
            pii_category = category

        events.append({
            'task_id': task_id,
            'type': 'added',
            'duration': duration,
            'entropy': entropy,
            'pii_category': pii_category,
            'changed_fields': []
        })

    for cookie in modified_cookies:
        task_id = int(cookie.get('task_id', 0))

        expires = cookie.get('expires', -1)
        if expires > 0:
            now = datetime.now().timestamp()
            duration = (expires - now) / (24 * 3600)
        else:
            duration = 0

        value = cookie.get('value', '')
        entropy = pm.calculate_entropy(value)

        category = cookie.get('_category', 'unknown')
        subcategory = cookie.get('matched_subcategory', '')

        if subcategory:
            pii_category = f"{category}::{subcategory}"
        else:
            pii_category = category

        changed_fields_raw = cookie.get('changed_fields', 'none')
        if isinstance(changed_fields_raw, str):
            if changed_fields_raw and changed_fields_raw != 'none':
                changed_fields = [f.strip() for f in changed_fields_raw.split(',')]
            else:
                changed_fields = []
        else:
            changed_fields = changed_fields_raw if changed_fields_raw else []

        events.append({
            'task_id': task_id,
            'type': 'modified',
            'duration': duration,
            'entropy': entropy,
            'pii_category': pii_category,
            'changed_fields': changed_fields
        })

    if removed_cookies:
        for cookie in removed_cookies:
            task_id = int(cookie.get('task_id', 0))

            expires = cookie.get('expires', -1)
            if expires > 0:
                now = datetime.now().timestamp()
                duration = (expires - now) / (24 * 3600)
            else:
                duration = 0

            value = cookie.get('value', '')
            entropy = pm.calculate_entropy(value)

            category = cookie.get('_category', 'unknown')
            subcategory = cookie.get('matched_subcategory', '')

            if subcategory:
                pii_category = f"{category}::{subcategory}"
            else:
                pii_category = category

            events.append({
                'task_id': task_id,
                'type': 'removed',
                'duration': duration,
                'entropy': entropy,
                'pii_category': pii_category,
                'changed_fields': []
            })

    events.sort(key=lambda x: x['task_id'])

    duration_evolution = [e['duration'] for e in events]
    entropy_evolution = [e['entropy'] for e in events]
    pii_categories = [e['pii_category'] for e in events]

    return {
        'key': cookie_key,
        'events': events,
        'duration_evolution': duration_evolution,
        'entropy_evolution': entropy_evolution,
        'pii_categories': pii_categories,
        'num_modifications': len([e for e in events if e['type'] == 'modified']),
        'num_removals': len([e for e in events if e['type'] == 'removed'])
    }


def analyze_lifecycle(added_dir: Path, modified_dir: Path, removed_dir: Path = None) -> Dict:
    """Full lifecycle analysis of cookies."""
    print("\n Cookie Lifecycle Analysis")
    print("=" * 70)

    print("\n Loading cookies...")
    added_by_key = load_cookies_by_key(added_dir)
    modified_by_key = load_cookies_by_key(modified_dir)
    removed_by_key = load_cookies_by_key(removed_dir) if removed_dir and removed_dir.exists() else {}

    print(f"   Added: {len(added_by_key)} unique keys")
    print(f"   Modified: {len(modified_by_key)} unique keys")
    print(f"   Removed: {len(removed_by_key)} unique keys")

    all_keys = set(added_by_key.keys()) | set(modified_by_key.keys()) | set(removed_by_key.keys())
    cookies_with_modifications = set(added_by_key.keys()) & set(modified_by_key.keys())

    print(f"   Total: {len(all_keys)} unique cookies")
    print(f"   With modifications: {len(cookies_with_modifications)} cookies")

    print("\n Building timelines...")
    timelines = {}

    for key in all_keys:
        added = added_by_key.get(key, [])
        modified = modified_by_key.get(key, [])
        removed = removed_by_key.get(key, [])

        if added or modified or removed:
            timeline = build_cookie_timeline(key, added, modified, removed)
            timelines[key] = timeline

    print(f"   {len(timelines)} timelines built")

    print("\n Analyzing patterns...")

    total_cookies = len(timelines)
    cookies_modified = len([t for t in timelines.values() if t['num_modifications'] > 0])
    cookies_removed = len([t for t in timelines.values() if t.get('num_removals', 0) > 0])

    duration_increases = 0
    duration_decreases = 0
    for timeline in timelines.values():
        if len(timeline['duration_evolution']) > 1:
            if timeline['duration_evolution'][-1] > timeline['duration_evolution'][0]:
                duration_increases += 1
            elif timeline['duration_evolution'][-1] < timeline['duration_evolution'][0]:
                duration_decreases += 1

    entropy_increases = 0
    entropy_decreases = 0
    for timeline in timelines.values():
        if len(timeline['entropy_evolution']) > 1:
            if timeline['entropy_evolution'][-1] > timeline['entropy_evolution'][0]:
                entropy_increases += 1
            elif timeline['entropy_evolution'][-1] < timeline['entropy_evolution'][0]:
                entropy_decreases += 1

    pii_transitions = Counter()
    for timeline in timelines.values():
        if len(timeline['pii_categories']) > 1:
            initial = timeline['pii_categories'][0]
            final = timeline['pii_categories'][-1]
            if initial != final:
                pii_transitions[(initial, final)] += 1

    volatility_dist = Counter()
    for timeline in timelines.values():
        num_mods = timeline['num_modifications']
        if num_mods == 0:
            volatility_dist['stable'] += 1
        elif num_mods <= 2:
            volatility_dist['moderate'] += 1
        else:
            volatility_dist['high'] += 1

    top_modified = sorted(
        timelines.values(),
        key=lambda x: x['num_modifications'],
        reverse=True
    )[:50]

    return {
        'timelines': timelines,
        'metrics': {
            'total_cookies': total_cookies,
            'cookies_modified': cookies_modified,
            'cookies_removed': cookies_removed,
            'duration_increases': duration_increases,
            'duration_decreases': duration_decreases,
            'entropy_increases': entropy_increases,
            'entropy_decreases': entropy_decreases,
            'pii_transitions': dict(pii_transitions),
            'volatility_distribution': dict(volatility_dist)
        },
        'top_modified': top_modified
    }


def main():
    """Main script (country extension)."""
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    output_base = Path(__file__).resolve().parent.parent / 'results_countries'

    if not base_dir.exists():
        print(f"Directory {base_dir} not found")
        return

    users = ('IT_0573', 'LU_0634', 'PT_0838', 'SE_0964', 'ES_0290', 'DE_0018')
    auth_statuses = ('AUTH', 'NOTAUTH')
    policies = ('PARTIAL',)

    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                added_dir = base_dir / 'user_countries' / auth_status / user / policy / 'cookies' / 'added'
                modified_dir = base_dir / 'user_countries' / auth_status / user / policy / 'cookies' / 'modified'
                removed_dir = base_dir / 'user_countries' / auth_status / user / policy / 'cookies' / 'removed'

                output_dir = output_base / auth_status / user / policy / 'cookies' / 'lifecycle'

                if not added_dir.exists() and not modified_dir.exists():
                    print(f"Directory {added_dir} does not exist, skipping.")
                    continue

                output_dir.mkdir(parents=True, exist_ok=True)

                results = analyze_lifecycle(added_dir, modified_dir, removed_dir)

                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / 'lifecycle_data.json'

                serializable_results = {
                    'metrics': {
                        **results['metrics'],
                        'pii_transitions': {f"{k[0]} -> {k[1]}": v for k, v in results['metrics']['pii_transitions'].items()}
                    },
                    'num_timelines': len(results['timelines']),
                    'top_modified_keys': [t['key'] for t in results['top_modified'][:20]]
                }

                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(serializable_results, f, indent=2, ensure_ascii=False)

                print(f"\n Results saved: {output_path}")

                print("\n Saving complete timelines...")
                timelines_output = output_dir / 'consolidated' / 'timelines_complete.json'
                timelines_output.parent.mkdir(parents=True, exist_ok=True)

                timelines_serializable = {}
                for key, timeline in results['timelines'].items():
                    timelines_serializable[key] = {
                        'key': timeline['key'],
                        'num_modifications': timeline['num_modifications'],
                        'events': timeline['events'],
                        'duration_evolution': timeline['duration_evolution'],
                        'entropy_evolution': timeline['entropy_evolution'],
                        'pii_categories': timeline['pii_categories']
                    }

                with open(timelines_output, 'w', encoding='utf-8') as f:
                    json.dump(timelines_serializable, f, indent=2, ensure_ascii=False)

                print(f"    {len(timelines_serializable)} complete timelines saved")
                print(f"    {timelines_output}")

                print("\n" + "=" * 70)
                if results['metrics']['total_cookies'] > 0:
                    print(f"\nTotal cookies: {results['metrics']['total_cookies']:,}")
                    print(f"Modified cookies: {results['metrics']['cookies_modified']:,} ({results['metrics']['cookies_modified']/results['metrics']['total_cookies']*100:.1f}%)")
                print("\n" + "=" * 70)


if __name__ == '__main__':
    main()
