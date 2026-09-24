"""
PII Aggregator - country extension.

Adapted from analysis_gdpr_profiles/scripts/pii_aggregator.py: identical
aggregation logic (by storage_type/category/lifecycle, persistence
metrics), but reads data/user_countries/ instead of data/user/, covers the
6 new-country personas (single PARTIAL policy, AUTH/NOTAUTH naming), and
writes to analysis_gdpr_profiles_countries/outputs - fully separate from
the FR pipeline.

Differences vs. the FR version:
- Sensitivity tiering (critical/high/medium/low) dropped entirely, per
  user's explicit request - not useful for this analysis.
- Cookie security (httpOnly/secure/sameSite + security posture) is now
  aggregated here too, by PII category, and carried on each individual
  pii_instance entry - not just in the separate analysis_countries/
  consolidated_analysis.py output - so this per-profile summary alone
  supports a full cross-country comparison without cross-referencing
  multiple output trees.
- UNCATEGORIZED.json (relocated to data/user_countries_raws/ by
  clean_user_folder.py, so invisible to the normal load_categorized_data()
  path - same situation the FR pipeline has with data/user_raws/) is
  additionally loaded and reported as separate 'uncategorized_items' /
  'total_items_with_uncategorized' fields, so auth-vs-unauth volume can be
  compared with and without it.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any

sys.path.append(str(Path(__file__).parent))
from utils import (
    load_all_user_data,
    export_to_json,
    get_pii_categories,
    count_by_category,
    filter_by_category,
    extract_pii_value,
    get_storage_key
)

# Reuse the FR pipeline's generic normalize_samesite() / is_third_party() (no FR-specific hardcoding there)
sys.path.append(str(Path(__file__).parent.parent.parent / 'analysis'))
from analyze_by_category import normalize_samesite, is_third_party

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from countries_config import add_users_arg, resolve_users


def load_uncategorized_counts(raws_path: str, nav_mode: str, user_id: str, policy: str) -> Dict[str, int]:
    """
    Counts UNCATEGORIZED.json items per storage type from the raws directory
    (where clean_user_folder.py relocated them), mirroring
    utils.load_categorized_data()'s lifecycle-aware / flat-indexeddb path
    resolution but restricted to just the UNCATEGORIZED.json file.
    """
    storage_types = ['cookies', 'indexeddb', 'localstorage', 'sessionstorage']
    counts = {}

    for storage_type in storage_types:
        storage_path = Path(raws_path) / nav_mode / user_id / policy / storage_type
        if not storage_path.exists():
            continue

        total = 0

        if storage_type == 'indexeddb':
            uncat_file = storage_path / 'UNCATEGORIZED.json'
            if uncat_file.exists():
                try:
                    with open(uncat_file, 'r', encoding='utf-8') as f:
                        total += len(json.load(f))
                except Exception as e:
                    print(f"Error loading {uncat_file}: {e}")
        else:
            for lc in ['added', 'modified', 'removed']:
                uncat_file = storage_path / lc / 'UNCATEGORIZED.json'
                if uncat_file.exists():
                    try:
                        with open(uncat_file, 'r', encoding='utf-8') as f:
                            total += len(json.load(f))
                    except Exception as e:
                        print(f"Error loading {uncat_file}: {e}")

        if total:
            counts[storage_type] = total

    return counts


def get_cookie_security(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts httpOnly/secure/sameSite/third-party + a security posture
    label for a cookie item. Same posture rule as
    analysis/consolidated_analysis.py: both flags set -> 'Secure', neither
    -> 'Lowly Secure', else 'Partially Secure'.
    """
    http_only = item.get('httpOnly', False)
    secure = item.get('secure', False)
    samesite = normalize_samesite(item.get('sameSite'))
    is_tp = is_third_party(item.get('domain', ''), item.get('initial_url', ''))
    thirdparty = 'Third-Party' if is_tp else 'First-Party'

    if not http_only and not secure:
        posture = 'Lowly Secure'
    elif http_only and secure:
        posture = 'Secure'
    else:
        posture = 'Partially Secure'

    return {
        'httpOnly': http_only,
        'secure': secure,
        'sameSite': samesite,
        'thirdparty': thirdparty,
        'security_posture': posture
    }


def _empty_cookie_security_rollup() -> Dict[str, Any]:
    """Empty accumulator shape for rolling up cookie_security across profiles."""
    return {
        'total_cookies': 0,
        'httponly_distribution': {},
        'secure_distribution': {},
        'samesite_distribution': {},
        'thirdparty_distribution': {},
        'security_posture_distribution': {}
    }


def merge_cookie_security_rollup(dest: Dict[str, Any], source: Dict[str, Any]) -> None:
    """Adds one profile's cookie_security block into a rollup accumulator in place."""
    dest['total_cookies'] += source.get('total_cookies', 0)
    for dist_key in ('httponly_distribution', 'secure_distribution', 'samesite_distribution',
                     'thirdparty_distribution', 'security_posture_distribution'):
        for k, count in source.get(dist_key, {}).items():
            dest[dist_key][k] = dest[dist_key].get(k, 0) + count


class PIIAggregator:
    """Aggregate PII across all storage types and lifecycles (country extension)."""

    def __init__(self, base_path: str, raws_path: str, output_path: str, users: List[str] = None):
        self.base_path = base_path
        self.raws_path = raws_path
        self.output_path = output_path
        self.users = users or resolve_users(None)
        self.nav_modes = ['AUTH', 'NOTAUTH']
        self.policies = ['PARTIAL']
        self.storage_types = ['cookies', 'indexeddb', 'localstorage', 'sessionstorage']
        self.lifecycles = ['added', 'modified', 'removed']

    def aggregate_for_profile(self, nav_mode: str, user_id: str, policy: str) -> Dict[str, Any]:
        """Aggregate all PII for a specific user/mode/policy combination."""
        print(f"\nAggregating PII for {nav_mode}/{user_id}/{policy}...")

        all_data = load_all_user_data(self.base_path, nav_mode, user_id, policy)

        aggregation = {
            'profile_id': f"{nav_mode}_{user_id}_{policy}",
            'nav_mode': nav_mode,
            'user_id': user_id,
            'policy': policy,
            'summary': {
                'total_items': 0,
                'by_storage_type': {},
                'by_category': {},
                'by_lifecycle': {},
                # UNCATEGORIZED items were relocated to data/user_countries_raws/
                # by clean_user_folder.py, so they never appear in by_storage_type/
                # by_category above (same as the FR pipeline). Reported separately
                # here so total data volume (including what stayed uncategorized)
                # can still be compared across auth modes.
                'uncategorized_by_storage_type': {},
                'uncategorized_items': 0,
                'total_items_with_uncategorized': 0,
                # Cookie security non-conformity, by PII category. Only cookies
                # carry httpOnly/secure/sameSite - other storage types are
                # omitted from this block entirely.
                'cookie_security': {
                    'total_cookies': 0,
                    'httponly_distribution': {},
                    'secure_distribution': {},
                    'samesite_distribution': {},
                    'thirdparty_distribution': {},
                    'security_posture_distribution': {},
                    'by_category': {}
                }
            },
            'pii_instances': {
                'DIRECT_PII': [],
                'IDENTITY_TRACKING': [],
                'ID_SOLUTIONS_AND_EXCHANGES': [],
                'NAVIGATION_HISTORY': [],
                'LOCATION_AND_DEMOGRAPHICS': [],
                'BEHAVIORAL_DATA': [],
                'DIRECT_PII_KEYS': [],
                'SENSITIVE_LOCATION_PII': [],
                'other': []
            },
            'persistence_metrics': {
                'by_storage_type': {},
                'by_category': {}
            }
        }

        cookie_sec = aggregation['summary']['cookie_security']

        for storage_type, items in all_data.items():
            if not items:
                continue

            storage_count = len(items)
            aggregation['summary']['total_items'] += storage_count
            aggregation['summary']['by_storage_type'][storage_type] = storage_count

            category_counts = count_by_category(items)
            for category, count in category_counts.items():
                aggregation['summary']['by_category'][category] = \
                    aggregation['summary']['by_category'].get(category, 0) + count

            for item in items:
                lifecycle = item.get('_metadata', {}).get('lifecycle', 'unknown')
                aggregation['summary']['by_lifecycle'][lifecycle] = \
                    aggregation['summary']['by_lifecycle'].get(lifecycle, 0) + 1

            for category in aggregation['pii_instances'].keys():
                category_items = filter_by_category(items, category)

                for item in category_items:
                    pii_instance = {
                        'storage_type': storage_type,
                        'lifecycle': item.get('_metadata', {}).get('lifecycle'),
                        'key': get_storage_key(item),
                        'value': extract_pii_value(item),
                        'category': category
                    }

                    if 'domain' in item:
                        pii_instance['domain'] = item['domain']

                    if storage_type == 'cookies':
                        pii_instance.update(get_cookie_security(item))

                    aggregation['pii_instances'][category].append(pii_instance)

            if storage_type == 'cookies':
                for item in items:
                    category = item.get('_metadata', {}).get('category', 'UNCATEGORIZED')
                    sec = get_cookie_security(item)

                    cookie_sec['total_cookies'] += 1
                    cookie_sec['httponly_distribution'][str(sec['httpOnly'])] = \
                        cookie_sec['httponly_distribution'].get(str(sec['httpOnly']), 0) + 1
                    cookie_sec['secure_distribution'][str(sec['secure'])] = \
                        cookie_sec['secure_distribution'].get(str(sec['secure']), 0) + 1
                    cookie_sec['samesite_distribution'][sec['sameSite']] = \
                        cookie_sec['samesite_distribution'].get(sec['sameSite'], 0) + 1
                    cookie_sec['thirdparty_distribution'][sec['thirdparty']] = \
                        cookie_sec['thirdparty_distribution'].get(sec['thirdparty'], 0) + 1
                    cookie_sec['security_posture_distribution'][sec['security_posture']] = \
                        cookie_sec['security_posture_distribution'].get(sec['security_posture'], 0) + 1

                    if category not in cookie_sec['by_category']:
                        cookie_sec['by_category'][category] = {
                            'total': 0,
                            'httponly_true': 0,
                            'httponly_false': 0,
                            'secure_true': 0,
                            'secure_false': 0,
                            'thirdparty_true': 0,
                            'thirdparty_false': 0,
                            'samesite': {},
                            'security_posture': {}
                        }
                    cat_sec = cookie_sec['by_category'][category]
                    cat_sec['total'] += 1
                    cat_sec['httponly_true'] += 1 if sec['httpOnly'] else 0
                    cat_sec['httponly_false'] += 0 if sec['httpOnly'] else 1
                    cat_sec['secure_true'] += 1 if sec['secure'] else 0
                    cat_sec['secure_false'] += 0 if sec['secure'] else 1
                    cat_sec['thirdparty_true'] += 1 if sec['thirdparty'] == 'Third-Party' else 0
                    cat_sec['thirdparty_false'] += 0 if sec['thirdparty'] == 'Third-Party' else 1
                    cat_sec['samesite'][sec['sameSite']] = cat_sec['samesite'].get(sec['sameSite'], 0) + 1
                    cat_sec['security_posture'][sec['security_posture']] = \
                        cat_sec['security_posture'].get(sec['security_posture'], 0) + 1

            aggregation['persistence_metrics']['by_storage_type'][storage_type] = \
                self._calculate_persistence(items)

        all_items = []
        for items in all_data.values():
            all_items.extend(items)

        for category in get_pii_categories():
            category_items = filter_by_category(all_items, category)
            if category_items:
                aggregation['persistence_metrics']['by_category'][category] = \
                    self._calculate_persistence(category_items)

        uncategorized_counts = load_uncategorized_counts(self.raws_path, nav_mode, user_id, policy)
        aggregation['summary']['uncategorized_by_storage_type'] = uncategorized_counts
        aggregation['summary']['uncategorized_items'] = sum(uncategorized_counts.values())
        aggregation['summary']['total_items_with_uncategorized'] = (
            aggregation['summary']['total_items'] + aggregation['summary']['uncategorized_items']
        )

        return aggregation

    def _calculate_persistence(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate persistence metrics for a set of items."""
        lifecycle_counts = defaultdict(int)

        for item in items:
            lifecycle = item.get('_metadata', {}).get('lifecycle', 'unknown')
            lifecycle_counts[lifecycle] += 1

        total = len(items)

        return {
            'total_items': total,
            'added': lifecycle_counts.get('added', 0),
            'modified': lifecycle_counts.get('modified', 0),
            'removed': lifecycle_counts.get('removed', 0),
            'persistence_ratio': (
                (lifecycle_counts.get('added', 0) + lifecycle_counts.get('modified', 0)) / total
                if total > 0 else 0
            )
        }

    def generate_comparative_analysis(self) -> Dict[str, Any]:
        """Generate comparative analysis across all profiles."""
        print("\n" + "="*80)
        print("Generating Comparative Analysis")
        print("="*80)

        comparative = {
            'by_user': {},
            'by_nav_mode': {},
            'by_policy': {},
            'overall_statistics': {
                'total_profiles': 0,
                'total_pii_instances': 0,
                'by_category': {},
                'total_uncategorized_items': 0,
                'total_pii_instances_with_uncategorized': 0,
                'cookie_security': _empty_cookie_security_rollup()
            }
        }

        all_aggregations = []

        for nav_mode in self.nav_modes:
            for user_id in self.users:
                for policy in self.policies:
                    agg = self.aggregate_for_profile(nav_mode, user_id, policy)
                    all_aggregations.append(agg)

                    output_file = Path(self.output_path) / nav_mode / user_id / policy / 'pii_aggregation_summary.json'
                    export_to_json(agg, str(output_file))

        comparative['overall_statistics']['total_profiles'] = len(all_aggregations)

        for agg in all_aggregations:
            user_id = agg['user_id']
            nav_mode = agg['nav_mode']
            policy = agg['policy']
            uncategorized_items = agg['summary'].get('uncategorized_items', 0)
            total_with_uncat = agg['summary'].get('total_items_with_uncategorized', agg['summary']['total_items'])
            cookie_sec = agg['summary'].get('cookie_security', {})

            if user_id not in comparative['by_user']:
                comparative['by_user'][user_id] = {
                    'total_items': 0,
                    'total_items_with_uncategorized': 0,
                    'by_policy': {},
                    'by_nav_mode': {},
                    'cookie_security': _empty_cookie_security_rollup()
                }

            comparative['by_user'][user_id]['total_items'] += agg['summary']['total_items']
            comparative['by_user'][user_id]['total_items_with_uncategorized'] += total_with_uncat
            comparative['by_user'][user_id]['by_policy'][policy] = agg['summary']['total_items']
            comparative['by_user'][user_id]['by_nav_mode'][nav_mode] = \
                comparative['by_user'][user_id]['by_nav_mode'].get(nav_mode, 0) + agg['summary']['total_items']

            merge_cookie_security_rollup(comparative['by_user'][user_id]['cookie_security'], cookie_sec)

            if nav_mode not in comparative['by_nav_mode']:
                comparative['by_nav_mode'][nav_mode] = {
                    'total_items': 0,
                    'total_items_with_uncategorized': 0,
                    'by_user': {},
                    'by_policy': {}
                }

            comparative['by_nav_mode'][nav_mode]['total_items'] += agg['summary']['total_items']
            comparative['by_nav_mode'][nav_mode]['total_items_with_uncategorized'] += total_with_uncat
            comparative['by_nav_mode'][nav_mode]['by_user'][user_id] = \
                comparative['by_nav_mode'][nav_mode]['by_user'].get(user_id, 0) + agg['summary']['total_items']
            comparative['by_nav_mode'][nav_mode]['by_policy'][policy] = \
                comparative['by_nav_mode'][nav_mode]['by_policy'].get(policy, 0) + agg['summary']['total_items']

            if policy not in comparative['by_policy']:
                comparative['by_policy'][policy] = {
                    'total_items': 0,
                    'by_user': {},
                    'by_nav_mode': {}
                }

            comparative['by_policy'][policy]['total_items'] += agg['summary']['total_items']
            comparative['by_policy'][policy]['by_user'][user_id] = \
                comparative['by_policy'][policy]['by_user'].get(user_id, 0) + agg['summary']['total_items']
            comparative['by_policy'][policy]['by_nav_mode'][nav_mode] = \
                comparative['by_policy'][policy]['by_nav_mode'].get(nav_mode, 0) + agg['summary']['total_items']

            comparative['overall_statistics']['total_pii_instances'] += agg['summary']['total_items']
            comparative['overall_statistics']['total_uncategorized_items'] += uncategorized_items
            comparative['overall_statistics']['total_pii_instances_with_uncategorized'] += total_with_uncat
            merge_cookie_security_rollup(comparative['overall_statistics']['cookie_security'], cookie_sec)

            for category, count in agg['summary']['by_category'].items():
                comparative['overall_statistics']['by_category'][category] = \
                    comparative['overall_statistics']['by_category'].get(category, 0) + count

        return comparative

    def run(self):
        """Run complete PII aggregation analysis."""
        print("="*80)
        print("PII AGGREGATION ANALYSIS - country extension")
        print("="*80)

        comparative = self.generate_comparative_analysis()

        comparative_file = Path(self.output_path).parent / 'reports' / 'pii_comparative_analysis.json'
        export_to_json(comparative, str(comparative_file))

        print("\n" + "="*80)
        print("PII Aggregation Complete!")
        print("="*80)
        print(f"Total profiles analyzed: {comparative['overall_statistics']['total_profiles']}")
        print(f"Total PII instances: {comparative['overall_statistics']['total_pii_instances']}")
        print(f"Total UNCATEGORIZED items (separate): {comparative['overall_statistics']['total_uncategorized_items']}")
        print(f"Total cookies analyzed for security: {comparative['overall_statistics']['cookie_security']['total_cookies']}")
        print(f"\nTop 5 PII categories:")

        sorted_categories = sorted(
            comparative['overall_statistics']['by_category'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        for category, count in sorted_categories:
            print(f"  - {category}: {count}")

        print(f"\nCookie security posture:")
        for posture, count in comparative['overall_statistics']['cookie_security']['security_posture_distribution'].items():
            print(f"  - {posture}: {count}")


def main(users=None):
    """Main entry point."""
    base_path = Path(__file__).parent.parent.parent / 'data' / 'user_countries'
    raws_path = Path(__file__).parent.parent.parent / 'data' / 'user_countries_raws'
    output_path = Path(__file__).parent.parent / 'outputs'

    aggregator = PIIAggregator(str(base_path), str(raws_path), str(output_path), users=users)
    aggregator.run()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
