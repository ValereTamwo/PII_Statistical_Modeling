"""
Consolidated Analysis Script - country extension.

Adapted from analysis/consolidated_analysis.py: identical metrics (lifetime,
httpOnly/secure/sameSite distributions, security matrix, third-party
cross-tabs, unified risk score, keywords, content/vendor/entropy privacy
metrics), but reads data/user_countries/ instead of data/user/, covers the
6 new-country personas (single PARTIAL policy, AUTH/NOTAUTH naming), and
writes to results_countries/ - fully separate from the FR pipeline.

Reuses analysis/privacy_metrics.py, analysis/analyze_by_category.py and
analysis/unified_risk_metrics.py directly (no FR-specific hardcoding in
those modules per investigation - no need to duplicate them).
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

# Reuse the FR pipeline's generic analysis modules directly (no duplication)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'analysis'))
import privacy_metrics as pm
from analyze_by_category import (
    calculate_lifetime_category,
    normalize_samesite,
    extract_keywords,
    is_third_party
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from countries_config import add_users_arg, resolve_users


def load_all_cookies(input_dir: Path) -> Tuple[List[Dict], List[Dict]]:
    """
    Load and categorize cookies from input directory.

    Returns:
        (direct_pii_cookies, other_cookies)
    """
    direct_pii_cookies = []
    other_cookies = []

    category_files = sorted(input_dir.glob('*.json'))

    for category_file in category_files:
        category_name = category_file.stem

        with open(category_file, 'r', encoding='utf-8') as f:
            cookies = json.load(f)

        for cookie in cookies:
            cookie['_category'] = category_name

        if category_name == 'DIRECT_PII':
            direct_pii_cookies.extend(cookies)
        else:
            other_cookies.extend(cookies)

    return direct_pii_cookies, other_cookies


def create_unified_pii_type(cookie: Dict) -> str:
    """
    Creates a unified PII type for a cookie.

    - If DIRECT_PII: returns the subcategory (email, gender, etc.)
    - Else: returns the category name (BEHAVIORAL_DATA, etc.)
    """
    category = cookie.get('_category', 'unknown')

    if category == 'DIRECT_PII':
        return cookie.get('matched_subcategory', 'unknown')
    else:
        return category


def analyze_consolidated(direct_pii_cookies: List[Dict], other_cookies: List[Dict]) -> Dict:
    """Consolidated analysis of all cookies."""
    all_cookies = direct_pii_cookies + other_cookies
    total = len(all_cookies)

    print(f"\n Consolidated Analysis")
    print(f"   DIRECT_PII: {len(direct_pii_cookies)} cookies")
    print(f"   Others: {len(other_cookies)} cookies")
    print(f"   TOTAL: {total} cookies\n")

    lifetime_dist = Counter()
    lifetime_by_pii = defaultdict(Counter)

    httponly_dist = Counter()
    httponly_by_pii = defaultdict(Counter)

    secure_dist = Counter()
    secure_by_pii = defaultdict(Counter)

    samesite_dist = Counter()
    samesite_by_pii = defaultdict(Counter)

    security_matrix = Counter()
    security_by_pii = defaultdict(Counter)

    thirdparty_dist = Counter()
    thirdparty_by_pii = defaultdict(Counter)
    thirdparty_httponly = Counter()
    thirdparty_secure = Counter()

    risk_levels = Counter()
    risk_by_pii = defaultdict(Counter)

    all_keywords = Counter()

    content_hierarchy = defaultdict(lambda: defaultdict(int))
    content_types = Counter()
    vendor_counts = Counter()
    category_vendor_flows = []
    entropy_lifetime_data = []
    entropy_by_pii = defaultdict(list)
    advanced_risk_levels = Counter()

    for cookie in all_cookies:
        pii_type = create_unified_pii_type(cookie)

        collection_timestamp = cookie.get('timestamp')
        if isinstance(collection_timestamp, str):
            try:
                collection_timestamp = datetime.fromisoformat(collection_timestamp.replace('Z', '+00:00')).timestamp()
            except:
                try:
                    collection_timestamp = float(collection_timestamp)
                except:
                    collection_timestamp = None

        lifetime_cat = calculate_lifetime_category(cookie.get('expires', -1), collection_timestamp)
        lifetime_dist[lifetime_cat] += 1
        lifetime_by_pii[pii_type][lifetime_cat] += 1

        http_only = cookie.get('httpOnly', False)
        httponly_dist[str(http_only)] += 1
        httponly_by_pii[pii_type][str(http_only)] += 1

        secure = cookie.get('secure', False)
        secure_dist[str(secure)] += 1
        secure_by_pii[pii_type][str(secure)] += 1

        samesite = normalize_samesite(cookie.get('sameSite'))
        samesite_dist[samesite] += 1
        samesite_by_pii[pii_type][samesite] += 1

        security_matrix[(http_only, secure)] += 1

        if not http_only and not secure:
            security_score = 'Lowly Secure'
        elif http_only and secure:
            security_score = 'Secure'
        else:
            security_score = 'Partially Secure'
        security_by_pii[pii_type][security_score] += 1

        is_tp = is_third_party(cookie.get('domain', ''), cookie.get('initial_url', ''))
        tp_status = 'Third-Party' if is_tp else 'First-Party'
        thirdparty_dist[tp_status] += 1
        thirdparty_by_pii[pii_type][tp_status] += 1
        thirdparty_httponly[(tp_status, http_only)] += 1
        thirdparty_secure[(tp_status, secure)] += 1

        from unified_risk_metrics import calculate_unified_risk_score

        cookie_item = cookie.copy()
        if '_category' not in cookie_item:
            cookie_item['_category'] = cookie.get('category', 'UNCATEGORIZED')

        risk_result = calculate_unified_risk_score(cookie_item, 'cookies')

        cookie['_unified_risk'] = risk_result

        risk_level = risk_result['risk_category']

        risk_levels[risk_level] += 1
        risk_by_pii[pii_type][risk_level] += 1

        keywords = extract_keywords(cookie.get('name', ''))
        all_keywords.update(keywords)

        privacy_analysis = pm.analyze_cookie_privacy(cookie)

        data_type = privacy_analysis['data_type']
        content_hierarchy[data_type][pii_type] += 1
        content_types[data_type] += 1

        vendor = privacy_analysis['vendor']
        vendor_counts[vendor] += 1
        category_vendor_flows.append((pii_type, vendor, 1))

        entropy = privacy_analysis['entropy']

        expires_val = cookie.get('expires', None)
        if isinstance(expires_val, (int, float)):
            try:
                duration_days = max(int((datetime.fromtimestamp(expires_val) - datetime.now()).total_seconds() / 86400), 0)
            except Exception:
                duration_days = -1
        elif isinstance(expires_val, str):
            try:
                exp_dt = datetime.fromisoformat(expires_val)
                duration_days = max(int((exp_dt - datetime.now()).total_seconds() / 86400), 0)
            except Exception:
                try:
                    exp_ts = int(expires_val)
                    duration_days = max(int((datetime.fromtimestamp(exp_ts) - datetime.now()).total_seconds() / 86400), 0)
                except Exception:
                    duration_days = -1
        else:
            duration_days = -1

        entropy_lifetime_data.append((entropy, duration_days, data_type))
        entropy_by_pii[pii_type].append(entropy)

        is_high_entropy = entropy > 4.0
        if is_high_entropy and is_tp and duration_days > 365:
            adv_risk = 'Critical'
        elif is_high_entropy and not http_only:
            adv_risk = 'High'
        elif is_high_entropy or (is_tp and duration_days > 365):
            adv_risk = 'Medium'
        else:
            adv_risk = 'Low'
        advanced_risk_levels[adv_risk] += 1

    flow_aggregated = defaultdict(int)
    for cat, vendor, count in category_vendor_flows:
        flow_aggregated[(cat, vendor)] += count
    category_vendor_flows_agg = [(cat, vendor, count) for (cat, vendor), count in flow_aggregated.items()]

    return {
        'total_cookies': total,
        'direct_pii_count': len(direct_pii_cookies),
        'other_count': len(other_cookies),

        'lifetime_distribution': dict(lifetime_dist),
        'lifetime_by_pii': {k: dict(v) for k, v in lifetime_by_pii.items()},
        'httponly_distribution': dict(httponly_dist),
        'httponly_by_pii': {k: dict(v) for k, v in httponly_by_pii.items()},
        'secure_distribution': dict(secure_dist),
        'secure_by_pii': {k: dict(v) for k, v in secure_by_pii.items()},
        'samesite_distribution': dict(samesite_dist),
        'samesite_by_pii': {k: dict(v) for k, v in samesite_by_pii.items()},
        'security_matrix': {str(k): v for k, v in security_matrix.items()},
        'security_by_pii': {k: dict(v) for k, v in security_by_pii.items()},
        'thirdparty_distribution': dict(thirdparty_dist),
        'thirdparty_by_pii': {k: dict(v) for k, v in thirdparty_by_pii.items()},
        'thirdparty_httponly': {f"{k[0]}_{k[1]}": v for k, v in thirdparty_httponly.items()},
        'thirdparty_secure': {f"{k[0]}_{k[1]}": v for k, v in thirdparty_secure.items()},
        'risk_levels': dict(risk_levels),
        'risk_by_pii': {k: dict(v) for k, v in risk_by_pii.items()},
        'keywords': dict(all_keywords.most_common(15)),

        'content_hierarchy': {k: dict(v) for k, v in content_hierarchy.items()},
        'content_types': dict(content_types),
        'vendor_counts': dict(vendor_counts),
        'category_vendor_flows': category_vendor_flows_agg,
        'entropy_lifetime_data': entropy_lifetime_data,
        'entropy_by_pii': {k: v for k, v in entropy_by_pii.items()},
        'advanced_risk_levels': dict(advanced_risk_levels)
    }


def main(users=None):
    """Main execution script for consolidated analysis (country extension)."""
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    output_base = Path(__file__).resolve().parent.parent / 'results_countries'

    if not base_dir.exists():
        print(f"Directory {base_dir} not found")
        return

    users = users or resolve_users(None)
    auth_statuses = ('AUTH', 'NOTAUTH')
    policies = ('PARTIAL',)

    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                for lifecycle in ['added', 'modified', 'removed']:
                    input_dir = base_dir / 'user_countries' / auth_status / user / policy / 'cookies' / lifecycle

                    output_lifecycle = 'deleted' if lifecycle == 'removed' else lifecycle
                    output_dir = output_base / auth_status / user / policy / 'cookies' / output_lifecycle

                    if not input_dir.exists():
                        print(f"Directory {input_dir} does not exist, skipping.")
                        continue

                    output_dir.mkdir(parents=True, exist_ok=True)

                    print(f"\n Loading {lifecycle} cookies...")
                    direct_pii_cookies, other_cookies = load_all_cookies(input_dir)

                    if len(direct_pii_cookies) == 0 and len(other_cookies) == 0:
                        print(f"  No cookies found for {lifecycle}, skipping.")
                        continue

                    analysis_results = analyze_consolidated(direct_pii_cookies, other_cookies)

                    output_path = output_dir / 'consolidated' / 'analysis.json'
                    output_path.parent.mkdir(parents=True, exist_ok=True)

                    serializable_results = {k: v for k, v in analysis_results.items()
                                        if k not in ['entropy_lifetime_data']}

                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(serializable_results, f, indent=2, ensure_ascii=False)

                    print(f" Results saved: {output_path}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
