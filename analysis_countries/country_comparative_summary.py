#!/usr/bin/env python3
"""
Country comparative summary - one consolidated, per-country artifact for
cross-country comparison, pulling together everything requested:

- PII category prevalence (from analysis_gdpr_profiles_countries)
- Per-storage-type stats delineated by data category (from results_countries/
  storage_analysis outputs, merged across AUTH/NOTAUTH and lifecycles)
- Cookie lifetime distribution (from results_countries/ cookies consolidated
  output, merged across AUTH/NOTAUTH and lifecycles)
- Cookie security non-conformity by category (httpOnly/secure, security
  posture) - from analysis_gdpr_profiles_countries's cookie_security block
- Vulnerability / missing-security-flag by category - same cookie_security
  block (httponly_false / secure_false / 'Lowly Secure' counts)
- Third-party vs first-party provenance + top vendors (from results_countries/
  cookies + storage consolidated outputs, merged across AUTH/NOTAUTH)
- AUTH vs NOTAUTH data volume, including UNCATEGORIZED (from
  analysis_gdpr_profiles_countries's pii_comparative_analysis.json)

This script does not recompute anything - it merges the already-computed
per-profile JSON outputs of analysis_countries/ and
analysis_gdpr_profiles_countries/ (run both of those first). Output is one
JSON (full detail, per country) plus one flat CSV (headline metrics per
country, for quick spreadsheet comparison).
"""

import json
import csv
from pathlib import Path
from collections import defaultdict, Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / 'results_countries'
GDPR_OUTPUTS_DIR = PROJECT_ROOT / 'analysis_gdpr_profiles_countries' / 'outputs'
GDPR_REPORTS_DIR = PROJECT_ROOT / 'analysis_gdpr_profiles_countries' / 'reports'
OUTPUT_DIR = PROJECT_ROOT / 'analysis_countries' / 'comparative'

USERS = ['IT_0573', 'LU_0634', 'PT_0838', 'SE_0964', 'ES_0290', 'DE_0018']
AUTH_MODES = ['AUTH', 'NOTAUTH']
POLICY = 'PARTIAL'
COOKIE_LIFECYCLES = ['added', 'modified', 'deleted']  # 'removed' is remapped to 'deleted' on output
STORAGE_TYPES = ['localstorage', 'sessionstorage', 'indexeddb']
STORAGE_LIFECYCLES = ['added', 'modified', 'deleted']


def merge_counter_dict(target: dict, source: dict):
    for k, v in source.items():
        target[k] = target.get(k, 0) + v


def merge_nested_counter(target: dict, source: dict):
    for outer_k, inner in source.items():
        if outer_k not in target:
            target[outer_k] = {}
        merge_counter_dict(target[outer_k], inner)


def load_json(path: Path):
    if not path.exists():
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"  Error loading {path}: {e}")
        return None


def build_cookie_summary(user: str) -> dict:
    """Merges cookies/*/consolidated/analysis.json across AUTH+NOTAUTH+lifecycles."""
    summary = {
        'total_cookies': 0,
        'lifetime_distribution': {},
        'lifetime_by_pii': {},
        'thirdparty_distribution': {},
        'thirdparty_by_pii': {},
        'vendor_counts': {},
    }

    for auth in AUTH_MODES:
        for lc in COOKIE_LIFECYCLES:
            path = RESULTS_DIR / auth / user / POLICY / 'cookies' / lc / 'consolidated' / 'analysis.json'
            data = load_json(path)
            if not data:
                continue

            summary['total_cookies'] += data.get('total_cookies', 0)
            merge_counter_dict(summary['lifetime_distribution'], data.get('lifetime_distribution', {}))
            merge_nested_counter(summary['lifetime_by_pii'], data.get('lifetime_by_pii', {}))
            merge_counter_dict(summary['thirdparty_distribution'], data.get('thirdparty_distribution', {}))
            merge_nested_counter(summary['thirdparty_by_pii'], data.get('thirdparty_by_pii', {}))
            merge_counter_dict(summary['vendor_counts'], data.get('vendor_counts', {}))

    return summary


def build_storage_summary(user: str) -> dict:
    """Merges {storage_type}/*/consolidated/analysis.json across AUTH+NOTAUTH+lifecycles, per storage type."""
    by_storage_type = {}

    for storage_type in STORAGE_TYPES:
        agg = {
            'total_items': 0,
            'pii_by_category': {},
            'persistence_distribution': {},
            'vendor_counts': {},
        }

        for auth in AUTH_MODES:
            for lc in STORAGE_LIFECYCLES:
                path = RESULTS_DIR / auth / user / POLICY / storage_type / lc / 'consolidated' / 'analysis.json'
                data = load_json(path)
                if not data:
                    continue

                agg['total_items'] += data.get('total_items', 0)
                merge_nested_counter(agg['pii_by_category'], data.get('pii_by_category', {}))
                merge_counter_dict(agg['persistence_distribution'], data.get('persistence_distribution', {}))
                merge_counter_dict(agg['vendor_counts'], data.get('vendor_counts', {}))

        if agg['total_items'] > 0:
            by_storage_type[storage_type] = agg

    return by_storage_type


def build_country_summary(user: str) -> dict:
    print(f"Building comparative summary for {user}...")

    country = {
        'user_id': user,
        'category_prevalence': {},
        'auth_vs_notauth': {},
        'cookie_lifetime_and_provenance': build_cookie_summary(user),
        'cookie_security': {},
        'by_storage_type': build_storage_summary(user),
        'uncategorized': {},
    }

    total_by_category = Counter()
    cookie_sec_total_cookies = 0
    cookie_sec_httponly = Counter()
    cookie_sec_secure = Counter()
    cookie_sec_samesite = Counter()
    cookie_sec_thirdparty = Counter()
    cookie_sec_posture = Counter()
    cookie_sec_by_category = {}
    uncategorized_by_auth = {}
    total_items_by_auth = {}

    for auth in AUTH_MODES:
        profile_path = GDPR_OUTPUTS_DIR / auth / user / POLICY / 'pii_aggregation_summary.json'
        profile = load_json(profile_path)
        if not profile:
            continue

        summary = profile.get('summary', {})
        for cat, count in summary.get('by_category', {}).items():
            total_by_category[cat] += count

        total_items_by_auth[auth] = summary.get('total_items', 0)
        uncategorized_by_auth[auth] = summary.get('uncategorized_items', 0)

        cs = summary.get('cookie_security', {})
        cookie_sec_total_cookies += cs.get('total_cookies', 0)
        merge_counter_dict(cookie_sec_httponly, cs.get('httponly_distribution', {}))
        merge_counter_dict(cookie_sec_secure, cs.get('secure_distribution', {}))
        merge_counter_dict(cookie_sec_samesite, cs.get('samesite_distribution', {}))
        merge_counter_dict(cookie_sec_thirdparty, cs.get('thirdparty_distribution', {}))
        merge_counter_dict(cookie_sec_posture, cs.get('security_posture_distribution', {}))
        for cat, catdata in cs.get('by_category', {}).items():
            if cat not in cookie_sec_by_category:
                cookie_sec_by_category[cat] = {
                    'total': 0, 'httponly_true': 0, 'httponly_false': 0,
                    'secure_true': 0, 'secure_false': 0,
                    'thirdparty_true': 0, 'thirdparty_false': 0,
                    'samesite': {}, 'security_posture': {}
                }
            dest = cookie_sec_by_category[cat]
            dest['total'] += catdata.get('total', 0)
            dest['httponly_true'] += catdata.get('httponly_true', 0)
            dest['httponly_false'] += catdata.get('httponly_false', 0)
            dest['secure_true'] += catdata.get('secure_true', 0)
            dest['secure_false'] += catdata.get('secure_false', 0)
            dest['thirdparty_true'] += catdata.get('thirdparty_true', 0)
            dest['thirdparty_false'] += catdata.get('thirdparty_false', 0)
            merge_counter_dict(dest['samesite'], catdata.get('samesite', {}))
            merge_counter_dict(dest['security_posture'], catdata.get('security_posture', {}))

    country['category_prevalence'] = dict(total_by_category)
    country['auth_vs_notauth'] = {
        'total_items_by_auth': total_items_by_auth,
        'uncategorized_items_by_auth': uncategorized_by_auth,
        'total_items_with_uncategorized_by_auth': {
            auth: total_items_by_auth.get(auth, 0) + uncategorized_by_auth.get(auth, 0)
            for auth in AUTH_MODES
        }
    }
    country['cookie_security'] = {
        'total_cookies': cookie_sec_total_cookies,
        'httponly_distribution': dict(cookie_sec_httponly),
        'secure_distribution': dict(cookie_sec_secure),
        'samesite_distribution': dict(cookie_sec_samesite),
        'thirdparty_distribution': dict(cookie_sec_thirdparty),
        'security_posture_distribution': dict(cookie_sec_posture),
        'by_category': cookie_sec_by_category,
        # Vulnerability shorthand: cookies missing BOTH httpOnly and secure
        # flags ('Lowly Secure' posture), per category
        'missing_both_flags_by_category': {
            cat: data.get('security_posture', {}).get('Lowly Secure', 0)
            for cat, data in cookie_sec_by_category.items()
        }
    }

    return country


def write_csv(countries: dict, output_path: Path):
    """Flat headline-metrics CSV, one row per country, for quick spreadsheet comparison."""
    fieldnames = [
        'country', 'total_categorized_items', 'total_uncategorized_items',
        'total_items_with_uncategorized',
        'auth_total', 'notauth_total', 'ratio_notauth_vs_auth',
        'total_cookies',
        'cookies_httponly_true_pct', 'cookies_secure_true_pct',
        'cookies_secure_pct', 'cookies_partially_secure_pct', 'cookies_lowly_secure_pct',
        'top_pii_category', 'top_pii_category_count',
        'top_vendor', 'top_vendor_count',
        'thirdparty_pct'
    ]

    rows = []
    for user, c in countries.items():
        auth_total = c['auth_vs_notauth']['total_items_by_auth'].get('AUTH', 0)
        notauth_total = c['auth_vs_notauth']['total_items_by_auth'].get('NOTAUTH', 0)
        uncat_total = sum(c['auth_vs_notauth']['uncategorized_items_by_auth'].values())
        total_categorized = sum(c['auth_vs_notauth']['total_items_by_auth'].values())

        cookie_total = c['cookie_security']['total_cookies']
        posture = c['cookie_security']['security_posture_distribution']
        httponly_dist = c['cookie_security']['httponly_distribution']
        secure_dist = c['cookie_security']['secure_distribution']

        top_cat, top_cat_count = (max(c['category_prevalence'].items(), key=lambda x: x[1])
                                   if c['category_prevalence'] else ('', 0))

        vendor_counts = c['cookie_lifetime_and_provenance']['vendor_counts']
        top_vendor, top_vendor_count = (max(vendor_counts.items(), key=lambda x: x[1])
                                         if vendor_counts else ('', 0))

        tp_dist = c['cookie_lifetime_and_provenance']['thirdparty_distribution']
        tp_total = sum(tp_dist.values())
        thirdparty_pct = (tp_dist.get('Third-Party', 0) / tp_total * 100) if tp_total else 0

        rows.append({
            'country': user,
            'total_categorized_items': total_categorized,
            'total_uncategorized_items': uncat_total,
            'total_items_with_uncategorized': total_categorized + uncat_total,
            'auth_total': auth_total,
            'notauth_total': notauth_total,
            'ratio_notauth_vs_auth': round(notauth_total / auth_total, 2) if auth_total else '',
            'total_cookies': cookie_total,
            'cookies_httponly_true_pct': round(httponly_dist.get('True', 0) / cookie_total * 100, 1) if cookie_total else '',
            'cookies_secure_true_pct': round(secure_dist.get('True', 0) / cookie_total * 100, 1) if cookie_total else '',
            'cookies_secure_pct': round(posture.get('Secure', 0) / cookie_total * 100, 1) if cookie_total else '',
            'cookies_partially_secure_pct': round(posture.get('Partially Secure', 0) / cookie_total * 100, 1) if cookie_total else '',
            'cookies_lowly_secure_pct': round(posture.get('Lowly Secure', 0) / cookie_total * 100, 1) if cookie_total else '',
            'top_pii_category': top_cat,
            'top_pii_category_count': top_cat_count,
            'top_vendor': top_vendor,
            'top_vendor_count': top_vendor_count,
            'thirdparty_pct': round(thirdparty_pct, 1)
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    countries = {}
    for user in USERS:
        countries[user] = build_country_summary(user)

    json_output = OUTPUT_DIR / 'country_comparison.json'
    with open(json_output, 'w', encoding='utf-8') as f:
        json.dump(countries, f, indent=2, ensure_ascii=False)
    print(f"\nFull comparison written to: {json_output}")

    csv_output = OUTPUT_DIR / 'country_comparison_headline.csv'
    write_csv(countries, csv_output)
    print(f"Headline CSV written to: {csv_output}")


if __name__ == '__main__':
    main()
