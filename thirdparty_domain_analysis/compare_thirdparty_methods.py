#!/usr/bin/env python3
"""
Compares two ways of flagging IndexedDB items as third-party, for both the
FR cluster (data/user, risk_analysis_PxI) and the country cluster
(data/user_countries, risk_analysis_PxI_countries):

  - CATEGORY PROXY (current items_vectorizer.py behaviour): an item is
    third-party if its PII category is one of THIRD_PARTY_CATEGORIES
    (ID_SOLUTIONS_AND_EXCHANGES, IDENTITY_TRACKING, SERVER_SIDE_TRACKING,
    UX_AND_PERFORMANCE_ANALYTICS). Content-based, ignores which domain
    actually wrote the data.
  - DOMAIN METHOD (proposed): an item is third-party if the domain its
    IndexedDB source_file belongs to is not one of the sites the persona
    was actually assigned to navigate to (data/user_sites/
    navigation_par_persona_final.json), using the same domain-suffix
    comparison already used for cookies (analysis/analyze_by_category.py's
    is_third_party()).

This is a read-only investigation tool: it never writes into data/user,
data/user_countries, or any pipeline output. It only reads existing
categorized IndexedDB files and the navigation assignment list, and writes
its own comparison report to thirdparty_comparison.json next to this
script.

Usage:
    python3 thirdparty_domain_analysis/compare_thirdparty_methods.py [--top-domains N]
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

THIRD_PARTY_CATEGORIES = {
    "ID_SOLUTIONS_AND_EXCHANGES",
    "IDENTITY_TRACKING",
    "SERVER_SIDE_TRACKING",
    "UX_AND_PERFORMANCE_ANALYTICS",
}

NON_PII_CATEGORY_FILES = {"UNCATEGORIZED", "INTERNAL_IDB_KEYS", "INFRASTRUCTURE"}

FR_USERS = ["FR_0417", "FR_0446", "FR_0458"]
FR_AUTH_STATUSES = ["Auth", "UnAuth"]
FR_POLICIES = ["ALL", "PARTIAL", "NONE"]

COUNTRY_USERS = [
    "IT_0573", "LU_0634", "PT_0838", "SE_0964", "ES_0290", "DE_0018",
    "FR_0429", "IE_0504", "NL_0694", "PL_0742", "AT_0077", "DK_0199", "FI_0373",
]
COUNTRY_AUTH_STATUSES = ["AUTH", "NOTAUTH"]
COUNTRY_POLICY = "PARTIAL"


def clean_domain(d: str) -> str:
    d = d.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def extract_domain_from_source_file(source_file: str):
    """Same logic as risk_analysis_PxI(_countries)/src/utils/items_vectorizer.py."""
    if not source_file:
        return None
    name = source_file.replace(".indexeddb.leveldb.json", "").replace(".json", "")
    parts = name.split("_", 1)
    if len(parts) == 2:
        return parts[1].rsplit("_", 1)[0]
    return None


def is_first_party_domain(domain: str, assigned_clean_domains: set) -> bool:
    """Same domain-suffix idiom as analysis/analyze_by_category.py's is_third_party()."""
    if not domain:
        return False
    d = clean_domain(domain)
    return any(d == a or d.endswith("." + a) for a in assigned_clean_domains)


def load_navigation_assignments():
    nav_path = ROOT / "data" / "user_sites" / "navigation_par_persona_final.json"
    nav = json.load(open(nav_path, "r", encoding="utf-8"))
    return {user: {clean_domain(s) for s in sites} for user, sites in nav.items()}


def iter_indexeddb_items(idb_dir: Path):
    if not idb_dir.exists():
        return
    for f in idb_dir.glob("*.json"):
        category = f.stem
        if category in NON_PII_CATEGORY_FILES:
            continue
        try:
            items = json.load(open(f, "r", encoding="utf-8"))
        except Exception:
            continue
        for item in items:
            yield category, item


def analyze_user(idb_dirs, assigned_domains, top_domains: int):
    """idb_dirs: list of Path, one per (auth, policy) combination for this user."""
    n_items = 0
    cat_tp = 0
    dom_tp = 0
    both_agree = 0
    newly_tp = Counter()      # domain -> item count (category said first-party, domain says third-party)
    newly_fp = Counter()      # domain -> item count (category said third-party, domain says first-party)
    sites_seen = set()
    sites_tp_by_domain = set()

    for idb_dir in idb_dirs:
        for category, item in iter_indexeddb_items(idb_dir):
            n_items += 1
            cat_is_tp = category in THIRD_PARTY_CATEGORIES
            src = item.get("source_file", "")
            sites_seen.add(src)
            domain = extract_domain_from_source_file(src)
            dom_is_tp = not is_first_party_domain(domain, assigned_domains)

            if cat_is_tp:
                cat_tp += 1
            if dom_is_tp:
                dom_tp += 1
                sites_tp_by_domain.add(src)

            if cat_is_tp == dom_is_tp:
                both_agree += 1
            elif dom_is_tp and not cat_is_tp:
                newly_tp[clean_domain(domain or "")] += 1
            elif cat_is_tp and not dom_is_tp:
                newly_fp[clean_domain(domain or "")] += 1

    def pct(a, b):
        return round(100 * a / b, 2) if b else 0.0

    def top_list(counter, total):
        return [
            {"domain": d, "items": c, "pct_of_total_items": pct(c, total)}
            for d, c in counter.most_common(top_domains)
        ]

    return {
        "n_assigned_sites": len(assigned_domains),
        "n_items": n_items,
        "n_distinct_indexeddb_sites": len(sites_seen),
        "n_distinct_sites_flagged_thirdparty_by_domain": len(sites_tp_by_domain),
        "category_proxy": {"thirdparty_items": cat_tp, "thirdparty_pct": pct(cat_tp, n_items)},
        "domain_method": {"thirdparty_items": dom_tp, "thirdparty_pct": pct(dom_tp, n_items)},
        "agreement_pct": pct(both_agree, n_items),
        "newly_flagged_thirdparty_by_domain_method": {
            "total_items": sum(newly_tp.values()),
            "pct_of_total_items": pct(sum(newly_tp.values()), n_items),
            "top_domains": top_list(newly_tp, n_items),
        },
        "newly_flagged_firstparty_by_domain_method": {
            "total_items": sum(newly_fp.values()),
            "pct_of_total_items": pct(sum(newly_fp.values()), n_items),
            "top_domains": top_list(newly_fp, n_items),
        },
    }


def aggregate_cluster(by_user: dict):
    agg = defaultdict(int)
    for stats in by_user.values():
        agg["n_items"] += stats["n_items"]
        agg["cat_tp"] += stats["category_proxy"]["thirdparty_items"]
        agg["dom_tp"] += stats["domain_method"]["thirdparty_items"]
        agg["newly_tp"] += stats["newly_flagged_thirdparty_by_domain_method"]["total_items"]
        agg["newly_fp"] += stats["newly_flagged_firstparty_by_domain_method"]["total_items"]

    def pct(a, b):
        return round(100 * a / b, 2) if b else 0.0

    n = agg["n_items"]
    return {
        "n_items": n,
        "category_proxy_thirdparty_pct": pct(agg["cat_tp"], n),
        "domain_method_thirdparty_pct": pct(agg["dom_tp"], n),
        "newly_flagged_thirdparty_pct": pct(agg["newly_tp"], n),
        "newly_flagged_firstparty_pct": pct(agg["newly_fp"], n),
    }


def run_cluster(users, idb_dirs_for_user, assignments, top_domains):
    by_user = {}
    for user in users:
        assigned = assignments.get(user, set())
        dirs = idb_dirs_for_user(user)
        by_user[user] = analyze_user(dirs, assigned, top_domains)
    return {"users": users, "by_user": by_user, "totals": aggregate_cluster(by_user)}


def main(top_domains: int = 15):
    assignments = load_navigation_assignments()

    fr_dirs = lambda user: [
        ROOT / "data" / "user" / auth / user / policy / "indexeddb"
        for auth in FR_AUTH_STATUSES for policy in FR_POLICIES
    ]
    country_dirs = lambda user: [
        ROOT / "data" / "user_countries" / auth / user / COUNTRY_POLICY / "indexeddb"
        for auth in COUNTRY_AUTH_STATUSES
    ]

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "method": {
            "category_proxy": (
                "An IndexedDB item is third-party if its PII category is one of "
                + ", ".join(sorted(THIRD_PARTY_CATEGORIES))
                + " (current behaviour of items_vectorizer.py)."
            ),
            "domain_method": (
                "An IndexedDB item is third-party if the domain of its source_file "
                "is not one of the sites the persona was assigned to navigate to "
                "(data/user_sites/navigation_par_persona_final.json), compared with "
                "the same domain-suffix rule used for cookies in "
                "analysis/analyze_by_category.py's is_third_party()."
            ),
            "newly_flagged_thirdparty_by_domain_method": (
                "Items the category proxy called first-party but the domain method "
                "calls third-party - the third parties that get added by switching "
                "methods, which is what this file is primarily for."
            ),
            "newly_flagged_firstparty_by_domain_method": (
                "Items the category proxy called third-party but the domain method "
                "calls first-party (the rarer, opposite disagreement)."
            ),
        },
        "clusters": {
            "fr": run_cluster(FR_USERS, fr_dirs, assignments, top_domains),
            "countries": run_cluster(COUNTRY_USERS, country_dirs, assignments, top_domains),
        },
    }

    out_path = Path(__file__).resolve().parent / "thirdparty_comparison.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    for cluster_name in ("fr", "countries"):
        t = report["clusters"][cluster_name]["totals"]
        print(f"{cluster_name}: items={t['n_items']:,}  "
              f"category_proxy_tp={t['category_proxy_thirdparty_pct']}%  "
              f"domain_method_tp={t['domain_method_thirdparty_pct']}%  "
              f"newly_flagged_tp={t['newly_flagged_thirdparty_pct']}%")
    print(f"\nWritten to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--top-domains", type=int, default=15,
                         help="How many top domains to list per disagreement bucket per user (default: 15)")
    args = parser.parse_args()
    main(top_domains=args.top_domains)
