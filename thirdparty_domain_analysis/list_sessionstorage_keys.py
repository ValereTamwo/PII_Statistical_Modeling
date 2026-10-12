#!/usr/bin/env python3
"""
Dumps every distinct sessionStorage key found in data/user_countries/, with
volume, cross-site spread, current match status, and an example value, for
manual investigation. Read-only - touches nothing under data/.

A key's "distinct_domains_seen" count is a useful signal on its own: a key
that appears identically across many unrelated site domains is far more
likely to be a shared third-party SDK than site-specific first-party code.

Usage:
    python3 thirdparty_domain_analysis/list_sessionstorage_keys.py
"""

import csv
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from thirdparty_domain_analysis.vendor_lookup import lookup_vendor_for_key

MANUAL_PATH = ROOT / "thirdparty_domain_analysis" / "sources" / "manual_session_trackers_candidates.csv"


def load_manual():
    exact, prefixes = {}, []
    with open(MANUAL_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = row["Cookie / Data Key name"].strip()
            entry = {"vendor": row["Platform"].strip(), "confidence": row["confidence"].strip()}
            if row["Wildcard match"].strip() == "1":
                prefixes.append((key, entry))
            else:
                exact[key] = entry
    return exact, prefixes


MANUAL_EXACT, MANUAL_PREFIX = load_manual()


def manual_lookup(key):
    if key in MANUAL_EXACT:
        return MANUAL_EXACT[key]
    for prefix, entry in MANUAL_PREFIX:
        if key.startswith(prefix):
            return entry
    return None


def item_key(it):
    return it.get("key") or it.get("name")


def domain_of(url):
    try:
        d = urlparse(url).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except Exception:
        return ""


def main():
    counts = defaultdict(int)
    domains = defaultdict(set)
    examples = {}

    for f in glob.glob("data/user_countries/*/*/PARTIAL/sessionstorage/**/*.json", recursive=True):
        if f.endswith("UNCATEGORIZED.json"):
            continue
        try:
            items = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for it in items:
            k = item_key(it)
            if not k:
                continue
            counts[k] += 1
            d = domain_of(it.get("initial_url", ""))
            if d:
                domains[k].add(d)
            if k not in examples:
                examples[k] = str(it.get("value"))[:150]

    rows = []
    for k, c in counts.items():
        ocd_tcf = lookup_vendor_for_key(k)
        man = manual_lookup(k) if not ocd_tcf else None
        if ocd_tcf:
            matched_by, vendor, confidence = ocd_tcf["source"], ocd_tcf["vendor"], ""
        elif man:
            matched_by, vendor, confidence = "manual", man["vendor"], man["confidence"]
        else:
            matched_by, vendor, confidence = "", "", ""
        rows.append({
            "key": k,
            "count": c,
            "distinct_domains_seen": len(domains[k]),
            "matched_by": matched_by,
            "vendor": vendor,
            "confidence": confidence,
            "example_value": examples[k],
        })

    rows.sort(key=lambda r: -r["count"])

    out_path = ROOT / "thirdparty_domain_analysis" / "sources" / "sessionstorage_all_keys.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"distinct keys: {len(rows):,}")
    print(f"total items:   {sum(r['count'] for r in rows):,}")
    print(f"written to {out_path}")


if __name__ == "__main__":
    main()
