"""
Vendor key lookup for localStorage/sessionStorage third-party detection.

localStorage/sessionStorage is strictly same-origin (the raw collector only
ever records one page URL per snapshot - see preprocessing_countries/
extract_localstorage.py - there is no per-frame origin to compare against),
so a domain-based third-party check (the kind used for cookies via
analysis/analyze_by_category.py's is_third_party(), and for IndexedDB via
navigation_domains.py) is structurally meaningless here. The only sound
signal is recognizing a known vendor SDK's key-naming convention, sourced
from two complementary CSVs under sources/:

- open_cookie_database.csv (OCD): a general cookie/storage-key database,
  NOT ad-tech-specific - its Platform column includes real third-party
  vendors (Google Analytics, Cookiebot, Adform) but also CMS/platform
  self-identification (Magento, WordPress, Shopify) writing their own
  first-party operational keys. Verified by hand: 353 of 354 distinct
  Platform values are genuine company names, so Platform alone isn't a
  reliable third-party signal here. Domain is: rows with a populated
  Domain (Google Analytics' __utmv -> google-analytics.com, Cookiebot's
  userlang -> cookiebot.com) are genuine third-party signatures; rows with
  an empty Domain (Magento's mage-cache-timeout, WordPress's
  wp-settings-) are the site's own CMS, not data reaching an external
  company. Rule: OCD rows only count if Domain is non-empty.

- tcf_storage_clean.csv (TCF): derived from the IAB TCF Global Vendor
  List, which by construction only lists advertising/tracking vendors (no
  CMS platforms at all - verified no Magento/WordPress/Shopify/Elementor
  entries exist in it). Here Platform alone is already a sufficient
  third-party signal, which is why ~37% of its rows (941/2537) have an
  empty Domain (the GVL declaration just didn't specify a resource domain
  for that particular key) without that meaning first-party - unlike OCD,
  TCF rows are NOT filtered on Domain.

Measured on real data: OCD alone covers only ~3.7% of localStorage/
sessionStorage items in the country dataset (its Platform-but-not-ad-tech
scope misses a lot of pure ad-tech key-naming, e.g. id5id, _gcl_ls,
__rtbh.uid, cto_bundle, _grecaptcha - all absent from OCD, all present in
TCF). The two sources overlap on only ~15% of their matched keys, so using
them together meaningfully raises coverage rather than being redundant.

- tiers_surs_sessionstorage.csv (third source): a hand-researched list
  specifically targeting sessionStorage keys that OCD+TCF both missed
  (session-scoped trackers: RUM/monitoring SDKs, chat widgets, Shopify-app
  vendors, pixel SDKs - categories structurally under-represented in OCD
  and entirely out of TCF's advertising-only scope). Every row cites an
  external source (vendor documentation or a third-party declaration) and
  has a non-empty Domain - verified, no filtering needed. Matching is
  always done through its own 'regex' column (not 'Cookie / Data Key
  name' or 'Wildcard match' - the two disagree row to row: 71 of 86 rows
  have a 'Cookie / Data Key name' that differs from 'regex', e.g. a bare
  prefix "__klarna_sdk_" vs its anchored regex "^__klarna_sdk_", or
  sometimes the key-name column already holds a full regex itself; 'regex'
  is the one column guaranteed to be a directly usable, already-anchored
  pattern for every row - checked via re.search()). Read with
  utf-8-sig (the file carries a UTF-8 BOM).

Wildcard match values (same convention in OCD/TCF):
  '0' - exact match
  '1' - key-name prefix, matched via str.startswith()
  '2' - TCF only: a full regex pattern (e.g. "^.*_key$"), already
        self-anchored with ^...$ - matched via re.search()
"""

import csv
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_SOURCES_DIR = Path(__file__).resolve().parent / "sources"
_OCD_PATH = _SOURCES_DIR / "open_cookie_database.csv"
_TCF_PATH = _SOURCES_DIR / "tcf_storage_clean.csv"
_CONFIRMED_PATH = _SOURCES_DIR / "tiers_surs_sessionstorage.csv"

Entry = Dict[str, str]


def _entry(row: dict, source: str) -> Entry:
    return {
        "vendor": row.get("Platform", "").strip(),
        "category": row.get("Category", "").strip(),
        "domain": row.get("Domain", "").strip(),
        "source": source,
    }


def _load_ocd() -> Tuple[Dict[str, Entry], List[Tuple[str, Entry]]]:
    """OCD: only rows with a non-empty Domain count (see module docstring)."""
    exact: Dict[str, Entry] = {}
    prefixes: List[Tuple[str, Entry]] = []

    with open(_OCD_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if not row.get("Domain", "").strip():
                continue
            key = row.get("Cookie / Data Key name", "").strip()
            if not key:
                continue
            entry = _entry(row, "ocd")
            if row.get("Wildcard match", "0").strip() == "1":
                prefixes.append((key, entry))
            else:
                exact[key] = entry

    return exact, prefixes


def _load_tcf() -> Tuple[Dict[str, Entry], List[Tuple[str, Entry]], List[Tuple["re.Pattern", Entry]]]:
    """TCF: every row counts regardless of Domain (see module docstring)."""
    exact: Dict[str, Entry] = {}
    prefixes: List[Tuple[str, Entry]] = []
    patterns: List[Tuple["re.Pattern", Entry]] = []

    with open(_TCF_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = row.get("Cookie / Data Key name", "").strip()
            if not key:
                continue
            entry = _entry(row, "tcf")
            wildcard = row.get("Wildcard match", "0").strip()
            if wildcard == "2":
                try:
                    patterns.append((re.compile(key), entry))
                except re.error:
                    continue
            elif wildcard == "1":
                prefixes.append((key, entry))
            else:
                exact[key] = entry

    return exact, prefixes, patterns


def _load_confirmed() -> List[Tuple["re.Pattern", Entry]]:
    """
    Manually-researched, externally-sourced sessionStorage vendor list.
    Every row is matched purely through its 'regex' column - see module
    docstring for why 'Cookie / Data Key name' and 'Wildcard match' aren't
    used here.
    """
    patterns: List[Tuple["re.Pattern", Entry]] = []

    if not _CONFIRMED_PATH.exists():
        return patterns

    with open(_CONFIRMED_PATH, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            pattern_str = row.get("regex", "").strip()
            if not pattern_str:
                continue
            try:
                pattern = re.compile(pattern_str)
            except re.error:
                continue
            patterns.append((pattern, _entry(row, "manual_confirmed")))

    return patterns


EXACT_KEY_TO_VENDOR_OCD, PREFIX_KEY_TO_VENDOR_OCD = _load_ocd()
EXACT_KEY_TO_VENDOR_TCF, PREFIX_KEY_TO_VENDOR_TCF, REGEX_KEY_TO_VENDOR_TCF = _load_tcf()
REGEX_KEY_TO_VENDOR_CONFIRMED = _load_confirmed()


def lookup_vendor_for_key(key: Optional[str]) -> Optional[Entry]:
    """
    Returns {"vendor": ..., "category": ..., "domain": ...,
    "source": "manual_confirmed"|"ocd"|"tcf"} if `key` matches a known
    vendor's localStorage/sessionStorage key-naming convention in any of
    the three sources, else None.

    The hand-researched, externally-sourced list (manual_confirmed) is
    checked FIRST, ahead of OCD and TCF - not just the most trustworthy of
    the three (every row cites a source), but in some cases a deliberate
    correction of a wrong TCF match: TCF's bulk-extracted regexes
    misattribute some keys (e.g. "sentryReplaySession" to "Triton Digital"
    instead of Sentry, "pushowl_current_config_key" to "Mediasmart" instead
    of PushOwl - both documented in tiers_surs_sessionstorage.csv's notes).
    Checking TCF first would silently let its wrong guess win before the
    correction is ever consulted, which defeats the point of adding it.
    """
    if not key:
        return None

    for pattern, entry in REGEX_KEY_TO_VENDOR_CONFIRMED:
        if pattern.search(key):
            return entry

    if key in EXACT_KEY_TO_VENDOR_OCD:
        return EXACT_KEY_TO_VENDOR_OCD[key]
    for prefix, entry in PREFIX_KEY_TO_VENDOR_OCD:
        if key.startswith(prefix):
            return entry

    if key in EXACT_KEY_TO_VENDOR_TCF:
        return EXACT_KEY_TO_VENDOR_TCF[key]
    for prefix, entry in PREFIX_KEY_TO_VENDOR_TCF:
        if key.startswith(prefix):
            return entry
    for pattern, entry in REGEX_KEY_TO_VENDOR_TCF:
        if pattern.search(key):
            return entry

    return None


def is_vendor_key(key: Optional[str]) -> bool:
    return lookup_vendor_for_key(key) is not None
