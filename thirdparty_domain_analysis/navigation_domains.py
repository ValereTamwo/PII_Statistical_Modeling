"""
Navigation-assignment domain lookup for IndexedDB third-party detection.

Unlike localStorage/sessionStorage, IndexedDB is organized per-origin (one
source file per site domain), so a domain comparison is meaningful - the
same idiom already used for cookies by analysis/analyze_by_category.py's
is_third_party() (domain vs. initial_url), applied here against the list of
sites the persona was actually assigned to navigate to
(data/user_sites/navigation_par_persona_final.json) rather than against a
single page's initial_url.

Empirically verified: this raises IndexedDB's third-party share sharply
(category proxy ~8%/27% -> domain method ~82%/89% for FR/countries),
concentrated mostly in embedded resources (e.g. YouTube) absent from every
persona's assigned site list - a genuine third-party embed the old
category-based proxy missed entirely.
"""

import json
from pathlib import Path
from typing import Dict, Set

_NAV_PATH = (
    Path(__file__).resolve().parent.parent
    / "data" / "user_sites" / "navigation_par_persona_final.json"
)


def clean_domain(d: str) -> str:
    d = (d or "").strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def _load_navigation() -> Dict[str, Set[str]]:
    if not _NAV_PATH.exists():
        return {}
    with open(_NAV_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return {user: {clean_domain(site) for site in sites} for user, sites in raw.items()}


_NAVIGATION_BY_USER = _load_navigation()


def get_assigned_domains(user_id: str) -> Set[str]:
    """Cleaned set of domains this persona was assigned to navigate to. Empty if unknown."""
    return _NAVIGATION_BY_USER.get(user_id, set())


def is_assigned_domain(domain: str, assigned: Set[str]) -> bool:
    """True if `domain` is (or is a subdomain of) one of the assigned domains."""
    if not domain or not assigned:
        return False
    d = clean_domain(domain)
    return any(d == a or d.endswith("." + a) for a in assigned)
