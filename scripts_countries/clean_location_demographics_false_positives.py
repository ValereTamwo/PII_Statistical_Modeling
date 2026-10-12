#!/usr/bin/env python3
"""
Cleans false positives out of LOCATION_AND_DEMOGRAPHICS.json's 'general_loc'
subcategory - country extension.

regex_merged_v3.py's 'general_loc' pattern matches bare dictionary words
(country, region, state, city, zip, locale, timezone, ...) against either
the item's key name (match_type 'name') or its raw/decoded value content
(match_type 'value'). Both modes collide heavily with non-geographic data:

  - 'state' as a generic application/event/OAuth/deployment status field
    (YouTube's SLI_STATE_END/START, next-auth's CSRF state token, AWS
    deployment-state headers) rather than a US state - by far the largest
    single false-positive cluster.
  - 'zip' matching the literal substring "zip" inside the MIME declaration
    of "data:application/zip;base92,..." encoded blobs - nothing to do
    with postal codes, and (confirmed by direct count) the single largest
    false-positive source overall.
  - 'region' matching cloud/infra region codes (e.g. "eu-central-2").
  - 'state' matching an OAuth2 "...?state=<csrf-token>..." query parameter.
  - a location word used as an ID namespace prefix (e.g. "city-<uuid>").
  - a location word appearing as a bare category/filter label rather than
    an actual disclosed value (e.g. search_type="province").
  - 'state' as a JSON key holding a non-geographic value (null/true/false/
    a number/an empty string) inside an app-state blob (e.g.
    {"data":{"state":null},"_expires":...}).

Separately (not a 'general_loc' regex bug - confirmed by checking
regex_merged_v3.py directly, 'origin' is not in that pattern at all): the
AI categorization pass has filed 16 items named exactly 'origin' holding a
full site URL (e.g. "https://www.glamsport.it" - the page's web origin,
scheme+host) under LOCATION_AND_DEMOGRAPHICS (subcategories 'general_loc'
or 'ai_context_aware'). These aren't false positives to discard - they are
genuine navigation-context data, just filed under the wrong top-level
category. NAVIGATION_HISTORY already has an equivalent recognized
subcategory for this exact kind of signal ('referrer_data', matching
referrer/came_from/origin_url-style fields), so these are redistributed
there instead of being removed, and tagged '_relocated_from' for an
explicit audit trail.

Third issue (found while investigating why AT_0077's LOCATION_AND_DEMOGRAPHICS
count barely moved after the first cleanup pass): a single IndexedDB source
file can legitimately contain real country names/codes that are nevertheless
not disclosed data about the persona at all - e.g.
https_de.mydirtyhobby.com's cached country-picker dropdown (label="Ireland",
value="ie", label="Luxemburg", value="lu", ... for every country in the
world), duplicated across 81 different cached records for a total of
7,000+ items for that one country alone. The regex is "correct" here (these
really are country names), but a single real address never has more than a
handful of location fields - a record contributing 15+ 'general_loc' matches
at once is structurally a reference list/dropdown dump, not a disclosed
location. This only applies to IndexedDB (the only storage type whose items
carry a 'field_path' identifying which flattened record they came from);
cookies/localStorage/sessionStorage have no equivalent record grouping.
Smaller-scale instances of the same pattern exist in IT_0573, PL_0742 and
IE_0504 too, so this isn't an Austria-only fix.

Two incompatible item schemas exist across storage types, and this script
has to handle both: cookies and IndexedDB items carry 'name' /
'matched_subcategory' / 'match_type'; localStorage and sessionStorage items
(both the regex and the AI writer) instead carry 'key' /
'_matched_subcategory' and never record a match_type at all. For the
latter, match_type can't disambiguate "matched on the key" from "matched
on the value", so every rule (name-based and value-based) is applied to
every item regardless - safe, since each rule stands on its own evidence
independent of which axis originally triggered the match.

Each rule below is narrow and independently verified against the real data
(see conversation/manual audit) rather than a general fuzzy heuristic, to
keep false removals near zero - e.g. the OAuth rule only matches the
literal "state=" query-string idiom, not a generic '"state":"..."' JSON
key, because the latter also legitimately carries real region codes (e.g.
a GDPR consent-detection blob with {"state":"HDF"}, a genuine French
region code) that must NOT be removed. A handful of harder cases (a
coincidental dictionary-word hit buried in an opaque analytics/tracking
ID with no surrounding structure) are deliberately left alone rather than
risk over-removal; see the project's established "favor precision" norm
for the other correction passes in this folder.

Dry-run by default; nothing is written without --apply. Removed items are
relocated (not deleted) to a mirrored path under
data_false_positives_countries/, exactly like clean_pii.py's existing
false-positive handling, so the decision is auditable later.

Usage:
    python3 scripts_countries/clean_location_demographics_false_positives.py [--users A,B] [--apply]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from categorize_cookies import try_decode_value

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from countries_config import add_users_arg, resolve_users, AUTH_STATUSES

US_STATE_NAMES = {
    'alabama', 'alaska', 'arizona', 'arkansas', 'california', 'colorado', 'connecticut', 'delaware',
    'florida', 'georgia', 'hawaii', 'idaho', 'illinois', 'indiana', 'iowa', 'kansas', 'kentucky',
    'louisiana', 'maine', 'maryland', 'massachusetts', 'michigan', 'minnesota', 'mississippi',
    'missouri', 'montana', 'nebraska', 'nevada', 'new hampshire', 'new jersey', 'new mexico',
    'new york', 'north carolina', 'north dakota', 'ohio', 'oklahoma', 'oregon', 'pennsylvania',
    'rhode island', 'south carolina', 'south dakota', 'tennessee', 'texas', 'utah', 'vermont',
    'virginia', 'washington', 'west virginia', 'wisconsin', 'wyoming', 'district of columbia',
    'al', 'ak', 'az', 'ar', 'ca', 'co', 'ct', 'de', 'fl', 'ga', 'hi', 'id', 'il', 'in', 'ia', 'ks',
    'ky', 'la', 'me', 'md', 'ma', 'mi', 'mn', 'ms', 'mo', 'mt', 'ne', 'nv', 'nh', 'nj', 'nm', 'ny',
    'nc', 'nd', 'oh', 'ok', 'or', 'pa', 'ri', 'sc', 'sd', 'tn', 'tx', 'ut', 'vt', 'va', 'wa', 'wv',
    'wi', 'wy', 'dc',
}

STATE_COMPOUND_RE = re.compile(r'(^state$|[._-]state$)', re.IGNORECASE)
CLOUD_REGION_RE = re.compile(r'^[a-z]{2,3}-[a-z]+-\d+$', re.IGNORECASE)
OAUTH_STATE_PARAM_RE = re.compile(r'(?:^|[?&])state=', re.IGNORECASE)
ID_PREFIX_RE = re.compile(r'^(city|region|state|country|province|county|town)-[0-9a-f-]{8,}$', re.IGNORECASE)
BARE_KEYWORD_VALUES = {
    'country', 'region', 'state', 'province', 'county', 'city', 'town', 'village', 'municipality',
    'postal_code', 'zip', 'zip_code', 'postcode', 'timezone', 'time_zone', 'locale', 'continent', 'district',
}
MIME_ZIP_RE = re.compile(r'^data:application/zip', re.IGNORECASE)
JSON_STATE_EMPTY_RE = re.compile(r'"state"\s*:\s*(null|true|false|-?\d+(\.\d+)?|""|\'\')', re.IGNORECASE)
ORIGIN_URL_RE = re.compile(r'^https?://', re.IGNORECASE)
RECORD_INDEX_RE = re.compile(r'^\[(\d+)\]')
BULK_REFERENCE_LIST_THRESHOLD = 15


def item_key_name(item):
    """'name' for cookies/IndexedDB items, 'key' for localStorage/sessionStorage items."""
    return item.get('name') if 'name' in item else item.get('key')


def item_subcategory(item):
    """'matched_subcategory' for cookies/IndexedDB, '_matched_subcategory' for storage items."""
    return item.get('matched_subcategory', item.get('_matched_subcategory'))


def classify(item):
    """Returns a false-positive reason string, or None if the item should be kept."""
    name_l = (item_key_name(item) or '').strip().lower()
    value = item.get('value')
    value_s = str(value) if value is not None else ''
    # match_type is only ever present for cookies/IndexedDB items. When absent
    # (localStorage/sessionStorage), apply both rule families unconditionally.
    match_type = item.get('match_type')
    has_match_type = 'match_type' in item

    if (not has_match_type or match_type == 'name') and STATE_COMPOUND_RE.search(name_l):
        if value_s.strip().lower() not in US_STATE_NAMES:
            return 'state_name_collision'

    if (not has_match_type or match_type == 'name') and name_l == 'region' and CLOUD_REGION_RE.match(value_s.strip()):
        return 'cloud_region_code'

    if not has_match_type or match_type == 'value':
        variants = try_decode_value(value_s) if value_s else [value_s]
        for v in variants:
            vs = str(v)
            if MIME_ZIP_RE.match(vs.strip()):
                return 'mime_zip_collision'
            if OAUTH_STATE_PARAM_RE.search(vs):
                return 'oauth_state_param'
            if ID_PREFIX_RE.match(vs.strip()):
                return 'id_prefix_tag'
            if vs.strip().lower() in BARE_KEYWORD_VALUES:
                return 'bare_keyword_label'
            if JSON_STATE_EMPTY_RE.search(vs):
                return 'json_state_empty_value'

    return None


def is_origin_url_misfile(item):
    """True if this item is a bare 'origin'/'key'=origin field holding a site
    URL - navigation context, not location data - regardless of whatever
    subcategory it currently carries."""
    name_l = (item_key_name(item) or '').strip().lower()
    value_s = str(item.get('value')) if item.get('value') is not None else ''
    return name_l == 'origin' and bool(ORIGIN_URL_RE.match(value_s.strip()))


def relocate_to_navigation_history(item):
    """Returns a copy of item re-tagged as NAVIGATION_HISTORY.referrer_data,
    with an explicit audit trail of where it came from."""
    new_item = dict(item)
    old_subcat = item_subcategory(item)
    if 'matched_subcategory' in new_item:
        new_item['_relocated_from'] = f'LOCATION_AND_DEMOGRAPHICS.{old_subcat}'
        new_item['matched_subcategory'] = 'referrer_data'
        if 'match_type' in new_item:
            new_item['match_type'] = 'location_fp_redistribution'
    else:
        new_item['_relocated_from'] = f'LOCATION_AND_DEMOGRAPHICS.{old_subcat}'
        new_item['_matched_subcategory'] = 'referrer_data'
    return new_item


def find_bulk_reference_list_items(items):
    """
    Groups general_loc items by (source_file, record index) using
    'field_path' (IndexedDB only - cookies/localStorage/sessionStorage items
    have no field_path and are never grouped by this rule). Returns the set
    of id()s of items belonging to a group of size >= threshold, i.e. a
    cached reference list/dropdown dump rather than a disclosed location.
    """
    groups = defaultdict(list)
    for item in items:
        if item_subcategory(item) != 'general_loc' or 'field_path' not in item:
            continue
        m = RECORD_INDEX_RE.match(item.get('field_path') or '')
        if not m:
            continue
        key = (item.get('source_file'), int(m.group(1)))
        groups[key].append(item)

    flagged = set()
    for key, group in groups.items():
        if len(group) >= BULK_REFERENCE_LIST_THRESHOLD:
            flagged.update(id(it) for it in group)
    return flagged


def find_location_files(base_path: Path, users):
    users_filter = set(users) if users else None
    for auth in AUTH_STATUSES:
        auth_dir = base_path / auth
        if not auth_dir.exists():
            continue
        for user_dir in sorted(auth_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            if users_filter is not None and user_dir.name not in users_filter:
                continue
            yield from user_dir.glob('PARTIAL/**/LOCATION_AND_DEMOGRAPHICS.json')


def main(users=None, apply=False):
    users = users or resolve_users(None)
    base_path = Path(__file__).resolve().parent.parent / 'data' / 'user_countries'
    fp_root = Path(__file__).resolve().parent.parent / 'data_false_positives_countries'

    print(f"Mode: {'APPLY' if apply else 'DRY-RUN'} | users: {users}\n")

    total_reasons = Counter()
    total_items = 0
    total_removed = 0
    total_redistributed = 0
    samples = defaultdict(list)
    redistributed_samples = []

    for file_path in find_location_files(base_path, users):
        try:
            items = json.load(open(file_path, 'r', encoding='utf-8'))
        except Exception as e:
            print(f"  Warning: could not read {file_path}: {e}")
            continue

        bulk_ids = find_bulk_reference_list_items(items)

        keep, removed, redistributed = [], [], []
        for item in items:
            total_items += 1
            if id(item) in bulk_ids:
                removed.append(('bulk_reference_list', item))
                continue
            if is_origin_url_misfile(item):
                redistributed.append(item)
                continue
            if item_subcategory(item) != 'general_loc':
                keep.append(item)
                continue
            reason = classify(item)
            if reason:
                removed.append((reason, item))
            else:
                keep.append(item)

        if not removed and not redistributed:
            continue

        rel = file_path.relative_to(base_path)
        print(f"{rel}: {len(items)} -> {len(keep)} "
              f"(removed {len(removed)}, redistributed {len(redistributed)})")
        for reason, item in removed:
            total_reasons[reason] += 1
            total_removed += 1
            if len(samples[reason]) < 3:
                samples[reason].append((item_key_name(item), str(item.get('value'))[:60]))
        for item in redistributed:
            total_redistributed += 1
            if len(redistributed_samples) < 3:
                redistributed_samples.append((item_key_name(item), str(item.get('value'))[:60]))

        if apply:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(keep, f, indent=2, ensure_ascii=False)

            if removed:
                fp_items = [dict(item, _fp_reason=reason) for reason, item in removed]
                fp_path = fp_root / rel
                fp_path.parent.mkdir(parents=True, exist_ok=True)
                existing = []
                if fp_path.exists():
                    try:
                        existing = json.load(open(fp_path, 'r', encoding='utf-8'))
                    except Exception:
                        existing = []
                with open(fp_path, 'w', encoding='utf-8') as f:
                    json.dump(existing + fp_items, f, indent=2, ensure_ascii=False)

            if redistributed:
                nav_items = [relocate_to_navigation_history(item) for item in redistributed]
                nav_path = file_path.parent / 'NAVIGATION_HISTORY.json'
                existing = []
                if nav_path.exists():
                    try:
                        existing = json.load(open(nav_path, 'r', encoding='utf-8'))
                    except Exception:
                        existing = []
                with open(nav_path, 'w', encoding='utf-8') as f:
                    json.dump(existing + nav_items, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Total LOCATION_AND_DEMOGRAPHICS items scanned: {total_items:,}")
    print(f"Total removed as false positives: {total_removed:,}")
    for reason, count in total_reasons.most_common():
        print(f"  {reason}: {count:,}")
        for name, value in samples[reason]:
            print(f"      name={name!r}  value={value!r}")
    print(f"\nTotal redistributed to NAVIGATION_HISTORY.referrer_data: {total_redistributed:,}")
    for name, value in redistributed_samples:
        print(f"    name={name!r}  value={value!r}")
    if not apply:
        print("\nDry-run only. Re-run with --apply to write changes.")
        print(f"(false positives would be relocated to {fp_root}, mirroring clean_pii.py's convention;")
        print(" 'origin' URL items would be moved into NAVIGATION_HISTORY.json in the same directory)")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    parser.add_argument('--apply', action='store_true', help='Write the cleaned files (default: dry-run preview only)')
    args = parser.parse_args()
    main(users=resolve_users(args.users), apply=args.apply)
