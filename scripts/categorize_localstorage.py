#!/usr/bin/env python3
"""
localStorage / sessionStorage categorization script.
"""

import json
import re
import sys
import os
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple
import math

# Import regex and existing modules
sys.path.insert(0, str(Path(__file__).parent))
from regex import TRACKING_PATTERNS_COMPLETE
from overlap_detection import collect_all_pii_matches
from categorize_cookies import (
    get_patterns_for_user,
    USER_ID_TO_INDEX,
    PII_PATTERN_FAMILIES,
    PII_PRIORITY_ORDER,
    is_valid_ip,
    is_valid_jwt,
    is_valid_uuid,
    is_valid_location_value,
    is_valid_gender,
    try_decode_value
)


def shannon_entropy(s: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not s: return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())



def deduplicate_pii_matches_storage(matches_list):
    """
    Deduplicates PII matches by family.
    """
    if not matches_list: return []
    
    subcat_to_family = {}
    for family, subcats in PII_PATTERN_FAMILIES.items():
        for subcat in subcats:
            subcat_to_family[subcat] = family
    
    family_matches = {}
    standalone_matches = []
    
    for match in matches_list:
        cat, subcat = match
        if subcat in subcat_to_family:
            family = subcat_to_family[subcat]
            if family not in family_matches: family_matches[family] = []
            family_matches[family].append(match)
        else:
            standalone_matches.append(match)
    
    deduplicated = []
    for family, matches_in_family in family_matches.items():
        priority = PII_PRIORITY_ORDER.get(family, [])
        def match_priority(m):
            try: return priority.index(m[1])
            except ValueError: return 999
        
        matches_in_family.sort(key=match_priority)
        deduplicated.append(matches_in_family[0])
    
    deduplicated.extend(standalone_matches)
    return deduplicated


def categorize_storage_item(item, patterns):
    """
    Hybrid Strategy for Storage.
    """
    main_key = item.get('key', '')
    value_raw = str(item.get('value', ''))

    # 1. Identity Extraction (Main key + Internal JSON keys)
    internal_keys = []
    vals_to_check = try_decode_value(value_raw)
    
    for val in vals_to_check:
        try:
            parsed = json.loads(val)
            def walk(obj, path=''):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        internal_keys.append(k)
                        walk(v, k)
                elif isinstance(obj, list):
                    for v in obj: walk(v)
            walk(parsed)
            break 
        except: continue

    all_identity_elements = [main_key] + internal_keys
    pii_keys_matches = set() # Set to avoid technical repetitions (e.g., 20x 'phone')

    # --- STEP 1: DIRECT_PII_KEYS (Intention) ---
    if 'DIRECT_PII_KEYS' in patterns:
        for subcat, pattern in patterns['DIRECT_PII_KEYS'].items():
            for identity in all_identity_elements:
                if re.search(pattern, str(identity), re.IGNORECASE):
                    pii_keys_matches.add(('DIRECT_PII_KEYS', subcat))
                    break # Stop at first match for this subcategory

    # --- STEP 2: PRIORITY AND COLLECTION OF ALL CATEGORIES ---
    priority_order = ['DIRECT_PII', 'SUSPICIOUS_VALUES', 'SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS', 'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES', 'CONSENT_AND_PRIVACY']
    for cat in patterns.keys():
        if cat not in priority_order and cat != 'DIRECT_PII_KEYS':
            priority_order.append(cat)

    pii_matches = set() 
    all_category_matches = []  # Collect ALL categories that match

    for category in priority_order:
        if category not in patterns: continue
        
        for subcat, pattern in patterns[category].items():
            
            # A. IDENTITY Test (Key-Only for tracking)
            for identity in all_identity_elements:
                if re.search(pattern, str(identity), re.IGNORECASE):
                    # Validation for location categories
                    if category in ['SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS']:
                        if not is_valid_location_value(subcat, value_raw):
                            continue
                    
                    if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
                        if shannon_entropy(value_raw) < 3.0: continue
                    
                    if category in ['DIRECT_PII', 'SUSPICIOUS_VALUES']:
                        pii_matches.add((category, subcat))
                        break # Match found, move to next pattern
                    else:
                        # For other categories, add to the list of all matches
                        all_category_matches.append((category, subcat))
                        break  # Move to the next pattern

            # B. CONTENT Test (Value-Only for DIRECT_PII)
            if category == 'DIRECT_PII':
                all_pii_found = collect_all_pii_matches(patterns[category], value_raw)
                for sub_m, text_m, start_m, end_m in all_pii_found:
                    # IP Filter
                    if sub_m == "ip_address" and not is_valid_ip(text_m): 
                        continue
                    # Email/Name overlap filter
                    if sub_m in ['first_name', 'last_name', 'full_name'] and "@" in value_raw:
                        if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', value_raw): 
                            continue
                    # Gender Filter (false positives in long texts)
                    if sub_m == "gender" and not is_valid_gender(text_m, value_raw):
                        continue
                    
                    pii_matches.add((category, sub_m))
                continue
            
            # C. CONTENT Test (Value-Only for SUSPICIOUS_VALUES)
            if category == 'SUSPICIOUS_VALUES':
                all_suspicious_found = collect_all_pii_matches(patterns[category], value_raw)
                for sub_m, text_m, start_m, end_m in all_suspicious_found:
                    # Validation pour ip_address
                    if sub_m == "ip_address":
                        if not is_valid_ip(text_m): continue
                    
                    # Validation pour jwt_token
                    if sub_m == "jwt_token":
                        if not is_valid_jwt(text_m): continue
                    
                    # Validation pour uuid_format
                    if sub_m == "uuid_format":
                        if not is_valid_uuid(text_m): continue
                    
                    pii_matches.add((category, sub_m))
                continue 
            
            # D. CONTENT Test (Value-Only for SENSITIVE_LOCATION_PII and LOCATION_AND_DEMOGRAPHICS)
            if category in ['SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS']:
                # Also search in values for these categories
                if re.search(pattern, value_raw, re.IGNORECASE):
                    if is_valid_location_value(subcat, value_raw):
                        all_category_matches.append((category, subcat))

    # End of loop: combine all matches
    final_matches = []
    
    # Add deduplicated PII
    if pii_matches:
        final_pii = deduplicate_pii_matches_storage(list(pii_matches))
        final_matches.extend(final_pii)
    
    # Add other categories (deduplicate to avoid duplicates)
    seen_categories = set()
    for cat, subcat in all_category_matches:
        if cat not in seen_categories:
            final_matches.append((cat, subcat))
            seen_categories.add(cat)
    
    if final_matches:
        return {'primary_matches': final_matches, 'pii_keys_matches': list(pii_keys_matches)}

    return {'primary_matches': None, 'pii_keys_matches': list(pii_keys_matches)}


def process_storage_file(input_file: Path, output_dir: Path, patterns: Dict):
    if not input_file.exists(): return

    print(f"  Processing {input_file.name}...")
    with open(input_file, 'r', encoding='utf-8') as f:
        items = json.load(f)

    categorized_data = {cat: [] for cat in list(patterns.keys()) if cat != 'DIRECT_PII_KEYS'}
    categorized_data['UNCATEGORIZED'] = []
    categorized_data['DIRECT_PII_KEYS'] = []
    
    for item in items:
        result = categorize_storage_item(item, patterns)
        primary_matches = result.get('primary_matches')
        pii_keys_matches = result.get('pii_keys_matches', [])
        
        # 1. Primary Category Processing
        if primary_matches:
            # An item can have multiple PII (e.g., Name + IP), but only one other category
            for cat, sub in primary_matches:
                item_out = item.copy()
                item_out.update({'_primary_category': cat, '_matched_subcategory': sub, '_source_file': input_file.name})
                categorized_data[cat].append(item_out)
        else:
            item_out = item.copy()
            item_out.update({'_primary_category': 'UNCATEGORIZED', '_matched_subcategory': 'none', '_source_file': input_file.name})
            # --- PREPARATION FOR LLM ---
            # Reuse try_decode_value (imported from cookies)
            decoded_list = try_decode_value(str(item.get('value', '')))
            # Look for a decoded value different from original
            extra_info = [v for v in decoded_list if v != str(item.get('value'))]
            if extra_info:
                item_out['try_decoded_value'] = extra_info[0]
            categorized_data['UNCATEGORIZED'].append(item_out)
        
        # 2. Intentions Processing (KEYS)
        for cat, sub in pii_keys_matches:
            item_key_out = item.copy()
            item_key_out.update({'_primary_category': cat, '_matched_subcategory': sub, '_source_file': input_file.name})
            categorized_data['DIRECT_PII_KEYS'].append(item_key_out)

    # Saving
    output_dir.mkdir(parents=True, exist_ok=True)
    for category, rows in categorized_data.items():
        if rows:
            with open(output_dir / f"{category}.json", 'w', encoding='utf-8') as f:
                json.dump(rows, f, indent=2, ensure_ascii=False)

def main():
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    users = ('FR_0417', 'FR_0446', 'FR_0458')
    auth_statuses = ('Auth', 'UnAuth')
    policies = ('ALL', 'PARTIAL', 'NONE')
    storage_types = ('localstorage', 'sessionstorage')

    for user in users:
        user_patterns = get_patterns_for_user(user)
        for auth in auth_statuses:
            for pol in policies:
                for s_type in storage_types:
                    input_path = base_dir / 'preprocessing' / auth / user / pol / s_type
                    output_base = base_dir / 'user' / auth / user / pol / s_type
                    if input_path.exists():
                        for lifecycle in ['added', 'modified', 'removed']:
                            process_storage_file(input_path / f"{lifecycle}_{s_type}.json", output_base / lifecycle, user_patterns)

if __name__ == '__main__':
    main()