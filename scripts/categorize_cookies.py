#!/usr/bin/env python3
"""
 Cookie Categorization Script.

- DIRECT_PII_KEYS detected independently (based on names and keys)
- Strict hierarchy for primary category
- PII deduplication by family
- Consistent output format for all categories
"""

import re
import os
import sys
import base64
import json
import urllib.parse
from pathlib import Path
import math
from collections import Counter

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from regex import TRACKING_PATTERNS_COMPLETE
from overlap_detection import collect_all_pii_matches

USER_ID_TO_INDEX = {'FR_0417': 0, 'FR_0446': 1, 'FR_0458': 2}

# PII PATTERN FAMILIES 

PII_PATTERN_FAMILIES = {
    'email': ['email_exact', 'email_encoded', 'email_username', 'email_pattern'],
    'phone': ['phone_full', 'phone_national', 'phone_short', 'phone_encoded', 'phone_partial', 'phone_spaced'],
    'birth_date': ['birth_date_slash', 'birth_date_iso', 'birth_date_dot', 'birth_date_full'],
    'user_id': ['user_id', 'user_id_partial'],
    'address': ['address_full', 'address_street', 'address_encoded'],
    #  'name': ['full_name', 'first_name', 'last_name', 'name_encoded'],
    'city': ['city', 'city_encoded', 'arrondissement'],
    'password': ['password', 'password_encoded'],
    'ip_address': ['ip_address']
}

# Priority order within each family (more specific patterns are prioritized)
PII_PRIORITY_ORDER = {
    'email': ['email_exact', 'email_encoded', 'email_username', 'email_pattern'],
    'phone': ['phone_full', 'phone_national', 'phone_short', 'phone_encoded', 'phone_partial', 'phone_spaced'],
    'birth_date': ['birth_date_slash', 'birth_date_iso', 'birth_date_full', 'birth_date_dot'],
    'user_id': ['user_id', 'user_id_partial'],
    'address': ['address_full', 'address_encoded', 'address_street'],
    # 'name': ['full_name', 'name_encoded', 'first_name', 'last_name'],
    'city': ['city', 'arrondissement', 'city_encoded'],
    'password': ['password', 'password_encoded'],
    'ip_address': ['ip_address']
}

# UTILITY FUNCTIONS

def shannon_entropy(s: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())


def try_decode_value(value):
    """Attempts to decode a value (URL, Base64, JSON)."""
    if not value or not isinstance(value, str):
        return [value]
    
    decoded_values = [value]
    
    # URL Decoding
    try:
        u = urllib.parse.unquote(value)
        if u != value:
            decoded_values.append(u)
    except:
        pass
    
    # Base64
    try:
        if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) % 4 == 0:
            b = base64.b64decode(value).decode('utf-8', errors='ignore')
            if b and b.isprintable():
                decoded_values.append(b)
    except:
        pass
    
    # JSON
    try:
        j = json.loads(value)
        if isinstance(j, dict):
            decoded_values.append(json.dumps(j, ensure_ascii=False))
    except:
        pass
    
    return list(set(decoded_values))


def get_patterns_for_user(user_id):
    """Returns patterns with the correct DIRECT_PII for the specific user."""
    patterns = dict(TRACKING_PATTERNS_COMPLETE)
    user_index = USER_ID_TO_INDEX.get(user_id, 0)
    if isinstance(TRACKING_PATTERNS_COMPLETE['DIRECT_PII'], list):
        patterns['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII'][user_index]
    return patterns


def calculate_modified_metrics(cookie):
    """Calculates changes for modified cookies."""
    fields = ['value', 'expires', 'httpOnly', 'secure', 'sameSite']
    changed = [f for f in fields if cookie.get(f'{f}_from') != cookie.get(f'{f}_to')]
    return {
        'changed_fields': ','.join(changed) if changed else 'none',
        'num_changes': len(changed)
    }


import ipaddress
import uuid

# Optional JWT validation
try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

def is_valid_ip(value: str) -> bool:
    """
    Validates if a value is a real IP address and not just a version number.
    
    IMPORTANT: Private IPs (192.168.x.x, 10.x.x.x, etc.) are considered PII as they
    reveal the user's network environment. These are KEPT.
    
    Filters out:
    - Invalid addresses (0.0.0.0, 127.0.0.1 loopback)
    - Obvious version numbers (e.g., 1.2.1.1, 2.0.0.1)
    """
    try:
        ip = ipaddress.ip_address(value)
        
        # Filtrer uniquement les adresses non-utilisables
        if ip.is_unspecified or ip.is_loopback:
            return False
        
        # Filtrer les patterns de version courants
        # Pattern 1: Tous les octets < 10 (ex: 1.2.1.1, 2.3.4.5)
        # Pattern 2: x.0.y.z où x < 10 (ex: 1.0.1.1, 2.0.0.1)
        # Pattern 3: x.y.0.0 (ex: 140.0.0.0, 537.36.0.0 - versions logicielles)
        parts = value.split('.')
        if len(parts) == 4:
            try:
                nums = [int(p) for p in parts]
                
                # If all octets are < 10, it's likely a version number
                if all(n < 10 for n in nums):
                    return False
                
                # Specific pattern: x.0.y.z where x < 10
                if nums[0] < 10 and nums[1] == 0:
                    return False
                
                # Software version pattern: x.y.0.0
                # Real IPs ending in .0.0 are extremely rare.
                # Examples: Chrome/140.0.0.0, Safari/537.36.0.0
                if nums[2] == 0 and nums[3] == 0:
                    return False
                    
            except ValueError:
                pass
        
        # All other IPs are valid (including private, multicast, etc.)
        return True
    except ValueError:
        return False

def is_valid_jwt(token):
    """Validates that a JWT token has a valid structure."""
    if not HAS_JWT: 
        return str(token).count('.') == 2
    try:
        jwt.decode(str(token), options={"verify_signature": False})
        return True
    except: 
        return False

def is_valid_uuid(val):
    """Validates that a value is a valid UUID."""
    try:
        uuid.UUID(str(val))
        return True
    except: 
        return False

def is_valid_location_value(subcat, value):
    """Filters out technical false positives for location data."""
    val = str(value).lower().strip().strip('"')
    noise = {'null', 'undefined', 'none', 'true', 'false', '', 'unknown', 'auto', 
             'default', 'n/a', 'nan', 'object', 'object object', 'undefined_undefined'}
    if val in noise: return False

    # Specific validation for Latitude/Longitude/Coords (MUST be numeric)
    if any(k in subcat.lower() for k in ['latitude', 'longitude', 'coords', 'precise_coords', 'gps', 'geo_position', 'altitude', 'elevation']):
        try:
            num_val = float(val.replace(',', '.'))
            # Validation of reasonable ranges for lat/lon
            if 'latitude' in subcat.lower() or 'lat' in subcat.lower():
                return -90 <= num_val <= 90
            if 'longitude' in subcat.lower() or 'lon' in subcat.lower() or 'lng' in subcat.lower():
                return -180 <= num_val <= 180
            # For other coords (altitude, etc.), accept any valid number
            return True
        except ValueError: 
            return False
  
    if len(val) < 2: return False
    if val.isdigit(): return False  
    return True

def is_valid_gender(match_text, full_value):
    """
    Validates if a gender detection (male/female) is a true PII and not a false positive.
    
    Filters cases where male/female appear in:
    - Long descriptive texts (privacy policies, etc.)
    - URLs or paths
    - Technical JSON keys
    
    Args:
        match_text: The matched text (e.g., "male", "female")
        full_value: The full value where the match was found
    
    Returns:
        True if it's likely a true PII, False if it's a false positive
    """
    match_lower = match_text.lower()
    value_str = str(full_value)
    
    # If the value is very long (>500 characters), it's likely descriptive text
    if len(value_str) > 500:
        return False
    
    # If the value contains many words (>50), it's likely text
    word_count = len(value_str.split())
    if word_count > 50:
        return False
    
    # If the match appears in a URL or path context
    if any(pattern in value_str.lower() for pattern in ['http://', 'https://', 'www.', '.com', '.fr', '.net', 'privacy', 'policy', 'legal']):
        return False
    
    # If the match appears in a JSON context with many keys
    if value_str.count('{') > 5 or value_str.count('[') > 5:
        return False
    
    # If the match is part of a longer word (e.g., "female" in "femaleness")
    # Check the context around the match
    match_index = value_str.lower().find(match_lower)
    if match_index != -1:
        # Check characters before and after
        before_char = value_str[match_index - 1] if match_index > 0 else ' '
        after_char = value_str[match_index + len(match_lower)] if match_index + len(match_lower) < len(value_str) else ' '
        
        # If surrounded by alphanumeric characters, it's likely part of a longer word
        if before_char.isalnum() or after_char.isalnum():
            return False
    
    # If we get here, it's likely a true PII
    return True


def extract_json_keys_recursive(obj, parent_key=''):
    """
    Recursively extracts all keys from a JSON object.
    """
    keys = []
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            keys.append(full_key)
            if isinstance(value, (dict, list)):
                keys.extend(extract_json_keys_recursive(value, full_key))
    
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                keys.extend(extract_json_keys_recursive(item, f"{parent_key}[{idx}]"))
    
    return keys



def deduplicate_pii_matches(matches):
    """
    Deduplicates PII matches by family.
    
    Rules:
    - Only 1 match per family (email, phone, birth_date, etc.)
    - Priority given to the most specific pattern (email_exact > email_pattern)
    - Ignore name patterns if found within an email
    """
    
    # Reverse mapping: subcategory -> family
    subcat_to_family = {}
    for family, subcats in PII_PATTERN_FAMILIES.items():
        for subcat in subcats:
            subcat_to_family[subcat] = family
    
    # Group matches by family
    family_matches = {}
    standalone_matches = []
    
    for match in matches:
        subcat = match['subcategory']
        
        if subcat in subcat_to_family:
            family = subcat_to_family[subcat]
            if family not in family_matches:
                family_matches[family] = []
            family_matches[family].append(match)
        else:
            # Patterns without a family (gender, religion, etc.)
            standalone_matches.append(match)
    
    # Select the best match per family
    deduplicated = []
    
    for family, matches_in_family in family_matches.items():
        
        # SPECIAL RULE: Ignore name patterns if an email was detected
        # if family == 'name':
        #     has_email = 'email' in family_matches
        #     if has_email:
        #         # Do not count names (they are part of the email)
        #         continue
        
        # Sort by priority
        priority = PII_PRIORITY_ORDER.get(family, [])
        
        def match_priority(m):
            subcat = m['subcategory']
            try:
                return priority.index(subcat)
            except ValueError:
                return 999  # Not found = low priority
        
        matches_in_family.sort(key=match_priority)
        
        # Take the best one (index 0)
        best_match = matches_in_family[0]
        deduplicated.append(best_match)
    
    # Add standalone matches
    deduplicated.extend(standalone_matches)
    
    return deduplicated



def categorize_cookie(cookie, patterns):
    """
    Categorizes a cookie according to defined patterns.
    
    LOGIC OPTION 2:
    1. Independent DIRECT_PII_KEYS detection (name + key)
    2. Strict hierarchy for primary category
    3. Deduplication for DIRECT_PII

    """
    name = cookie.get('name', '')
    value = str(cookie.get('value', ''))


    pii_keys_matches = []
    
    if 'DIRECT_PII_KEYS' in patterns:
        for subcat, pattern in patterns['DIRECT_PII_KEYS'].items():
            try:
                # Test on the cookie NAME
                if re.search(pattern, name, re.IGNORECASE):
                    pii_keys_matches.append({
                        'category': 'DIRECT_PII_KEYS',
                        'subcategory': subcat,
                        'match_type': 'name',
                        'was_decoded': False,
                        'pattern': pattern,
                        'decoded_value': None
                    })
                    continue  # Move to next pattern
                
                # Test on JSON KEYS only (not values)
                vals_to_check = try_decode_value(value)
                for val in vals_to_check:
                    try:
                        parsed_json = json.loads(val)
                        if isinstance(parsed_json, dict):
                            # Extract all keys from JSON (recursive)
                            json_keys = extract_json_keys_recursive(parsed_json)
                            for key in json_keys:
                                if re.search(pattern, key, re.IGNORECASE):
                                    pii_keys_matches.append({
                                        'category': 'DIRECT_PII_KEYS',
                                        'subcategory': subcat,
                                        'match_type': 'json_key',
                                        'matched_key_name': key,
                                        'was_decoded': val != value,
                                        'pattern': pattern,
                                        'decoded_value': val if val != value else None
                                    })
                                    break  # Only one match per pattern
                            if pii_keys_matches and pii_keys_matches[-1]['subcategory'] == subcat:
                                break  # Already found for this pattern, move to next
                    except (json.JSONDecodeError, TypeError):
                        # Not a valid JSON, continue with next value
                        continue
                        
            except re.error:
                pass

    
    # Priority order
    priority_order = [
        'DIRECT_PII',
        'SUSPICIOUS_VALUES',
        'SENSITIVE_LOCATION_PII',
        'LOCATION_AND_DEMOGRAPHICS',
        'IDENTITY_TRACKING',
        'ID_SOLUTIONS_AND_EXCHANGES',
        'CONSENT_AND_PRIVACY'
    ]
    
  
    for cat in patterns.keys():
        if cat not in priority_order and cat != 'DIRECT_PII_KEYS':
            priority_order.append(cat)

    vals_to_check = try_decode_value(value)

    # Collector for DIRECT_PII and SUSPICIOUS_VALUES
    pii_matches = []
    all_category_matches = []  # Collect ALL categories that match

    for category in priority_order:
        if category not in patterns:
            continue

        for subcat, pattern in patterns[category].items():

            try:
                # --- A. MATCH ON NAME (key) ---
                if re.search(pattern, name, re.IGNORECASE):

                    # Validation for location categories
                    if category in ['SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS']:
                        if not is_valid_location_value(subcat, value):
                            continue

                    # Special case: IDENTITY_TRACKING::generic_ids
                    if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
                        entropy = shannon_entropy(value)
                        if entropy < 3.0:
                            continue  # Insufficient signal

                        return {
                            'primary_matches': [{
                                'category': category,
                                'subcategory': subcat,
                                'match_type': 'name',
                                'entropy': round(entropy, 2),
                                'confidence': 'medium',
                                'pattern': pattern,
                                'was_decoded': False,
                                'decoded_value': None
                            }],
                            'pii_keys_matches': pii_keys_matches
                        }

                    # IF DIRECT_PII or SUSPICIOUS_VALUES: store match but continue
                    if category in ['DIRECT_PII', 'SUSPICIOUS_VALUES']:
                        pii_matches.append({
                            'category': category,
                            'subcategory': subcat,
                            'match_type': 'name',
                            'was_decoded': False,
                            'pattern': pattern,
                            'decoded_value': None
                        })
                        continue  

                    # For other categories (location, tracking, etc.), add to list
                    all_category_matches.append({
                        'category': category,
                        'subcategory': subcat,
                        'match_type': 'name',
                        'was_decoded': False,
                        'pattern': pattern,
                        'decoded_value': None
                    })
                    continue  # Continue searching for PII in values

                # --- B. MATCH ON VALUE (PII ONLY) ---
                if category == 'DIRECT_PII':
                    # Collect all DIRECT_PII matches from all values with overlap detection
                    for val in vals_to_check:
                        if not val:
                            continue
                        
                        # Use collect_all_pii_matches to find all occurrences with overlap removal
                        all_pii_in_val = collect_all_pii_matches(patterns[category], str(val))
                        
                        for subcat, match_text, start_pos, end_pos in all_pii_in_val:
                            # SPECIAL RULE: Ignore name patterns if within an email
                            if subcat in ['first_name', 'last_name', 'full_name', 'name_encoded']:
                                # Check if value contains an email
                                if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', val):
                                    # Name found in an email -> do not count
                                    continue
                            
                            # Validation pour ip_address
                            if subcat == "ip_address":
                                if not is_valid_ip(match_text):
                                    continue
                            
                            # Validation for gender (filter false positives in long texts)
                            if subcat == "gender":
                                if not is_valid_gender(match_text, val):
                                    continue
                            
                            pii_matches.append({
                                'category': category,
                                'subcategory': subcat,
                                'match_type': 'value',
                                'was_decoded': val != value,
                                'decoded_value': val if val != value else None,
                                'pattern': patterns[category][subcat],
                                'match_text': match_text,
                                'start_pos': start_pos,
                                'end_pos': end_pos
                            })
                    
                    # After processing all values for DIRECT_PII, move to next category
                    continue
                
                # --- C. MATCH ON VALUE (SUSPICIOUS_VALUES) ---
                if category == 'SUSPICIOUS_VALUES':
                    # Collect all SUSPICIOUS_VALUES matches from all values with overlap detection
                    for val in vals_to_check:
                        if not val:
                            continue
                        
                        # Use collect_all_pii_matches to find all occurrences
                        all_suspicious_in_val = collect_all_pii_matches(patterns[category], str(val))
                        
                        for subcat, match_text, start_pos, end_pos in all_suspicious_in_val:
                            # Validation pour ip_address
                            if subcat == "ip_address":
                                if not is_valid_ip(match_text):
                                    continue
                            
                            # Validation pour jwt_token
                            if subcat == "jwt_token":
                                if not is_valid_jwt(match_text):
                                    continue
                            
                            # Validation pour uuid_format
                            if subcat == "uuid_format":
                                if not is_valid_uuid(match_text):
                                    continue
                            
                            pii_matches.append({
                                'category': category,
                                'subcategory': subcat,
                                'match_type': 'value',
                                'was_decoded': val != value,
                                'decoded_value': val if val != value else None,
                                'pattern': patterns[category][subcat],
                                'match_text': match_text,
                                'start_pos': start_pos,
                                'end_pos': end_pos
                            })
                    
                    continue
                
                # --- D. MATCH ON VALUE (LOCATION categories) ---
                if category in ['SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS']:
                    for val in vals_to_check:
                        if not val:
                            continue
                        if re.search(pattern, str(val), re.IGNORECASE):
                            if is_valid_location_value(subcat, val):
                                all_category_matches.append({
                                    'category': category,
                                    'subcategory': subcat,
                                    'match_type': 'value',
                                    'was_decoded': val != value,
                                    'pattern': pattern,
                                    'decoded_value': val if val != value else None
                                })
                                break
                    continue
                             
            except re.error:
                pass

    
    # Combine all matches
    final_matches = []
    
    # Add deduplicated PII
    if pii_matches:
        deduplicated_pii = deduplicate_pii_matches(pii_matches)
        final_matches.extend(deduplicated_pii)
    
    # Add other categories (deduplicate to avoid duplicates)
    seen_categories = set()
    for match in all_category_matches:
        cat = match['category']
        if cat not in seen_categories:
            final_matches.append(match)
            seen_categories.add(cat)
    
    if final_matches:
        return {
            'primary_matches': final_matches,
            'pii_keys_matches': pii_keys_matches
        }
    
    # Otherwise, no primary category
    return {
        'primary_matches': None,
        'pii_keys_matches': pii_keys_matches
    }


def main():
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    users = ('FR_0417', 'FR_0446', 'FR_0458')
    auth_statuses = ('Auth', 'UnAuth')
    policies = ('ALL', 'PARTIAL', 'NONE')

    for user in users:
        user_patterns = get_patterns_for_user(user)
        
        for auth in auth_statuses:
            for pol in policies:
                input_path = base_dir / 'preprocessing' / auth / user / pol / 'cookies'
                if not input_path.exists():
                    continue
                
                output_base = base_dir / 'user' / auth / user / pol / 'cookies'
                
                for lifecycle in ['added', 'modified', 'removed']:
                    f_name = f"{lifecycle}_cookies.json"
                    f_path = input_path / f_name
                    if not f_path.exists():
                        continue
                    
                    print(f"Analysis {user} | {auth} | {pol} | {lifecycle}")
                    
                    with open(f_path, 'r', encoding='utf-8') as f:
                        cookies = json.load(f)
                    
                    out_dir = output_base / lifecycle
                    out_dir.mkdir(parents=True, exist_ok=True)
                    
                    categorized = {cat: [] for cat in list(user_patterns.keys()) if cat != 'DIRECT_PII_KEYS'}
                    categorized['UNCATEGORIZED'] = []
                    categorized['DIRECT_PII_KEYS'] = []  # Added separately
                    
                    for cookie in cookies:
                        result = categorize_cookie(cookie, user_patterns)
                        
                        if lifecycle == 'modified':
                            cookie_metrics = calculate_modified_metrics(cookie)
                        
                        primary_matches = result.get('primary_matches')
                        pii_keys_matches = result.get('pii_keys_matches', [])
                        
                        if primary_matches:
                            # Primary category found
                            for match in primary_matches:
                                cookie_out = cookie.copy()
                                cookie_out['source_file'] = f_name
                                
                                if lifecycle == 'modified':
                                    cookie_out.update(cookie_metrics)
                                
                                cookie_out.update({
                                    'matched_subcategory': match['subcategory'],
                                    'match_type': match['match_type'],
                                    'was_decoded': match['was_decoded'],
                                    'matched_pattern': match['pattern'],
                                    'decoded_value': match.get('decoded_value')
                                })
                                
                                categorized[match['category']].append(cookie_out)
                        else:
                            # No primary category -> UNCATEGORIZED
                            cookie_out = cookie.copy()
                            cookie_out['source_file'] = f_name
                            
                            if lifecycle == 'modified':
                                cookie_out.update(cookie_metrics)
                            # --- PREPARATION FOR LLM ---
                            decoded_list = try_decode_value(cookie.get('value', ''))
                            # Search for a decoded value that is different from original
                            extra_info = [v for v in decoded_list if v != str(cookie.get('value'))]
                            if extra_info:
                                cookie_out['try_decoded_value'] = extra_info[0]
                            categorized['UNCATEGORIZED'].append(cookie_out)
                        
                        if pii_keys_matches:
                            for match in pii_keys_matches:
                                cookie_out_key = cookie.copy()
                                cookie_out_key['source_file'] = f_name
                                
                                if lifecycle == 'modified':
                                    cookie_out_key.update(cookie_metrics)
                                
                                cookie_out_key.update({
                                    'matched_subcategory': match['subcategory'],
                                    'match_type': match['match_type'],
                                    'was_decoded': match['was_decoded'],
                                    'matched_pattern': match['pattern'],
                                    'decoded_value': match.get('decoded_value')
                                })
                                
                                categorized['DIRECT_PII_KEYS'].append(cookie_out_key)
                    
                    for cat, rows in categorized.items():
                        if rows:
                            with open(out_dir / f"{cat}.json", 'w', encoding='utf-8') as f:
                                json.dump(rows, f, indent=2, ensure_ascii=False)
                    
                    # PII duplication stats
                    if categorized['DIRECT_PII']:
                        unique_cookies = len(set(c['name'] for c in categorized['DIRECT_PII']))
                        total_entries = len(categorized['DIRECT_PII'])
                        avg_pii = total_entries / unique_cookies if unique_cookies > 0 else 0
                        print(f"  → DIRECT_PII: {unique_cookies} unique cookies, {total_entries} entries (avg {avg_pii:.1f} PII/cookie)")
                    
                    # Stats for DIRECT_PII_KEYS
                    if categorized['DIRECT_PII_KEYS']:
                        unique_cookies_keys = len(set(c['name'] for c in categorized['DIRECT_PII_KEYS']))
                        total_entries_keys = len(categorized['DIRECT_PII_KEYS'])
                        avg_keys = total_entries_keys / unique_cookies_keys if unique_cookies_keys > 0 else 0
                        print(f"  → DIRECT_PII_KEYS: {unique_cookies_keys} unique cookies, {total_entries_keys} intentions (avg {avg_keys:.1f} PII keys/cookie)")

if __name__ == '__main__':
    main()