
"""
INDEXEDDB CATEGORIZATION PIPELINE 
Scientific method: Family Deduplication + Intention Audit + 3 Levels of Location 
+ Technical Validation + Structural Filtering (Anti-Explosion).
"""

import os
import json
import re
import sys
import uuid
import ipaddress
import math
from pathlib import Path
from collections import defaultdict, Counter

# Optional technical validation
try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

# Import constants and shared functions
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from regex import TRACKING_PATTERNS_COMPLETE
from overlap_detection import collect_all_pii_matches
from categorize_cookies import (
    try_decode_value, 
    get_patterns_for_user,
    PII_PATTERN_FAMILIES,
    PII_PRIORITY_ORDER,
    is_valid_ip
)


def is_valid_location_value(subcat, value):
    """Filters technical false positives for location data."""
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

# def is_valid_ip(value: str) -> bool:
#     try:
#         val = str(value).strip('"')
#         ip = ipaddress.ip_address(val)
#         return not (ip.is_unspecified or ip.is_loopback)
#     except: return False

def is_valid_ip_in_context(ip_match: str, value: str, field_path: str) -> bool:
    """
    Validates if a detected IP is a real IP and not a false positive.
    """
    # 1. Basic technical validation
    if not is_valid_ip(ip_match):
        return False
    
    # 2. Blacklist of suspicious IPs (versions, placeholders)
    suspicious_ips = {
        '140.0.0.0',  # Version Chrome/Browser
        '0.0.0.0',    # Placeholder
        '255.255.255.255',  # Broadcast
        '127.0.0.1',  # Localhost
    }
    if ip_match in suspicious_ips:
        return False
    

    # 4. Network check (private, loopback, reserved)
    try:
        ip_obj = ipaddress.ip_address(ip_match)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return False
    except:
        return False
    
    # 5. IP in URL (SDK version, CDN)
    if re.search(r'https?://[^\s]+', str(value)):
        if re.search(re.escape(ip_match), str(value)):
            return False
    
    # 6. Technical context (version, sdk, browser)
    path_lower = field_path.lower()
    val_lower = str(value).lower()
    
    tech_keywords = ['version', 'sdk', 'browser', 'agent', 'ua', 'build', 
                     'release', 'chrome', 'firefox', 'safari', 'edge']
    if any(kw in path_lower or kw in val_lower for kw in tech_keywords):
        return False
    
    # 7. URL/manifest/endpoint fields
    url_keywords = ['url', 'link', 'href', 'src', 'manifest', 'endpoint', 
                    'api', 'cdn', 'path', 'uri']
    if any(kw in path_lower for kw in url_keywords):
        return False

    if re.match(r'^\[\d+\]\.value$', field_path) and ip_match.endswith('.0.0.0'):
        return False
    
    return True

def is_valid_jwt(token):
    if not HAS_JWT: return str(token).count('.') == 2
    try:
        jwt.decode(str(token), options={"verify_signature": False})
        return True
    except: return False

def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except: return False

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    s = str(s)
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())



def extract_all_fields_recursive(data, parent_key='', separator='.'):
    """
    Extracts fields from an IndexedDB structure while ignoring technical metadata.
    For ObjectStoreDataValue, only the content of 'value' is extracted.
    """
    fields = []
    
    if isinstance(data, dict):
        # If it's an ObjectStoreDataValue, extract only the content from 'value'
        if data.get('__type__') == 'ObjectStoreDataValue' and 'value' in data:
            # Continue extraction from 'value' only
            value_content = data['value']
            if isinstance(value_content, (dict, list)):
                fields.extend(extract_all_fields_recursive(value_content, parent_key, separator))
            else:
                # If value is a simple value, return it with the parent_key
                if parent_key:
                    fields.append((parent_key, value_content))
        # If it's an IDBKeyPath or other technical type, ignore it completely
        elif data.get('__type__') in ['IDBKeyPath', 'IDBKey']:
            # Ignorer ces types techniques
            pass
        else:
            # Pour les autres dictionnaires, extraction normale
            for key, value in data.items():
                # Ignore technical metadata keys
                if key in ['__type__', 'version', 'blob_size', 'blob_offset', 'offset', 'type']:
                    continue
                    
                new_key = f"{parent_key}{separator}{key}" if parent_key else key
                if isinstance(value, (dict, list)): 
                    fields.extend(extract_all_fields_recursive(value, new_key, separator))
                else: 
                    fields.append((new_key, value))
                    
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            new_key = f"{parent_key}[{idx}]"
            if isinstance(item, (dict, list)): 
                fields.extend(extract_all_fields_recursive(item, new_key, separator))
            else: 
                fields.append((new_key, item))
    
    return fields

def extract_json_keys_recursive(obj, parent_key=''):
    keys = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            keys.append(full_key)
            if isinstance(value, (dict, list)):
                keys.extend(extract_json_keys_recursive(value, full_key))
    return keys


def deduplicate_pii_matches_idb(matches_list):
    if not matches_list: return []
    subcat_to_family = {sub: fam for fam, subs in PII_PATTERN_FAMILIES.items() for sub in subs}
    family_matches = {}
    standalone = []
    for m in matches_list:
        cat, subcat, m_type, dec = m
        if subcat in subcat_to_family:
            fam = subcat_to_family[subcat]
            if fam not in family_matches: family_matches[fam] = []
            family_matches[fam].append(m)
        else: standalone.append(m)
    deduplicated = []
    for fam, m_list in family_matches.items():
        prio = PII_PRIORITY_ORDER.get(fam, [])
        m_list.sort(key=lambda x: prio.index(x[1]) if x[1] in prio else 999)
        deduplicated.append(m_list[0])
    return deduplicated + standalone


def categorize_idb_field(field_path, value, patterns):
    val_str = str(value)
    # Extraction of the final key name for matching
    field_name = field_path.split('.')[-1]
    path_lower = field_path.lower()
    context_info = (field_path + field_name).lower()
    
    # --- STEP 0: ANTI-EXPLOSION (Structural Filter) ---
    structural_suffixes = ('.key', '.value.key', '.name', '.propertyname', '._id', '.compositekey')
    if any(path_lower.endswith(s) for s in structural_suffixes):
        if len(val_str) < 60 and "@" not in val_str:
            return {'primary_matches': [('INTERNAL_IDB_KEYS', 'structural_metadata', 'name', None)], 'pii_keys_matches': []}

    pii_keys_matches = set()
    
    # --- STEP 1: DIRECT_PII_KEYS (Intention / Structure) ---
    if 'DIRECT_PII_KEYS' in patterns:
        tech_names = [field_name]  # We only use field_name
        try:
            parsed = json.loads(val_str)
            if isinstance(parsed, (dict, list)): tech_names.extend(extract_json_keys_recursive(parsed))
        except: pass
        for subcat, pattern in patterns['DIRECT_PII_KEYS'].items():
            for t_name in tech_names:
                if re.search(pattern, str(t_name), re.IGNORECASE):
                    pii_keys_matches.add(('DIRECT_PII_KEYS', subcat, 'name', None))
                    break  # One match per pattern

    # --- STEP 2: DECISION HIERARCHY AND PRIORITIES ---
    priority_order = ['DIRECT_PII', 'SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS', 
                      'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES', 'SUSPICIOUS_VALUES', 'CONSENT_AND_PRIVACY']
    
    # Dynamic addition of other categories from regex.py
    for cat in patterns.keys():
        if cat not in priority_order and cat != 'DIRECT_PII_KEYS': 
            priority_order.append(cat)

    detected_pairs = set() 
    final_matches = []
    vals_to_check = try_decode_value(val_str)

    for category in priority_order:
        if category not in patterns: continue
        
        for subcat, pattern in patterns[category].items():

            # A. Match on IDENTITY (Field name only, not the full path)
            if re.search(pattern, field_name, re.IGNORECASE):
                # Specific validity controls
                if category in ['SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS']:
                    if not is_valid_location_value(subcat, val_str): continue
                
                if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
                    if shannon_entropy(val_str) < 3.0: continue
                
                # For PII and SUSPICIOUS, continue to check the value as well
                if category in ['DIRECT_PII', 'SUSPICIOUS_VALUES']:
                    if (category, subcat) not in detected_pairs:
                        final_matches.append((category, subcat, 'name', None))
                        detected_pairs.add((category, subcat))
                    continue
                
                # For others, immediate return (Mutual Exclusion)
                return {'primary_matches': [(category, subcat, 'name', None)], 'pii_keys_matches': list(pii_keys_matches)}
            
            # A.2. SPECIAL CASE: If field_name is "value", also check within the value
            # for "keys based" categories (all except DIRECT_PII, SUSPICIOUS_VALUES, DIRECT_PII_KEYS)
            if field_name == "value" and category not in ['DIRECT_PII', 'SUSPICIOUS_VALUES', 'DIRECT_PII_KEYS']:
                if re.search(pattern, val_str, re.IGNORECASE):
                    # Specific validity controls
                    if category in ['SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS']:
                        if not is_valid_location_value(subcat, val_str): continue
                    
                    if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
                        if shannon_entropy(val_str) < 3.0: continue
                    
                    # Immediate return (Mutual Exclusion)
                    return {'primary_matches': [(category, subcat, 'value', None)], 'pii_keys_matches': list(pii_keys_matches)}

            # B. Match on CONTENT (Search in raw or decoded value)
            if category in ['DIRECT_PII', 'SUSPICIOUS_VALUES']:
                for val in vals_to_check:
                    all_matches = collect_all_pii_matches(patterns[category], str(val))
                    for s_m, t_m, _, _ in all_matches:
                        # Technical validations
                        if s_m == "ip_address":
                            # if not is_valid_ip(t_m): continue
                            # if any(x in context_info for x in ['version', 'sdk', 'browser', 'agent', 'ua']): continue
                            # if "Mozilla" in str(val): continue
                            # if t_m.startswith("140."): continue
                            if not is_valid_ip_in_context(t_m, val, field_path): continue
                        if s_m == "jwt_token" and not is_valid_jwt(t_m): continue
                        if s_m == "uuid_format" and not is_valid_uuid(t_m): continue
                        if s_m in ['first_name', 'last_name'] and "@" in str(val): continue
                        
                        if (category, s_m) not in detected_pairs:
                            dec_val = val if val != val_str else None
                            final_matches.append((category, s_m, 'value', dec_val))
                            detected_pairs.add((category, s_m))
                
                # If a direct PII leak is found in the content, treat it as priority
                if final_matches and category == 'DIRECT_PII':
                    return {'primary_matches': deduplicate_pii_matches_idb(final_matches), 'pii_keys_matches': list(pii_keys_matches)}

    if final_matches:
        return {'primary_matches': deduplicate_pii_matches_idb(final_matches), 'pii_keys_matches': list(pii_keys_matches)}
    
    return {'primary_matches': None, 'pii_keys_matches': list(pii_keys_matches)}



def process_indexeddb_for_config(input_dir, output_dir, patterns):
    json_files = list(input_dir.glob("*.json"))
    if not json_files: return
    output_dir.mkdir(parents=True, exist_ok=True)
    categorized = defaultdict(list)

    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                content = data.get("data", data) if isinstance(data, dict) else data
                all_fields = extract_all_fields_recursive(content)
                for path, val in all_fields:
                    res = categorize_idb_field(path, val, patterns)
                    if res['primary_matches']:
                        for m_cat, m_sub, m_type, dec in res['primary_matches']:
                            categorized[m_cat].append({
                                'field_path': path, 'name': path.split('.')[-1], 'value': val,
                                'matched_subcategory': m_sub, 'match_type': m_type, 'decoded_value': dec,
                                'source_file': json_file.name
                            })
                    else:
                        item_out = {'field_path': path, 'value': val, 'source_file': json_file.name,'name': path.split('.')[-1]}
                        dec_list = try_decode_value(str(val))
                        if len(dec_list) > 1: item_out['try_decoded_value'] = dec_list[1]
                        categorized['UNCATEGORIZED'].append(item_out)

                    for ck, cs, cmt, cd in res['pii_keys_matches']:
                        categorized[ck].append({'field_path': path, 'value': val, 'matched_subcategory': cs, 'match_type': cmt, 'source_file': json_file.name})
        except: continue

    for cat, items in categorized.items():
        if items:
            with open(output_dir / f"{cat}.json", 'w', encoding='utf-8') as f:
                json.dump(items, f, indent=2, ensure_ascii=False)

def main():
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    users = ('FR_0417', 'FR_0446', 'FR_0458')
    for auth in ('Auth', 'UnAuth'):
        for user in users:
            patterns = get_patterns_for_user(user)
            for pol in ('ALL', 'PARTIAL', 'NONE'):
                input_p = base_dir / 'preprocessing' / auth / user / pol / 'indexeddb'
                output_p = base_dir / 'user' / auth / user / pol / 'indexeddb'
                if input_p.exists():
                    print(f"Categorization: {user} | {auth} | {pol}")
                    process_indexeddb_for_config(input_p, output_p, patterns)

if __name__ == '__main__':
    main()