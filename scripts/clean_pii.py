

import json
import os
from pathlib import Path
from typing import List, Dict, Any

BEHAVIORAL_TRANSFERS = ["lastLoginAt", "createdAt", "isAnonymous"]

SUSPICIOUS_MAPPING = {
    "jwt_token": "TECHNICAL_PASSWORDS.json",
    "auth_tokens": "TECHNICAL_PASSWORDS.json",
    "auth0_patterns": "TECHNICAL_PASSWORDS.json",
    "api_keys": "TECHNICAL_PASSWORDS.json",
    "uuid_format": "IDENTITY_TRACKING.json",
    "tracking_extended": "IDENTITY_TRACKING.json",
    "geo_coordinates": "LOCATION_AND_DEMOGRAPHICS.json",
    "url_list": "BEHAVIORAL_DATA.json",
    "google_rollout": "UX_AND_PERFORMANCE_ANALYTICS.json",
    "base64_json": "APP_STATE_STORAGE.json",
    "php_serialized": "APP_STATE_STORAGE.json"
}

def main():
    base_dir = Path(__file__).resolve().parent.parent
    data_user_dir = base_dir / "data" / "user"
    fp_dir_root = base_dir / "data_false_positives"
    
    if not data_user_dir.exists():
        print(f"Error: Directory {data_user_dir} does not exist.")
        return

    print(f"Starting PII cleaning and redistribution from: {data_user_dir}")

    stats = {
        'files_processed': 0,
        'ip_false_positives': 0,
        'timestamp_false_positives': 0,
        'behavioral_relocations': 0,
        'suspicious_redistributions': 0,
        'files_cleaned': 0
    }

    for root, dirs, files in os.walk(data_user_dir):
        root_path = Path(root)
        
        for filename in files:
            file_upper = filename.upper()
            if file_upper == "DIRECT_PII.JSON":
                file_path = root_path / filename
                clean_direct_pii(file_path, data_user_dir, fp_dir_root, stats)
            elif file_upper == "DIRECT_PII_KEYS.JSON":
                file_path = root_path / filename
                clean_direct_pii_keys(file_path, data_user_dir, fp_dir_root, stats)
            elif file_upper == "SUSPICIOUS_VALUES.JSON":
                file_path = root_path / filename
                redistribute_suspicious(file_path, stats)

    print("\n" + "="*40)
    print("CLEANING & REDISTRIBUTION COMPLETE")
    print("="*40)
    print(f"Files processed: {stats['files_processed']}")
    print(f"Files modified: {stats['files_cleaned']}")
    print(f"IP false positives (1.1.*) moved to FP dir: {stats['ip_false_positives']}")
    print(f"Timestamp key false positives moved to FP dir: {stats['timestamp_false_positives']}")
    print(f"Behavioral items relocated: {stats['behavioral_relocations']}")
    print(f"Suspicious items redistributed: {stats['suspicious_redistributions']}")
    print("="*40)

def clean_direct_pii(file_path: Path, data_user_dir: Path, fp_dir_root: Path, stats: Dict[str, Any]):
    """Clean DIRECT_PII.json: removes ip_address starting with 1.1. and behavioral items."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            items = json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return

    stats['files_processed'] += 1
    
    valid_items = []
    false_positives = []
    behavioral_items = []

    for item in items:
        name = item.get('name', '')
        subcat = item.get('matched_subcategory', '')
        value = str(item.get('value', ''))

        if subcat == 'ip_address' and value.startswith('1.1.'):
            false_positives.append(item)
        elif name in BEHAVIORAL_TRANSFERS:
            behavioral_items.append(item)
        else:
            valid_items.append(item)

    if false_positives or behavioral_items:
        # Save valid items back to original file
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(valid_items, f, indent=2)
        
        # Save false positives to mirrored directory
        if false_positives:
            save_items_to_path(file_path, false_positives, data_user_dir, fp_dir_root)
            stats['ip_false_positives'] += len(false_positives)
        
        # Relocate behavioral items to BEHAVIORAL_DATA.json in the SAME folder
        if behavioral_items:
            relocate_items(file_path.parent / "BEHAVIORAL_DATA.json", behavioral_items, "DIRECT_PII", "behavioral_telemetry")
            stats['behavioral_relocations'] += len(behavioral_items)
        
        stats['files_cleaned'] += 1
        print(f"Cleaned {len(false_positives)} IPs and {len(behavioral_items)} behavioral items from {file_path.relative_to(data_user_dir)}")

def clean_direct_pii_keys(file_path: Path, data_user_dir: Path, fp_dir_root: Path, stats: Dict[str, Any]):
    """Clean DIRECT_PII_KEYS.json: removes timestamp_key."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            items = json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return

    stats['files_processed'] += 1
    
    valid_items = []
    false_positives = []

    for item in items:
        if item.get('matched_subcategory') == 'timestamp_key':
            false_positives.append(item)
        else:
            valid_items.append(item)

    if false_positives:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(valid_items, f, indent=2)
        
        save_items_to_path(file_path, false_positives, data_user_dir, fp_dir_root)
        stats['timestamp_false_positives'] += len(false_positives)
        stats['files_cleaned'] += 1
        print(f"Cleaned {len(false_positives)} timestamp items from {file_path.relative_to(data_user_dir)}")

def redistribute_suspicious(file_path: Path, stats: Dict[str, Any]):
    """Redistributes items from SUSPICIOUS_VALUES.json to other files."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            items = json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return

    if not items:
        return

    stats['files_processed'] += 1
    redistributed_count = 0
    
    # Group items by their target file
    targets = {}
    for item in items:
        subcat = item.get('matched_subcategory', item.get('_matched_subcategory', ''))
        target_file = SUSPICIOUS_MAPPING.get(subcat)
        
        if target_file:
            if target_file not in targets:
                targets[target_file] = []
            targets[target_file].append(item)
        else:
            # If no mapping, we could leave it or move to UNCATEGORIZED or a default?
            # The user said "redistribution of all suspicious_values.json",
            # implying we should handle everything. If missing, print a warning.
            print(f"Warning: No mapping for subcategory '{subcat}' in {file_path}")

    for target_file, redistributed_items in targets.items():
        target_path = file_path.parent / target_file
        relocate_items(target_path, redistributed_items, "SUSPICIOUS_VALUES")
        redistributed_count += len(redistributed_items)

    # Remove or clear the original file
    if redistributed_count > 0:
        # If all items are redistributed, we should empty the file or delete it.
        # Let's empty it to be safe (keep the file but set content to [])
        # or delete it if the user wants it gone. "Redistribution" usually means moving.
        # I'll empty it to indicate it has been processed.
        remaining_items = [item for item in items if item.get('matched_subcategory', item.get('_matched_subcategory', '')) not in SUSPICIOUS_MAPPING]
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(remaining_items, f, indent=2)
            
        stats['suspicious_redistributions'] += redistributed_count
        stats['files_cleaned'] += 1
        print(f"Redistributed {redistributed_count} items from {file_path.name} in {file_path.parent.name}")

def relocate_items(target_path: Path, items: List[Dict], original_cat: str, new_subcat: str = None):
    """Appends items to a target JSON file."""
    existing_items = []
    if target_path.exists():
        try:
            with open(target_path, 'r', encoding='utf-8') as f:
                existing_items = json.load(f)
        except Exception as e:
            print(f"Warning: Could not read {target_path} for merging: {e}")
            
    for item in items:
        item['original_category'] = original_cat
        if new_subcat:
            item['matched_subcategory'] = new_subcat
        
    all_items = existing_items + items
    
    with open(target_path, 'w', encoding='utf-8') as f:
        json.dump(all_items, f, indent=2)

def save_items_to_path(original_file_path: Path, items: List[Dict], data_user_dir: Path, output_root: Path):
    """Save extracted items to a mirrored directory structure in data_false_positives."""
    relative_path = original_file_path.relative_to(data_user_dir)
    target_path = output_root / relative_path
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    existing_items = []
    if target_path.exists():
        try:
            with open(target_path, 'r', encoding='utf-8') as f:
                existing_items = json.load(f)
        except:
            pass
            
    all_items = existing_items + items
    with open(target_path, 'w', encoding='utf-8') as f:
        json.dump(all_items, f, indent=2)

if __name__ == "__main__":
    main()
