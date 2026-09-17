"""
Utility functions for GDPR Profile Reconstruction Analysis
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple
from urllib.parse import urlparse
import re


def load_categorized_data(
    base_path: str,
    nav_mode: str,
    user_id: str,
    policy: str,
    storage_type: str,
    lifecycle: str = None
) -> List[Dict[str, Any]]:
    """
    Load categorized data from the user directory structure.
    
    Args:
        base_path: Base path to data/user directory
        nav_mode: 'Auth' or 'UnAuth'
        user_id: User identifier (e.g., 'FR_0417')
        policy: Consent policy ('ALL', 'NONE', 'PARTIAL')
        storage_type: Type of storage ('cookies', 'indexeddb', 'localstorage', 'sessionstorage')
        lifecycle: Optional lifecycle filter ('added', 'modified', 'removed')
    
    Returns:
        List of categorized items
    """
    all_items = []
    
    storage_path = Path(base_path) / nav_mode / user_id / policy / storage_type
    
    if not storage_path.exists():
        print(f"Warning: Path does not exist: {storage_path}")
        return all_items
    
    # Support for flat IndexedDB structure (no lifecycle subdirectories)
    if storage_type == 'indexeddb':
        for json_file in storage_path.glob('*.json'):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # Add metadata to each item
                    if isinstance(data, list):
                        for item in data:
                            item['_metadata'] = {
                                'nav_mode': nav_mode,
                                'user_id': user_id,
                                'policy': policy,
                                'storage_type': storage_type,
                                'lifecycle': 'unknown',  
                                'category': json_file.stem  # filename without extension
                            }
                            all_items.append(item)
                    elif isinstance(data, dict):
                        data['_metadata'] = {
                            'nav_mode': nav_mode,
                            'user_id': user_id,
                            'policy': policy,
                            'storage_type': storage_type,
                            'lifecycle': 'unknown',
                            'category': json_file.stem
                        }
                        all_items.append(data)
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
    else:
       
        if lifecycle:
            lifecycle_dirs = [lifecycle]
        else:
            lifecycle_dirs = ['added', 'modified', 'removed']
        
        for lc in lifecycle_dirs:
            lc_path = storage_path / lc
            if not lc_path.exists():
                continue
            
            # Load all JSON files in the lifecycle directory
            for json_file in lc_path.glob('*.json'):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        # Metadata enrichment
                        if isinstance(data, list):
                            for item in data:
                                item['_metadata'] = {
                                    'nav_mode': nav_mode,
                                    'user_id': user_id,
                                    'policy': policy,
                                    'storage_type': storage_type,
                                    'lifecycle': lc,
                                    'category': json_file.stem  # filename without extension
                                }
                                all_items.append(item)
                        elif isinstance(data, dict):
                            data['_metadata'] = {
                                'nav_mode': nav_mode,
                                'user_id': user_id,
                                'policy': policy,
                                'storage_type': storage_type,
                                'lifecycle': lc,
                                'category': json_file.stem
                            }
                            all_items.append(data)
                except Exception as e:
                    print(f"Error loading {json_file}: {e}")
    
    return all_items


def load_all_user_data(base_path: str, nav_mode: str, user_id: str, policy: str) -> Dict[str, List[Dict]]:
    """
    Load all categorized data for a specific user/mode/policy combination.
    
    Returns:
        Dictionary with storage types as keys and lists of items as values
    """
    storage_types = ['cookies', 'indexeddb', 'localstorage', 'sessionstorage']
    
    all_data = {}
    for storage_type in storage_types:
        all_data[storage_type] = load_categorized_data(
            base_path, nav_mode, user_id, policy, storage_type
        )
    
    return all_data


def extract_domain_from_source_file(source_file: str) -> str:
    """
    Extract domain from IndexedDB source_file format.
    
    Format: https_domain.com_0.indexeddb.leveldb.json
    Example: https_fr.windfinder.com_0.indexeddb.leveldb.json  fr.windfinder.com
    
    Args:
        source_file: Source file name from IndexedDB item
    
    Returns:
        Extracted domain or 'unknown'
    """
    if not source_file:
        return 'unknown'
    
    # Pattern: https_DOMAIN_NUMBER.indexeddb.leveldb.json
    # We want to extract DOMAIN
    pattern = r'https?_([^_]+(?:\.[^_]+)*)_\d+\.indexeddb'
    match = re.search(pattern, source_file)
    
    if match:
        domain = match.group(1)
        # Replace underscores with dots (they're escaped in the filename)
        # e.g., fr_windfinder_com  fr.windfinder.com (if needed)
        # But usually it's already correct: fr.windfinder.com
        return domain
    
    return 'unknown'


def extract_domain(key: str, value: str = None, storage_type: str = None, item: Dict[str, Any] = None) -> str:
    """
    Extract domain from storage key, value, or item metadata.
    
    Args:
        key: Storage key (cookie name, localStorage key, etc.)
        value: Optional value to extract domain from
        storage_type: Type of storage for context
        item: Optional full item dict (for IndexedDB source_file)
    
    Returns:
        Extracted domain or 'unknown'
    """
    # For IndexedDB, try to extract from source_file first
    if storage_type == 'indexeddb' and item and 'source_file' in item:
        domain = extract_domain_from_source_file(item['source_file'])
        if domain != 'unknown':
            return domain
    
    # Try to extract from key first
    domain_patterns = [
        r'https?://([^/]+)',
        r'([a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,})',
        r'([a-z0-9-]+\.[a-z]{2,})',
    ]
    
    for pattern in domain_patterns:
        match = re.search(pattern, key, re.IGNORECASE)
        if match:
            return match.group(1)
    
    # Try value if provided
    if value:
        for pattern in domain_patterns:
            match = re.search(pattern, str(value), re.IGNORECASE)
            if match:
                return match.group(1)
    
    return 'unknown'


def calculate_pii_overlap(items1: List[Dict], items2: List[Dict]) -> Dict[str, Any]:
    """
    Calculate overlap between two sets of PII items.
    
    Returns:
        Dictionary with overlap statistics
    """
    # Extract unique values from each set
    values1 = set()
    values2 = set()
    
    for item in items1:
        if 'value' in item:
            values1.add(str(item['value']))
        elif 'decoded_value' in item:
            values1.add(str(item['decoded_value']))
    
    for item in items2:
        if 'value' in item:
            values2.add(str(item['value']))
        elif 'decoded_value' in item:
            values2.add(str(item['decoded_value']))
    
    overlap = values1.intersection(values2)
    
    return {
        'set1_count': len(values1),
        'set2_count': len(values2),
        'overlap_count': len(overlap),
        'overlap_percentage': (len(overlap) / len(values1) * 100) if values1 else 0,
        'overlapping_values': list(overlap)
    }


def generate_profile_id(nav_mode: str, user_id: str, policy: str) -> str:
    """
    Generate unique profile identifier.
    
    Returns:
        Profile ID string
    """
    return f"{nav_mode}_{user_id}_{policy}"


def export_to_json(data: Any, output_path: str, indent: int = 2) -> None:
    """
    Export data to JSON file with proper formatting.
    
    Args:
        data: Data to export
        output_path: Path to output file
        indent: JSON indentation level
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)
    
    print(f"Exported to: {output_path}")


def get_pii_categories() -> List[str]:
    """
    Get list of all PII categories from taxonomy.
    
    Returns:
        List of category names
    """
    return [
        'DIRECT_PII',
        'DIRECT_PII_KEYS',
        'SENSITIVE_LOCATION_PII',
        'LOCATION_AND_DEMOGRAPHICS',
        'ID_SOLUTIONS_AND_EXCHANGES',
        'NAVIGATION_HISTORY',
        'BEHAVIORAL_DATA',
        'IDENTITY_TRACKING',
        'APP_STATE_STORAGE',
        'TECHNICAL_PASSWORDS',
        'DEVICE_ENV',
        'FINGERPRINTING_ADVANCED',
        'TELEMETRY_AND_ERRORS',
        'CONSENT_AND_PRIVACY',
        'SERVER_SIDE_TRACKING',
        'USER_PREFERENCES',
        'UX_AND_PERFORMANCE_ANALYTICS',
        'SECURITY_AND_BOT_MITIGATION',
        'SESSION_MANAGEMENT',
        'INFRASTRUCTURE'
    ]


def categorize_pii_sensitivity(category: str) -> str:
    """
    Categorize PII by GDPR sensitivity level.
    
    Returns:
        'critical', 'high', 'medium', or 'low'
    """
    critical_categories = [
        'DIRECT_PII',
        'DIRECT_PII_KEYS',
        'SENSITIVE_LOCATION_PII'
    ]
    
    high_categories = [
        'LOCATION_AND_DEMOGRAPHICS',
        'FINGERPRINTING_ADVANCED',
        'ID_SOLUTIONS_AND_EXCHANGES'
    ]
    
    medium_categories = [
        'IDENTITY_TRACKING',
        'NAVIGATION_HISTORY',
        'BEHAVIORAL_DATA',
        'SUSPICIOUS_VALUES'
    ]
    
    if category in critical_categories:
        return 'critical'
    elif category in high_categories:
        return 'high'
    elif category in medium_categories:
        return 'medium'
    else:
        return 'low'


def extract_pii_value(item: Dict[str, Any]) -> str:
    """
    Extract PII value from item, handling different formats.
    
    Returns:
        Extracted value as string
    """
    if 'decoded_value' in item and item['decoded_value']:
        return str(item['decoded_value'])
    elif 'value' in item:
        return str(item['value'])
    elif 'field_value' in item:
        return str(item['field_value'])
    else:
        return ''


def get_storage_key(item: Dict[str, Any]) -> str:
    """
    Extract storage key from item, handling different formats.
    
    Returns:
        Storage key as string
    """
    if 'name' in item:
        return item['name']
    elif 'key' in item:
        return item['key']
    elif 'field_path' in item:
        return item['field_path']
    else:
        return 'unknown'


def count_by_category(items: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count items by category.
    
    Returns:
        Dictionary mapping category to count
    """
    counts = {}
    for item in items:
        category = item.get('_metadata', {}).get('category', 'UNCATEGORIZED')
        counts[category] = counts.get(category, 0) + 1
    
    return counts


def filter_by_category(items: List[Dict[str, Any]], category: str) -> List[Dict[str, Any]]:
    """
    Filter items by category.
    
    Returns:
        Filtered list of items
    """
    return [
        item for item in items
        if item.get('_metadata', {}).get('category') == category
    ]


def get_unique_domains(items: List[Dict[str, Any]]) -> Set[str]:
    """
    Extract unique domains from items.
    
    Returns:
        Set of unique domains
    """
    domains = set()
    
    for item in items:
        # Try to get domain from item
        if 'domain' in item:
            domains.add(item['domain'])
        else:
            # Extract from key/value with full item context
            key = get_storage_key(item)
            value = extract_pii_value(item)
            storage_type = item.get('_metadata', {}).get('storage_type')
            domain = extract_domain(key, value, storage_type, item)
            if domain != 'unknown':
                domains.add(domain)
    
    return domains

def get_matched_subcategory(item: Dict[str, Any]) -> str:

    return item.get('_matched_subcategory') or item.get('matched_subcategory') or ''
