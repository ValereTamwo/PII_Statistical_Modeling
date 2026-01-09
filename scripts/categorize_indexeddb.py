#!/usr/bin/env python3
"""
Logique : Aplatissement récursif + Hiérarchie de priorité + Exclusion mutuelle.
"""

import os
import json
import re
import sys
from pathlib import Path
from collections import defaultdict

# Importer les regex et les fonctions de base
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from regex import TRACKING_PATTERNS_COMPLETE
from categorize_cookies import try_decode_value, USER_ID_TO_INDEX, get_patterns_for_user


def categorize_item_robust(name, value, patterns):
    """
    Logique de décision unique pour un champ IndexedDB.
    Retourne (Catégorie, Sous-Catégorie, Match_Type, Valeur_Décodée).
    """
    # 1. Hiérarchie de priorité (La même que pour les cookies)
    priority_order = [
        'DIRECT_PII',
        'IDENTITY_TRACKING',
        'ID_SOLUTIONS_AND_EXCHANGES',
        'CONSENT_AND_PRIVACY',
        'BEHAVIORAL_DATA',
        'NAVIGATION_HISTORY',
        'SUSPICIOUS_VALUES'
    ]
    for cat in patterns.keys():
        if cat not in priority_order: priority_order.append(cat)

    # 2. Préparation des valeurs à tester
    vals_to_check = try_decode_value(str(value))

    # 3. Boucle de décision unique
    for category in priority_order:
        if category not in patterns: continue
        
        for subcat, pattern in patterns[category].items():
            # A. Test sur le NOM du champ (ou chemin)
            if re.search(pattern, name, re.IGNORECASE):
                return category, subcat, 'name', None
            
            # B. Test sur la VALEUR
            for val in vals_to_check:
                if val and re.search(pattern, str(val), re.IGNORECASE):
                    # Filtre Anti-Faux Positif pour le consentement
                    if category not in ['DIRECT_PII', 'CONSENT_AND_PRIVACY']:
                        if re.search(r'(consent|privacy|tac-portail|didomi|cookie-notice)', name, re.IGNORECASE):
                            continue
                            
                    return category, subcat, 'value', (val if val != str(value) else None)
                    
    return 'UNCATEGORIZED', 'none', 'none', None

def extract_all_fields_recursive(data, parent_key='', separator='.'):
    fields = []
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else key
            if isinstance(value, (dict, list)): fields.extend(extract_all_fields_recursive(value, new_key))
            else: fields.append((new_key, value))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            new_key = f"{parent_key}[{idx}]"
            if isinstance(item, (dict, list)): fields.extend(extract_all_fields_recursive(item, new_key))
            else: fields.append((new_key, item))
    return fields

def categorize_idb_field(field_path, value, patterns):
    """
    Stratégie Hybride pour IndexedDB :
    - field_path (chemin du champ) est traité comme une KEY.
    - value est analysée UNIQUEMENT pour DIRECT_PII.
    """
    priority_order = ['DIRECT_PII', 'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES', 'CONSENT_AND_PRIVACY']
    for cat in patterns.keys():
        if cat not in priority_order: priority_order.append(cat)

    # Préparation des valeurs décodées (pour la PII)
    from categorize_cookies import try_decode_value
    vals_to_check = try_decode_value(str(value))

    for category in priority_order:
        if category not in patterns: continue
        for subcat, pattern in patterns[category].items():
            
            # --- TEST SUR LE CHEMIN (Identity / Key) ---
            # On cherche dans le chemin complet (ex: settings.google_id)
            if re.search(pattern, field_path, re.IGNORECASE):
                return category, subcat, 'name'
            
            # --- TEST SUR LA VALEUR (Value) ---
            # Uniquement pour la PII
            if category == 'DIRECT_PII':
                for val in vals_to_check:
                    if val and re.search(pattern, str(val), re.IGNORECASE):
                        return category, subcat, 'value'
                        
    return 'UNCATEGORIZED', 'none', 'none'

def categorize_indexeddb_for_config(input_dir, output_dir, patterns):
    json_files = list(input_dir.glob("*.json"))
    if not json_files: return
    output_dir.mkdir(parents=True, exist_ok=True)
    categorized = defaultdict(list)

    for json_file in json_files:
        with open(json_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                data_to_process = data.get("data", data) if isinstance(data, dict) else data
                all_fields = extract_all_fields_recursive(data_to_process)
                
                for field_path, field_value in all_fields:
                    cat, subcat, m_type = categorize_idb_field(field_path, field_value, patterns)
                    
                    # Garde ton format de stockage IndexedDB original
                    item_out = {
                        'field_path': field_path,
                        'name': field_path.split('.')[-1],
                        'value': field_value,
                        'matched_subcategory': subcat,
                        'match_type': m_type,
                        'source_file': json_file.name
                    }
                    categorized[cat].append(item_out)
            except: continue

    for category, items in categorized.items():
        with open(output_dir / f"{category}.json", 'w', encoding='utf-8') as f:
            json.dump(items, f, indent=2, ensure_ascii=False)

def main():
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    users = ('FR_0417', 'FR_0446', 'FR_0458')
    auth_statuses = ('Auth', 'UnAuth')
    policies = ('ALL', 'PARTIAL', 'NONE')

    for auth in auth_statuses:
        for user in users:
            user_patterns = get_patterns_for_user(user)
            for policy in policies:
                input_path = base_dir / 'preprocessing' / auth / user / policy / 'indexeddb'
                output_path = base_dir / 'user' / auth / user / policy / 'indexeddb'
                
                if input_path.exists():
                    print(f"Catégorisation IndexedDB: {user} ({auth}/{policy})")
                    categorize_indexeddb_for_config(input_path, output_path, user_patterns)

if __name__ == '__main__':
    main()