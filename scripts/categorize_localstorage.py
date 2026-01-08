#!/usr/bin/env python3
"""
Script final de catégorisation localStorage / sessionStorage.
Logique : Hiérarchie stricte + Analyse JSON profonde + Exclusion mutuelle.
"""

import json
import re
import sys
import os
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple

# Importer les regex existantes
sys.path.insert(0, str(Path(__file__).parent))
from regex import TRACKING_PATTERNS_COMPLETE

USER_ID_TO_INDEX = {'FR_0017': 0, 'FR_0018': 1, 'FR_0019': 2}

def get_patterns_for_user(user_id):
    patterns = dict(TRACKING_PATTERNS_COMPLETE)
    user_index = USER_ID_TO_INDEX.get(user_id, 0)
    if isinstance(TRACKING_PATTERNS_COMPLETE['DIRECT_PII'], list):
        patterns['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII'][user_index]
    return patterns

def extract_all_text_from_json(obj, texts):
    if isinstance(obj, dict):
        for k, v in obj.items():
            texts.append(str(k))
            extract_all_text_from_json(v, texts)
    elif isinstance(obj, list):
        for item in obj: extract_all_text_from_json(item, texts)
    else:
        if obj is not None: texts.append(str(obj))

def categorize_storage_item(item, patterns):
    """
    Stratégie Hybride pour Storage :
    - DIRECT_PII : Analyse Clé + Valeurs JSON
    - Reste : Analyse Clé + Clés internes JSON (mais pas les valeurs)
    """
    main_key = item.get('key', '')
    value_raw = str(item.get('value', ''))
    
    # 1. Extraire les clés et valeurs séparément si c'est du JSON
    internal_keys = []
    all_values = [value_raw]
    try:
        parsed = json.loads(value_raw)
        # On récupère toutes les clés imbriquées (ex: path.to.key) 
        # et toutes les valeurs
        def walk(obj, path=''):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = f"{path}.{k}" if path else k
                    internal_keys.append(new_path)
                    walk(v, new_path)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    walk(v, f"{path}[{i}]")
            else:
                all_values.append(str(obj))
        walk(parsed)
    except:
        pass

    # Liste de toutes les "Identités" (Clé principale + Clés internes)
    all_identity_elements = [main_key] + internal_keys

    # 2. Ordre de priorité
    priority_order = ['DIRECT_PII', 'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES', 'CONSENT_AND_PRIVACY']
    for cat in patterns.keys():
        if cat not in priority_order: priority_order.append(cat)

    for category in priority_order:
        if category not in patterns: continue
        for subcat, pattern in patterns[category].items():
            
            # --- TEST SUR LES CLÉS (Pour TOUTES les catégories) ---
            for identity in all_identity_elements:
                if re.search(pattern, identity, re.IGNORECASE):
                    return category, subcat

            # --- TEST SUR LES VALEURS (Uniquement pour DIRECT_PII) ---
            if category == 'DIRECT_PII':
                for val in all_values:
                    if val and re.search(pattern, val, re.IGNORECASE):
                        return category, subcat
                        
    return 'UNCATEGORIZED', 'none'

def process_storage_file(input_file: Path, output_dir: Path, patterns: Dict):
    """Traite un fichier JSON de storage et répartit dans les fichiers par catégorie."""
    if not input_file.exists(): return

    print(f"  Traitement de {input_file.name}...")
    with open(input_file, 'r', encoding='utf-8') as f:
        items = json.load(f)

    categorized_data = defaultdict(list)
    
    for item in items:
        primary_cat, sub_cat = categorize_storage_item(item, patterns)
        
        # Enrichissement de l'item
        item_out = item.copy()
        item_out['_primary_category'] = primary_cat
        item_out['_matched_subcategory'] = sub_cat
        item_out['_size_bytes'] = len(str(item.get('value', '')).encode('utf-8'))
        
        categorized_data[primary_cat].append(item_out)

    # Sauvegarde
    output_dir.mkdir(parents=True, exist_ok=True)
    for category, rows in categorized_data.items():
        out_file = output_dir / f"{category}.json"
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)

def main():
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    users = ('FR_0017', 'FR_0018', 'FR_0019')
    auth_statuses = ('Auth', 'UnAuth')
    policies = ('ALL', 'PARTIAL', 'NONE')
    storage_types = ('localstorage', 'sessionstorage')

    for user in users:
        user_patterns = get_patterns_for_user(user)
        
        for auth in auth_statuses:
            for pol in policies:
                for s_type in storage_types:
                    input_path = base_dir / 'preprocessing' / auth / user / pol / s_type
                    if not input_path.exists(): continue
                    
                    output_base = base_dir / 'user' / auth / user / pol / s_type
                    
                    print(f"\nAnalysing {s_type} for {user} ({auth}/{pol})")
                    
                    # Traitement Added / Modified / Removed
                    for lifecycle in ['added', 'modified', 'removed']:
                        f_name = f"{lifecycle}_{s_type}.json"
                        process_storage_file(
                            input_path / f_name, 
                            output_base / lifecycle, 
                            user_patterns
                        )

if __name__ == '__main__':
    main()