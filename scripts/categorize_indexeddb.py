#!/usr/bin/env python3
"""
INDEXEDDB CATEGORIZATION PIPELINE - FINAL VERSION
Rigueur Scientifique : Déduplication par positions + Filtre IP Contextuel + Hiérarchie RGPD.
"""

import os
import json
import re
import sys
from pathlib import Path
from collections import defaultdict, Counter
import math
import ipaddress

# Import des constantes et fonctions partagées
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from regex import TRACKING_PATTERNS_COMPLETE
from overlap_detection import collect_all_pii_matches
from categorize_cookies import (
    try_decode_value, 
    USER_ID_TO_INDEX, 
    get_patterns_for_user,
    PII_PATTERN_FAMILIES,
    PII_PRIORITY_ORDER
)

# =====================================================================
# FONCTIONS UTILITAIRES DE SÉCURITÉ
# =====================================================================

def is_valid_ip(value: str) -> bool:
    """Valide mathématiquement une IP et ignore les adresses non-identifiantes."""
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_loopback: # Ignore 0.0.0.0 et 127.0.0.1
            return False
        return True
    except ValueError:
        return False

def shannon_entropy(s: str) -> float:
    """Calcule l'entropie pour valider la qualité des identifiants."""
    if not s: return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

def extract_all_fields_recursive(data, parent_key='', separator='.'):
    """Aplatit les structures IndexedDB complexes en field_paths."""
    fields = []
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else key
            if isinstance(value, (dict, list)): 
                fields.extend(extract_all_fields_recursive(value, new_key))
            else: 
                fields.append((new_key, value))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            new_key = f"{parent_key}[{idx}]"
            if isinstance(item, (dict, list)): 
                fields.extend(extract_all_fields_recursive(item, new_key))
            else: 
                fields.append((new_key, item))
    return fields

def extract_json_keys_recursive(obj, parent_key=''):
    """Extrait les noms des clés d'un objet JSON pour l'audit d'intention."""
    keys = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            keys.append(full_key)
            if isinstance(value, (dict, list)):
                keys.extend(extract_json_keys_recursive(value, full_key))
    return keys

# =====================================================================
# MOTEUR DE DÉDUPLICATION
# =====================================================================

def deduplicate_pii_matches_idb(matches_list):
    """Harmonise les PII (ex: garde full_name vs first_name) par champ."""
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
        else:
            standalone.append(m)
            
    deduplicated = []
    for fam, m_list in family_matches.items():
        prio = PII_PRIORITY_ORDER.get(fam, [])
        m_list.sort(key=lambda x: prio.index(x[1]) if x[1] in prio else 999)
        deduplicated.append(m_list[0])
        
    return deduplicated + standalone

# =====================================================================
# FONCTION DE CATÉGORISATION PRINCIPALE
# =====================================================================

def categorize_idb_field(field_path, value, patterns):
    val_str = str(value)
    # Contexte technique pour filtrer les faux positifs (ex: version de chrome)
    context_info = (field_path + field_path.split('.')[-1]).lower()
    
    pii_keys_matches = set()
    
    # --- ÉTAPE 1 : DIRECT_PII_KEYS (Intention / Structure) ---
    if 'DIRECT_PII_KEYS' in patterns:
        tech_names = [field_path, field_path.split('.')[-1]]
        try:
            parsed = json.loads(val_str)
            if isinstance(parsed, dict): tech_names.extend(extract_json_keys_recursive(parsed))
        except: pass

        for subcat, pattern in patterns['DIRECT_PII_KEYS'].items():
            for t_name in tech_names:
                if re.search(pattern, str(t_name), re.IGNORECASE):
                    pii_keys_matches.add(('DIRECT_PII_KEYS', subcat, 'name', None))
                    break

    # --- ÉTAPE 2 : PRIORITÉ ET EXCLUSION MUTUELLE ---
    priority_order = ['DIRECT_PII', 'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES', 'CONSENT_AND_PRIVACY']
    for cat in patterns.keys():
        if cat not in priority_order and cat != 'DIRECT_PII_KEYS': 
            priority_order.append(cat)

    detected_pairs = set() 
    final_matches = []
    vals_to_check = try_decode_value(val_str)

    for category in priority_order:
        if category not in patterns: continue
        
        for subcat, pattern in patterns[category].items():

            # A. Match sur l'IDENTITÉ (Key-Only pour Tracking/ID/Consent)
            if re.search(pattern, field_path, re.IGNORECASE):
                # Filtre Entropie pour les ID génériques
                if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
                    if shannon_entropy(val_str) < 3.0: continue
                
                if category == 'DIRECT_PII':
                    if (category, subcat) not in detected_pairs:
                        final_matches.append((category, subcat, 'name', None))
                        detected_pairs.add((category, subcat))
                    continue
                # Retour immédiat pour les autres catégories (Exclusion Mutuelle)
                return {'primary_matches': [(category, subcat, 'name', None)], 'pii_keys_matches': list(pii_keys_matches)}

            # B. Match sur le CONTENU (Value-Only pour DIRECT_PII)
            if category == 'DIRECT_PII':
                for val in vals_to_check:
                    all_pii = collect_all_pii_matches(patterns[category], str(val))
                    for s_m, t_m, start_m, end_m in all_pii:
                        
                        # --- FILTRE IP ANTI-VERSION ---
                        if s_m == "ip_address":
                            if not is_valid_ip(t_m): continue
                            # On ignore si le nom du champ ou la valeur évoquent un outil technique
                            if any(x in context_info for x in ['version', 'sdk', 'browser', 'agent', 'ua']): continue
                            if "Mozilla" in str(val): continue
                            if t_m.startswith("140."): continue # Sécurité spécifique Chrome 140

                        # --- FILTRE EMAIL/NAME ---
                        if s_m in ['first_name', 'last_name'] and "@" in str(val): continue
                        
                        # AJOUT UNIQUE (Gère les doublons de décodage)
                        if (category, s_m) not in detected_pairs:
                            dec_val = val if val != val_str else None
                            final_matches.append((category, s_m, 'value', dec_val))
                            detected_pairs.add((category, s_m))
                continue 

    if final_matches:
        return {'primary_matches': deduplicate_pii_matches_idb(final_matches), 'pii_keys_matches': list(pii_keys_matches)}
    
    return {'primary_matches': None, 'pii_keys_matches': list(pii_keys_matches)}

# =====================================================================
# GESTION DES FICHIERS ET SAUVEGARDE
# =====================================================================

def categorize_indexeddb_for_config(input_dir, output_dir, patterns):
    json_files = list(input_dir.glob("*.json"))
    if not json_files: return
    output_dir.mkdir(parents=True, exist_ok=True)
    categorized = defaultdict(list)

    for json_file in json_files:
        with open(json_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                all_fields = extract_all_fields_recursive(data.get("data", data))
                
                for path, field_value in all_fields:
                    res = categorize_idb_field(path, field_value, patterns)
                    
                    if res['primary_matches']:
                        for cat, sub, mt, dec in res['primary_matches']:
                            item_out = {
                                'field_path': path, 'name': path.split('.')[-1], 'value': field_value,
                                'matched_subcategory': sub, 'match_type': mt, 'was_decoded': dec is not None,
                                'decoded_value': dec, 'source_file': json_file.name
                            }
                            categorized[cat].append(item_out)
                    else:
                        # Item non-PII et non-Tracking -> UNCATEGORIZED
                        item_out = {'field_path': path, 'value': field_value, 'source_file': json_file.name}
                        categorized['UNCATEGORIZED'].append(item_out)

                    for cat, sub, mt, dec in res['pii_keys_matches']:
                        item_key_out = {
                            'field_path': path, 'name': path.split('.')[-1], 'value': field_value,
                            'matched_subcategory': sub, 'match_type': mt, 'source_file': json_file.name
                        }
                        categorized['DIRECT_PII_KEYS'].append(item_key_out)
            except: continue

    for category, items in categorized.items():
        if items:
            with open(output_dir / f"{category}.json", 'w', encoding='utf-8') as f:
                json.dump(items, f, indent=2, ensure_ascii=False)

# =====================================================================
# MAIN
# =====================================================================

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
                    print(f"Catégorisation {user} | {auth} | {pol}")
                    categorize_indexeddb_for_config(input_p, output_p, patterns)

if __name__ == '__main__':
    main()