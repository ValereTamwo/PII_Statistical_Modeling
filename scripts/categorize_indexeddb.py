# #!/usr/bin/env python3
# """
# INDEXEDDB CATEGORIZATION PIPELINE - FINAL VERSION
# Rigueur Scientifique : Déduplication par positions + Filtre IP Contextuel + Hiérarchie RGPD.
# """

# import os
# import json
# import re
# import sys
# from pathlib import Path
# from collections import defaultdict, Counter
# import math
# import ipaddress
# import uuid

# try:
#     import jwt
#     HAS_JWT = True
# except ImportError:
#     HAS_JWT = False

# # Import des constantes et fonctions partagées
# sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# from regex import TRACKING_PATTERNS_COMPLETE
# from overlap_detection import collect_all_pii_matches
# from categorize_cookies import (
#     try_decode_value, 
#     USER_ID_TO_INDEX, 
#     get_patterns_for_user,
#     PII_PATTERN_FAMILIES,
#     PII_PRIORITY_ORDER
# )

# # =====================================================================
# # FONCTIONS UTILITAIRES DE SÉCURITÉ
# # =====================================================================


# def is_valid_ip(value: str) -> bool:
#     """Valide mathématiquement une IP et ignore les adresses techniques."""
#     try:
#         val = str(value).strip('"')
#         ip = ipaddress.ip_address(val)
#         return not (ip.is_unspecified or ip.is_loopback)
#     except: return False

# def is_valid_jwt(token):
#     if not HAS_JWT: return str(token).count('.') == 2
#     try:
#         jwt.decode(str(token), options={"verify_signature": False})
#         return True
#     except: return False

# def is_valid_uuid(val):
#     try:
#         uuid.UUID(str(val))
#         return True
#     except: return False

# def shannon_entropy(s: str) -> float:
#     """Calcule l'entropie pour valider la qualité des identifiants."""
#     if not s: return 0.0
#     counts = Counter(s)
#     length = len(s)
#     return -sum((c/length) * math.log2(c/length) for c in counts.values())

# def extract_all_fields_recursive(data, parent_key='', separator='.'):
#     """Aplatit les structures IndexedDB complexes en field_paths."""
#     fields = []
#     if isinstance(data, dict):
#         for key, value in data.items():
#             new_key = f"{parent_key}{separator}{key}" if parent_key else key
#             if isinstance(value, (dict, list)): 
#                 fields.extend(extract_all_fields_recursive(value, new_key))
#             else: 
#                 fields.append((new_key, value))
#     elif isinstance(data, list):
#         for idx, item in enumerate(data):
#             new_key = f"{parent_key}[{idx}]"
#             if isinstance(item, (dict, list)): 
#                 fields.extend(extract_all_fields_recursive(item, new_key))
#             else: 
#                 fields.append((new_key, item))
#     return fields

# def extract_json_keys_recursive(obj, parent_key=''):
#     """Extrait les noms des clés d'un objet JSON pour l'audit d'intention."""
#     keys = []
#     if isinstance(obj, dict):
#         for key, value in obj.items():
#             full_key = f"{parent_key}.{key}" if parent_key else key
#             keys.append(full_key)
#             if isinstance(value, (dict, list)):
#                 keys.extend(extract_json_keys_recursive(value, full_key))
#     return keys

# # =====================================================================
# # MOTEUR DE DÉDUPLICATION
# # =====================================================================

# def deduplicate_pii_matches_idb(matches_list):
#     """Harmonise les PII (ex: garde full_name vs first_name) par champ."""
#     if not matches_list: return []
#     subcat_to_family = {sub: fam for fam, subs in PII_PATTERN_FAMILIES.items() for sub in subs}
    
#     family_matches = {}
#     standalone = []
    
#     for m in matches_list:
#         cat, subcat, m_type, dec = m
#         if subcat in subcat_to_family:
#             fam = subcat_to_family[subcat]
#             if fam not in family_matches: family_matches[fam] = []
#             family_matches[fam].append(m)
#         else:
#             standalone.append(m)
            
#     deduplicated = []
#     for fam, m_list in family_matches.items():
#         prio = PII_PRIORITY_ORDER.get(fam, [])
#         m_list.sort(key=lambda x: prio.index(x[1]) if x[1] in prio else 999)
#         deduplicated.append(m_list[0])
        
#     return deduplicated + standalone

# # =====================================================================
# # FONCTION DE CATÉGORISATION PRINCIPALE
# # =====================================================================

# def categorize_idb_field(field_path, value, patterns):
#     val_str = str(value)
#     # Contexte technique pour filtrer les faux positifs (ex: version de chrome)
#     context_info = (field_path + field_path.split('.')[-1]).lower()
    
#     pii_keys_matches = set()
    
#     # --- ÉTAPE 1 : DIRECT_PII_KEYS (Intention / Structure) ---
#     if 'DIRECT_PII_KEYS' in patterns:
#         tech_names = [field_path, field_path.split('.')[-1]]
#         # On regarde si la valeur est un JSON qui contient des noms de clés suspects
#         try:
#             parsed = json.loads(val_str)
#             if isinstance(parsed, (dict, list)): 
#                 tech_names.extend(extract_json_keys_recursive(parsed))
#         except: pass

#         for subcat, pattern in patterns['DIRECT_PII_KEYS'].items():
#             for t_name in tech_names:
#                 if re.search(pattern, str(t_name), re.IGNORECASE):
#                     pii_keys_matches.add(('DIRECT_PII_KEYS', subcat, 'name', None))
#                     break

#     # --- ÉTAPE 2 : PRIORITÉ ET EXCLUSION MUTUELLE ---
#     priority_order = ['DIRECT_PII', 'SUSPICIOUS_VALUES', 'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES', 'CONSENT_AND_PRIVACY']
#     for cat in patterns.keys():
#         if cat not in priority_order and cat != 'DIRECT_PII_KEYS': 
#             priority_order.append(cat)

#     detected_pairs = set() 
#     final_matches = []
#     vals_to_check = try_decode_value(val_str)

#     for category in priority_order:
#         if category not in patterns: continue
        
#         for subcat, pattern in patterns[category].items():

#             # A. Match sur l'IDENTITÉ (Nom du champ / Path)
#             if re.search(pattern, field_path, re.IGNORECASE):
#                 if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
#                     if shannon_entropy(val_str) < 3.0: continue
                
#                 # Pour PII et SUSPICIOUS, on continue pour checker la valeur
#                 if category in ['DIRECT_PII', 'SUSPICIOUS_VALUES']:
#                     if (category, subcat) not in detected_pairs:
#                         final_matches.append((category, subcat, 'name', None))
#                         detected_pairs.add((category, subcat))
#                     continue
#                 # Retour immédiat pour les autres (Exclusion Mutuelle)
#                 return {'primary_matches': [(category, subcat, 'name', None)], 'pii_keys_matches': list(pii_keys_matches)}

#             # B. Match sur le CONTENU (Recherche dans la valeur brute ou décodée)
#             if category in ['DIRECT_PII', 'SUSPICIOUS_VALUES']:
#                 for val in vals_to_check:
#                     all_matches = collect_all_pii_matches(patterns[category], str(val))
#                     for s_m, t_m, start_m, end_m in all_matches:
                        
#                         # --- FILTRES DE SÉCURITÉ CONTEXTUELS ---
#                         if s_m == "ip_address":
#                             if not is_valid_ip(t_m): continue
#                             if any(x in context_info for x in ['version', 'sdk', 'browser', 'agent', 'ua']): continue
#                             if "Mozilla" in str(val): continue
#                             if t_m.startswith("140."): continue
                        
#                         # --- VALIDATIONS TECHNIQUES ---
#                         if s_m == "jwt_token" and not is_valid_jwt(t_m): continue
#                         if s_m == "uuid_format" and not is_valid_uuid(t_m): continue
                        
#                         # --- FILTRE EMAIL/NAME ---
#                         if s_m in ['first_name', 'last_name'] and "@" in str(val): continue
                        
#                         if (category, s_m) not in detected_pairs:
#                             dec_val = val if val != val_str else None
#                             final_matches.append((category, s_m, 'value', dec_val))
#                             detected_pairs.add((category, s_m))
#                 continue 

#     if final_matches:
#         return {
#             'primary_matches': deduplicate_pii_matches_idb(final_matches), 
#             'pii_keys_matches': list(pii_keys_matches)
#         }
    
#     return {'primary_matches': None, 'pii_keys_matches': list(pii_keys_matches)}


# # =====================================================================
# # GESTION DES FICHIERS ET SAUVEGARDE
# # =====================================================================

# def categorize_indexeddb_for_config(input_dir, output_dir, patterns):
#     json_files = list(input_dir.glob("*.json"))
#     if not json_files: return
#     output_dir.mkdir(parents=True, exist_ok=True)
#     categorized = defaultdict(list)

#     for json_file in json_files:
#         with open(json_file, 'r', encoding='utf-8') as f:
#             try:
#                 data = json.load(f)
#                 all_fields = extract_all_fields_recursive(data.get("data", data))
                
#                 for path, field_value in all_fields:
#                     res = categorize_idb_field(path, field_value, patterns)
                    
#                     if res['primary_matches']:
#                         for cat, sub, mt, dec in res['primary_matches']:
#                             item_out = {
#                                 'field_path': path, 'name': path.split('.')[-1], 'value': field_value,
#                                 'matched_subcategory': sub, 'match_type': mt, 'was_decoded': dec is not None,
#                                 'decoded_value': dec, 'source_file': json_file.name
#                             }
#                             categorized[cat].append(item_out)
#                     else:
#                         # Item non-PII et non-Tracking -> UNCATEGORIZED
#                         item_out = {'field_path': path, 'value': field_value, 'source_file': json_file.name}
#                         # --- PRÉPARATION POUR LE LLM ---
#                         decoded_list = try_decode_value(str(field_value))
#                         extra_info = [v for v in decoded_list if v != str(field_value)]
#                         if extra_info:
#                             item_out['try_decoded_value'] = extra_info[0]
#                         categorized['UNCATEGORIZED'].append(item_out)

#                     for cat, sub, mt, dec in res['pii_keys_matches']:
#                         item_key_out = {
#                             'field_path': path, 'name': path.split('.')[-1], 'value': field_value,
#                             'matched_subcategory': sub, 'match_type': mt, 'source_file': json_file.name
#                         }
#                         categorized['DIRECT_PII_KEYS'].append(item_key_out)
#             except: continue

#     for category, items in categorized.items():
#         if items:
#             with open(output_dir / f"{category}.json", 'w', encoding='utf-8') as f:
#                 json.dump(items, f, indent=2, ensure_ascii=False)

# # =====================================================================
# # MAIN
# # =====================================================================

# def main():
#     base_dir = Path(__file__).resolve().parent.parent / 'data'
#     users = ('FR_0417', 'FR_0446', 'FR_0458')
    
#     for auth in ('Auth', 'UnAuth'):
#         for user in users:
#             patterns = get_patterns_for_user(user)
#             for pol in ('ALL', 'PARTIAL', 'NONE'):
#                 input_p = base_dir / 'preprocessing' / auth / user / pol / 'indexeddb'
#                 output_p = base_dir / 'user' / auth / user / pol / 'indexeddb'
#                 if input_p.exists():
#                     print(f"Catégorisation {user} | {auth} | {pol}")
#                     categorize_indexeddb_for_config(input_p, output_p, patterns)

# if __name__ == '__main__':
#     main()


#!/usr/bin/env python3
"""
INDEXEDDB CATEGORIZATION PIPELINE - ULTIMATE AUDIT VERSION
méthode Scientifique : Déduplication Familles + Audit Intention + 3 Niveaux de Localisation 
+ Validation Technique + Filtrage Structurel (Anti-Explosion).
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

# Validation technique optionnelle
try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

# Import des constantes et fonctions partagées
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

# =====================================================================
# 1. FONCTIONS UTILITAIRES DE SÉCURITÉ ET VALIDATION
# =====================================================================

def is_valid_location_value(subcat, value):
    """Filtre les faux positifs techniques pour la localisation."""
    val = str(value).lower().strip().strip('"')
    noise = {'null', 'undefined', 'none', 'true', 'false', '', 'unknown', 'auto', 
             'default', 'n/a', 'nan', 'object', 'object object', 'undefined_undefined'}
    if val in noise: return False

    # Validation spécifique pour Latitude/Longitude/Coords (DOIT être numérique)
    if any(k in subcat.lower() for k in ['latitude', 'longitude', 'coords', 'precise_coords', 'gps', 'geo_position', 'altitude', 'elevation']):
        try:
            num_val = float(val.replace(',', '.'))
            # Validation des ranges raisonnables pour lat/lon
            if 'latitude' in subcat.lower() or 'lat' in subcat.lower():
                return -90 <= num_val <= 90
            if 'longitude' in subcat.lower() or 'lon' in subcat.lower() or 'lng' in subcat.lower():
                return -180 <= num_val <= 180
            # Pour les autres coords (altitude, etc.), accepter tout nombre valide
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
    Valide qu'une IP détectée est bien une vraie IP et pas un faux positif.
    """
    # 1. Validation technique de base
    if not is_valid_ip(ip_match):
        return False
    
    # 2. Blacklist d'IPs suspectes (versions, placeholders)
    suspicious_ips = {
        '140.0.0.0',  # Version Chrome/Browser
        '0.0.0.0',    # Placeholder
        '255.255.255.255',  # Broadcast
        '127.0.0.1',  # Localhost
    }
    if ip_match in suspicious_ips:
        return False
    

    # 4. Vérification réseau (private, loopback, reserved)
    try:
        ip_obj = ipaddress.ip_address(ip_match)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return False
    except:
        return False
    
    # 5. IP dans URL (version SDK, CDN)
    if re.search(r'https?://[^\s]+', str(value)):
        if re.search(re.escape(ip_match), str(value)):
            return False
    
    # 6. Contexte technique (version, sdk, browser)
    path_lower = field_path.lower()
    val_lower = str(value).lower()
    
    tech_keywords = ['version', 'sdk', 'browser', 'agent', 'ua', 'build', 
                     'release', 'chrome', 'firefox', 'safari', 'edge']
    if any(kw in path_lower or kw in val_lower for kw in tech_keywords):
        return False
    
    # 7. Champs URL/manifest/endpoint
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

# =====================================================================
# 2. EXTRACTION RÉCURSIVE ET AUDIT D'INTENTION
# =====================================================================

def extract_all_fields_recursive(data, parent_key='', separator='.'):
    """
    Extrait les champs d'une structure IndexedDB en ignorant les métadonnées techniques.
    Pour les ObjectStoreDataValue, on extrait uniquement le contenu de 'value'.
    """
    fields = []
    
    if isinstance(data, dict):
        # Si c'est un ObjectStoreDataValue, on extrait uniquement le contenu de 'value'
        if data.get('__type__') == 'ObjectStoreDataValue' and 'value' in data:
            # On continue l'extraction à partir de 'value' uniquement
            value_content = data['value']
            if isinstance(value_content, (dict, list)):
                fields.extend(extract_all_fields_recursive(value_content, parent_key, separator))
            else:
                # Si value est une valeur simple, on la retourne avec le parent_key
                if parent_key:
                    fields.append((parent_key, value_content))
        # Si c'est un IDBKeyPath ou autre type technique, on l'ignore complètement
        elif data.get('__type__') in ['IDBKeyPath', 'IDBKey']:
            # Ignorer ces types techniques
            pass
        else:
            # Pour les autres dictionnaires, extraction normale
            for key, value in data.items():
                # Ignorer les clés de métadonnées techniques
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

# =====================================================================
# 3. MOTEUR DE DÉDUPLICATION (RIGUEUR RGPD)
# =====================================================================

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

# =====================================================================
# 4. FONCTION DE CATÉGORISATION PRINCIPALE
# =====================================================================

def categorize_idb_field(field_path, value, patterns):
    val_str = str(value)
    # Extraction du nom de la clé finale pour le matching
    field_name = field_path.split('.')[-1]
    path_lower = field_path.lower()
    context_info = (field_path + field_name).lower()
    
    # --- ÉTAPE 0 : ANTI-EXPLOSION (Filtre Structurel) ---
    structural_suffixes = ('.key', '.value.key', '.name', '.propertyname', '._id', '.compositekey')
    if any(path_lower.endswith(s) for s in structural_suffixes):
        if len(val_str) < 60 and "@" not in val_str:
            return {'primary_matches': [('INTERNAL_IDB_KEYS', 'structural_metadata', 'name', None)], 'pii_keys_matches': []}

    pii_keys_matches = set()
    
    # --- ÉTAPE 1 : DIRECT_PII_KEYS (Intention / Structure) ---
    if 'DIRECT_PII_KEYS' in patterns:
        tech_names = [field_name]  # On utilise uniquement le field_name
        try:
            parsed = json.loads(val_str)
            if isinstance(parsed, (dict, list)): tech_names.extend(extract_json_keys_recursive(parsed))
        except: pass
        for subcat, pattern in patterns['DIRECT_PII_KEYS'].items():
            for t_name in tech_names:
                if re.search(pattern, str(t_name), re.IGNORECASE):
                    pii_keys_matches.add(('DIRECT_PII_KEYS', subcat, 'name', None))
                    break

    # --- ÉTAPE 2 : HIÉRARCHIE DE DÉCISION ET PRIORITÉS ---
    priority_order = ['DIRECT_PII', 'SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS', 
                      'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES', 'SUSPICIOUS_VALUES', 'CONSENT_AND_PRIVACY']
    
    # Ajout dynamique des autres catégories de regex.py
    for cat in patterns.keys():
        if cat not in priority_order and cat != 'DIRECT_PII_KEYS': 
            priority_order.append(cat)

    detected_pairs = set() 
    final_matches = []
    vals_to_check = try_decode_value(val_str)

    for category in priority_order:
        if category not in patterns: continue
        
        for subcat, pattern in patterns[category].items():

            # A. Match sur l'IDENTITÉ (Nom du champ uniquement, pas le path complet)
            if re.search(pattern, field_name, re.IGNORECASE):
                # Contrôles de validité spécifiques
                if category in ['SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS']:
                    if not is_valid_location_value(subcat, val_str): continue
                
                if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
                    if shannon_entropy(val_str) < 3.0: continue
                
                # Pour PII et SUSPICIOUS, on continue pour checker la valeur aussi
                if category in ['DIRECT_PII', 'SUSPICIOUS_VALUES']:
                    if (category, subcat) not in detected_pairs:
                        final_matches.append((category, subcat, 'name', None))
                        detected_pairs.add((category, subcat))
                    continue
                
                # Pour les autres, retour immédiat (Exclusion Mutuelle)
                return {'primary_matches': [(category, subcat, 'name', None)], 'pii_keys_matches': list(pii_keys_matches)}
            
            # A.2. CAS SPÉCIAL : Si field_name est "value", on vérifie aussi dans la valeur
            # pour les catégories "keys based" (toutes sauf DIRECT_PII, SUSPICIOUS_VALUES, DIRECT_PII_KEYS)
            if field_name == "value" and category not in ['DIRECT_PII', 'SUSPICIOUS_VALUES', 'DIRECT_PII_KEYS']:
                if re.search(pattern, val_str, re.IGNORECASE):
                    # Contrôles de validité spécifiques
                    if category in ['SENSITIVE_LOCATION_PII', 'LOCATION_AND_DEMOGRAPHICS']:
                        if not is_valid_location_value(subcat, val_str): continue
                    
                    if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
                        if shannon_entropy(val_str) < 3.0: continue
                    
                    # Retour immédiat (Exclusion Mutuelle)
                    return {'primary_matches': [(category, subcat, 'value', None)], 'pii_keys_matches': list(pii_keys_matches)}

            # B. Match sur le CONTENU (Recherche dans la valeur brute ou décodée)
            if category in ['DIRECT_PII', 'SUSPICIOUS_VALUES']:
                for val in vals_to_check:
                    all_matches = collect_all_pii_matches(patterns[category], str(val))
                    for s_m, t_m, _, _ in all_matches:
                        # Validations techniques
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
                
                # Si on trouve une fuite PII directe dans le contenu, on la traite en priorité
                if final_matches and category == 'DIRECT_PII':
                    return {'primary_matches': deduplicate_pii_matches_idb(final_matches), 'pii_keys_matches': list(pii_keys_matches)}

    if final_matches:
        return {'primary_matches': deduplicate_pii_matches_idb(final_matches), 'pii_keys_matches': list(pii_keys_matches)}
    
    return {'primary_matches': None, 'pii_keys_matches': list(pii_keys_matches)}

# =====================================================================
# 5. GESTION DES FICHIERS ET SAUVEGARDE
# =====================================================================

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
                    print(f"Catégorisation : {user} | {auth} | {pol}")
                    process_indexeddb_for_config(input_p, output_p, patterns)

if __name__ == '__main__':
    main()