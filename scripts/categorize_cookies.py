#!/usr/bin/env python3
"""
Script final de catégorisation des cookies.
Logique : 
- DIRECT_PII_KEYS détecté INDÉPENDAMMENT (noms + valeurs)
- Hiérarchie stricte pour catégorie principale
- Déduplication PII par famille
- Format d'écriture identique pour toutes les catégories
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

# Ajouter le dossier courant au path pour importer regex
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from regex import TRACKING_PATTERNS_COMPLETE
from overlap_detection import collect_all_pii_matches

USER_ID_TO_INDEX = {'FR_0417': 0, 'FR_0446': 1, 'FR_0458': 2}

# =====================================================================
# FAMILLES DE PATTERNS PII (pour déduplication)
# =====================================================================

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

# Ordre de priorité au sein de chaque famille (plus spécifique = prioritaire)
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

# =====================================================================
# FONCTIONS UTILITAIRES
# =====================================================================

def shannon_entropy(s: str) -> float:
    """Calcule l'entropie de Shannon d'une chaîne"""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())


def try_decode_value(value):
    """Tente de décoder une valeur (URL, Base64, JSON)"""
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
    """Retourne les patterns avec le bon DIRECT_PII pour l'utilisateur"""
    patterns = dict(TRACKING_PATTERNS_COMPLETE)
    user_index = USER_ID_TO_INDEX.get(user_id, 0)
    if isinstance(TRACKING_PATTERNS_COMPLETE['DIRECT_PII'], list):
        patterns['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII'][user_index]
    return patterns


def calculate_modified_metrics(cookie):
    """Calcule les changements pour les cookies modifiés"""
    fields = ['value', 'expires', 'httpOnly', 'secure', 'sameSite']
    changed = [f for f in fields if cookie.get(f'{f}_from') != cookie.get(f'{f}_to')]
    return {
        'changed_fields': ','.join(changed) if changed else 'none',
        'num_changes': len(changed)
    }


import ipaddress

def is_valid_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        # On ignore l'adresse nulle (0.0.0.0) et les adresses de bouclage (127.0.0.1)
        if ip.is_unspecified or ip.is_loopback or ip == ipaddress.ip_address("14.0.0.0") or ip == ipaddress.ip_address("1.1.41.2") :
            return False
        return True
    except ValueError:
        return False


def extract_json_keys_recursive(obj, parent_key=''):
    """
    Extrait récursivement toutes les clés d'un objet JSON.
    
    Args:
        obj: Objet JSON (dict ou list)
        parent_key: Préfixe pour les clés imbriquées
    
    Returns:
        Liste de toutes les clés (avec notation pointée pour les clés imbriquées)
    
    Exemples:
        {"email": "test@test.com"} -> ["email"]
        {"user": {"email": "test"}} -> ["user", "user.email"]
        {"items": [{"name": "foo"}]} -> ["items", "items[0].name"]
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


# =====================================================================
# DÉDUPLICATION DES PII
# =====================================================================

def deduplicate_pii_matches(matches):
    """
    Déduplique les matches PII par famille.
    
    Règles :
    - 1 seul match par famille (email, phone, birth_date, etc.)
    - Priorité au pattern le plus spécifique (email_exact > email_pattern)
    - Ignore les name patterns si trouvés dans un email
    
    Returns:
        Liste de matches dédupliqués
    """
    
    # Inverser : subcategory -> family
    subcat_to_family = {}
    for family, subcats in PII_PATTERN_FAMILIES.items():
        for subcat in subcats:
            subcat_to_family[subcat] = family
    
    # Grouper les matches par famille
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
            # Patterns sans famille (gender, religion, etc.)
            standalone_matches.append(match)
    
    # Sélectionner le meilleur match par famille
    deduplicated = []
    
    for family, matches_in_family in family_matches.items():
        
        # # RÈGLE SPÉCIALE : Ignorer name patterns si un email a été détecté
        # if family == 'name':
        #     has_email = 'email' in family_matches
        #     if has_email:
        #         # Ne pas compter les names (ils sont dans l'email)
        #         continue
        
        # Trier par priorité
        priority = PII_PRIORITY_ORDER.get(family, [])
        
        def match_priority(m):
            subcat = m['subcategory']
            try:
                return priority.index(subcat)
            except ValueError:
                return 999  # Non trouvé = basse priorité
        
        matches_in_family.sort(key=match_priority)
        
        # Prendre le meilleur (index 0)
        best_match = matches_in_family[0]
        deduplicated.append(best_match)
    
    # Ajouter les standalone
    deduplicated.extend(standalone_matches)
    
    return deduplicated

# =====================================================================
# CATÉGORISATION
# =====================================================================

def categorize_cookie(cookie, patterns):
    """
    Catégorise un cookie selon les patterns définis.
    
    LOGIQUE OPTION 2 :
    1. Détection DIRECT_PII_KEYS indépendante (nom + valeur)
    2. Hiérarchie stricte pour catégorie principale
    3. Déduplication pour DIRECT_PII
    
    Returns:
        {
            'primary_matches': [...],      # Catégorie principale
            'pii_keys_matches': [...]      # Intentions PII (DIRECT_PII_KEYS)
        }
    """
    name = cookie.get('name', '')
    value = str(cookie.get('value', ''))

    # =====================================================================
    # ÉTAPE 1 : DÉTECTION DIRECT_PII_KEYS (INDÉPENDANTE)
    # Test sur NOM + CLÉS JSON UNIQUEMENT (pas les valeurs)
    # =====================================================================
    pii_keys_matches = []
    
    if 'DIRECT_PII_KEYS' in patterns:
        for subcat, pattern in patterns['DIRECT_PII_KEYS'].items():
            try:
                # Test sur le NOM du cookie
                if re.search(pattern, name, re.IGNORECASE):
                    pii_keys_matches.append({
                        'category': 'DIRECT_PII_KEYS',
                        'subcategory': subcat,
                        'match_type': 'name',
                        'was_decoded': False,
                        'pattern': pattern,
                        'decoded_value': None
                    })
                    continue  # Passer au pattern suivant
                
                # Test sur les CLÉS JSON uniquement (pas les valeurs)
                vals_to_check = try_decode_value(value)
                for val in vals_to_check:
                    try:
                        parsed_json = json.loads(val)
                        if isinstance(parsed_json, dict):
                            # Extraire toutes les clés du JSON (récursif)
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
                                    break  # Un seul match par pattern
                            if pii_keys_matches and pii_keys_matches[-1]['subcategory'] == subcat:
                                break  # Déjà trouvé pour ce pattern, passer au suivant
                    except (json.JSONDecodeError, TypeError):
                        # Pas un JSON valide, continuer avec la prochaine valeur
                        continue
                        
            except re.error:
                pass

    # =====================================================================
    # ÉTAPE 2 : HIÉRARCHIE DE PRIORITÉ (CATÉGORIE PRINCIPALE)
    # Sans DIRECT_PII_KEYS qui est déjà traité
    # =====================================================================
    
    # Ordre de priorité
    priority_order = [
        'DIRECT_PII',
        'IDENTITY_TRACKING',
        'ID_SOLUTIONS_AND_EXCHANGES',
        'CONSENT_AND_PRIVACY'
    ]
    
    # Ajouter les autres catégories (sauf DIRECT_PII_KEYS)
    for cat in patterns.keys():
        if cat not in priority_order and cat != 'DIRECT_PII_KEYS':
            priority_order.append(cat)

    # Valeurs décodées UNIQUEMENT pour la PII
    vals_to_check = try_decode_value(value)

    # Collecteur pour DIRECT_PII
    pii_matches = []

    for category in priority_order:
        if category not in patterns:
            continue

        for subcat, pattern in patterns[category].items():

            try:
                # --- A. MATCH SUR LE NOM (clé) ---
                if re.search(pattern, name, re.IGNORECASE):

                    # Cas spécial : IDENTITY_TRACKING::generic_ids
                    if category == "IDENTITY_TRACKING" and subcat == "generic_ids":
                        entropy = shannon_entropy(value)
                        if entropy < 3.0:
                            continue  # Signal insuffisant

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

                    # SI DIRECT_PII : stocker le match mais continuer
                    if category == 'DIRECT_PII':
                        pii_matches.append({
                            'category': category,
                            'subcategory': subcat,
                            'match_type': 'name',
                            'was_decoded': False,
                            'pattern': pattern,
                            'decoded_value': None
                        })
                        continue  # Ne pas retourner immédiatement

                    # Tous les autres cas (clé seule suffisante)
                    return {
                        'primary_matches': [{
                            'category': category,
                            'subcategory': subcat,
                            'match_type': 'name',
                            'was_decoded': False,
                            'pattern': pattern,
                            'decoded_value': None
                        }],
                        'pii_keys_matches': pii_keys_matches
                    }

                # --- B. MATCH SUR LA VALEUR (PII UNIQUEMENT) ---
                if category == 'DIRECT_PII':
                    # Collect all DIRECT_PII matches from all values with overlap detection
                    for val in vals_to_check:
                        if not val:
                            continue
                        
                        # Use collect_all_pii_matches to find all occurrences with overlap removal
                        all_pii_in_val = collect_all_pii_matches(patterns[category], str(val))
                        
                        for subcat, match_text, start_pos, end_pos in all_pii_in_val:
                            # RÈGLE SPÉCIALE : Ignorer name patterns si dans un email
                            if subcat in ['first_name', 'last_name', 'full_name', 'name_encoded']:
                                # Vérifier si la valeur contient un email
                                if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', val):
                                    # Name trouvé dans un email → ne pas compter
                                    continue
                            
                            if subcat == "ip_address":
                                if not is_valid_ip(match_text):
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
                             
            except re.error:
                pass

    # =====================================================================
    # ÉTAPE 3 : RETOUR DES RÉSULTATS
    # =====================================================================
    
    # Si DIRECT_PII détecté, déduplication
    if pii_matches:
        deduplicated_pii = deduplicate_pii_matches(pii_matches)
        return {
            'primary_matches': deduplicated_pii,
            'pii_keys_matches': pii_keys_matches
        }
    
    # Sinon, pas de catégorie principale
    return {
        'primary_matches': None,
        'pii_keys_matches': pii_keys_matches
    }

# =====================================================================
# MAIN
# =====================================================================

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
                    
                    print(f"Analyse {user} | {auth} | {pol} | {lifecycle}")
                    
                    with open(f_path, 'r', encoding='utf-8') as f:
                        cookies = json.load(f)
                    
                    out_dir = output_base / lifecycle
                    out_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Rangement par catégorie (SANS DIRECT_PII_KEYS dans la liste initiale)
                    categorized = {cat: [] for cat in list(user_patterns.keys()) if cat != 'DIRECT_PII_KEYS'}
                    categorized['UNCATEGORIZED'] = []
                    categorized['DIRECT_PII_KEYS'] = []  # Ajouté séparément
                    
                    for cookie in cookies:
                        result = categorize_cookie(cookie, user_patterns)
                        
                        if lifecycle == 'modified':
                            cookie_metrics = calculate_modified_metrics(cookie)
                        
                        # ========================================
                        # TRAITER LA CATÉGORIE PRINCIPALE
                        # ========================================
                        primary_matches = result.get('primary_matches')
                        pii_keys_matches = result.get('pii_keys_matches', [])
                        
                        if primary_matches:
                            # Catégorie principale trouvée
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
                            # Pas de catégorie principale → UNCATEGORIZED
                            cookie_out = cookie.copy()
                            cookie_out['source_file'] = f_name
                            
                            if lifecycle == 'modified':
                                cookie_out.update(cookie_metrics)
                            
                            categorized['UNCATEGORIZED'].append(cookie_out)
                        
                        # ========================================
                        # TRAITER DIRECT_PII_KEYS (SÉPARÉMENT)
                        # ========================================
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
                    
                    # Écriture des fichiers (FORMAT IDENTIQUE pour toutes les catégories)
                    for cat, rows in categorized.items():
                        if rows:
                            with open(out_dir / f"{cat}.json", 'w', encoding='utf-8') as f:
                                json.dump(rows, f, indent=2, ensure_ascii=False)
                    
                    # Stats de duplication PII
                    if categorized['DIRECT_PII']:
                        unique_cookies = len(set(c['name'] for c in categorized['DIRECT_PII']))
                        total_entries = len(categorized['DIRECT_PII'])
                        avg_pii = total_entries / unique_cookies if unique_cookies > 0 else 0
                        print(f"  → DIRECT_PII: {unique_cookies} cookies uniques, {total_entries} entrées (avg {avg_pii:.1f} PII/cookie)")
                    
                    # Stats pour DIRECT_PII_KEYS
                    if categorized['DIRECT_PII_KEYS']:
                        unique_cookies_keys = len(set(c['name'] for c in categorized['DIRECT_PII_KEYS']))
                        total_entries_keys = len(categorized['DIRECT_PII_KEYS'])
                        avg_keys = total_entries_keys / unique_cookies_keys if unique_cookies_keys > 0 else 0
                        print(f"  → DIRECT_PII_KEYS: {unique_cookies_keys} cookies uniques, {total_entries_keys} intentions (avg {avg_keys:.1f} clés PII/cookie)")

if __name__ == '__main__':
    main()