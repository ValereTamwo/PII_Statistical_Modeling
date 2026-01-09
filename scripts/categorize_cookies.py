#!/usr/bin/env python3
"""
Script pour classer les cookies en fonction des patterns définis dans regex.py.
Génère des fichiers JSON séparés pour added/modified et par catégorie.
Inclut le décodage automatique des valeurs pour détecter les PII encodées.
"""

import re
import os
import sys
import base64
import json
import urllib.parse
from pathlib import Path

# Ajouter le dossier courant au path pour importer regex
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from regex import TRACKING_PATTERNS_COMPLETE

# Mapping user_id vers index dans DIRECT_PII
USER_ID_TO_INDEX = {
    'FR_0417': 0,
    'FR_0446': 1,
    'FR_0458': 2
}


# def try_decode_value(value):
#     """
#     Tente de décoder une valeur avec différents encodages courants.
#     Retourne une liste de valeurs décodées (original + décodages réussis).
#     """
#     if not value or not isinstance(value, str):
#         return [value]
    
#     decoded_values = [value]  # Toujours inclure la valeur originale
    
#     # 1. URL Decoding (peut être appliqué plusieurs fois)
#     try:
#         url_decoded = urllib.parse.unquote(value)
#         if url_decoded != value:
#             decoded_values.append(url_decoded)
#             # Double décodage si nécessaire
#             url_decoded2 = urllib.parse.unquote(url_decoded)
#             if url_decoded2 != url_decoded:
#                 decoded_values.append(url_decoded2)
#     except:
#         pass
    
#     # 2. Base64 Decoding
#     try:
#         # Vérifier si ça ressemble à du Base64
#         if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) % 4 == 0:
#             b64_decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
#             if b64_decoded and b64_decoded.isprintable():
#                 decoded_values.append(b64_decoded)
#     except:
#         pass
    
#     # 3. JSON Parsing (pour les cookies qui contiennent du JSON)
#     try:
#         json_decoded = json.loads(value)
#         if isinstance(json_decoded, dict):
#             # Extraire toutes les valeurs du JSON
#             json_str = json.dumps(json_decoded, ensure_ascii=False)
#             decoded_values.append(json_str)
#     except:
#         pass
    
#     # 4. Hex Decoding (pour les valeurs hexadécimales)
#     try:
#         if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0:
#             hex_decoded = bytes.fromhex(value).decode('utf-8', errors='ignore')
#             if hex_decoded and hex_decoded.isprintable():
#                 decoded_values.append(hex_decoded)
#     except:
#         pass
    
#     return list(set(decoded_values))  # Dédupliquer


# def load_cookies(filepath):
#     """Charge les cookies depuis un fichier JSON"""
#     try:
#         with open(filepath, 'r', encoding='utf-8') as f:
#             return json.load(f)
#     except Exception as e:
#         print(f"Erreur lors de la lecture de {filepath}: {e}")
#         return []


# def decode_jwt(value):
#     """
#     Décode un JWT token (sans vérification de signature).
#     Retourne le payload décodé sous forme de JSON string.
#     """
#     try:
#         parts = value.split('.')
#         if len(parts) != 3:
#             return None
        
#         # Décoder payload (partie 2)
#         # Ajouter padding si nécessaire
#         payload_b64 = parts[1]
#         padding = 4 - (len(payload_b64) % 4)
#         if padding != 4:
#             payload_b64 += '=' * padding
        
#         payload_bytes = base64.urlsafe_b64decode(payload_b64)
#         payload = json.loads(payload_bytes.decode('utf-8'))
        
#         return json.dumps(payload, ensure_ascii=False)
#     except Exception:
#         return None


# def decode_base64_json(value):
#     """
#     Décode une valeur base64 qui contient du JSON.
#     Retourne le JSON décodé sous forme de string.
#     """
#     try:
#         # Décoder base64
#         decoded_bytes = base64.b64decode(value)
#         decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        
#         # Vérifier si c'est du JSON valide
#         json_data = json.loads(decoded_str)
#         return json.dumps(json_data, ensure_ascii=False)
#     except Exception:
#         return None


# def decode_url_list(value):
#     """
#     Décode une liste d'URLs (URL-encoded).
#     Retourne une string avec les URLs séparées par des espaces.
#     """
#     try:
#         # URL decode
#         decoded = urllib.parse.unquote(value)
        
#         # Extraire toutes les URLs
#         urls = re.findall(r'https?://[^\s,\|"\']+', decoded)
        
#         if urls:
#             return ' '.join(urls)
#         return decoded
#     except Exception:
#         return None


# def recursive_decode_and_reclassify(cookie, matches, patterns, source_type):
#     """
#     Décode récursivement les cookies SUSPICIOUS_VALUES et les re-classifie.
    
#     Args:
#         cookie: Le cookie original
#         matches: Les matches initiaux
#         patterns: Les patterns de classification
#         source_type: 'added' ou 'modified'
    
#     Returns:
#         Liste de matches mise à jour (SUSPICIOUS_VALUES remplacés par vraies catégories)
#     """
#     # Filtrer les matches SUSPICIOUS_VALUES
#     suspicious_matches = [m for m in matches if m['category'] == 'SUSPICIOUS_VALUES']
#     other_matches = [m for m in matches if m['category'] != 'SUSPICIOUS_VALUES']
    
#     if not suspicious_matches:
#         return matches
    
#     # Pour chaque match suspect, essayer de décoder et re-classifier
#     for match in suspicious_matches:
#         subcat = match['subcategory']
#         decoded_value = None
        
#         # Décoder selon le type
#         if subcat == 'jwt_token':
#             decoded_value = decode_jwt(cookie['value'])
#         elif subcat == 'base64_json':
#             decoded_value = decode_base64_json(cookie['value'])
#         elif subcat == 'url_list':
#             decoded_value = decode_url_list(cookie['value'])
        
#         # Si décodage réussi, re-classifier
#         if decoded_value:
#             # Règle spéciale : url_list → NAVIGATION_HISTORY
#             if subcat == 'url_list':
#                 # Forcer la catégorisation dans NAVIGATION_HISTORY
#                 other_matches.append({
#                     'category': 'NAVIGATION_HISTORY',
#                     'subcategory': 'url_list',
#                     'match_type': 'value',
#                     'pattern': 'url_list (decoded)',
#                     'matched_content': decoded_value[:200] + '...' if len(decoded_value) > 200 else decoded_value,
#                     'decoded': True,
#                     'decoded_value': decoded_value,
#                     'decoded_from': f'SUSPICIOUS_VALUES::{subcat}'
#                 })
#             else:
#                 # Re-classifier UNIQUEMENT sur la valeur décodée (ignorer le nom)
#                 # On cherche les patterns dans la valeur décodée
#                 new_matches = []
                
#                 for category, subcategories in patterns.items():
#                     # Skip SUSPICIOUS_VALUES pour éviter boucle infinie
#                     if category == 'SUSPICIOUS_VALUES':
#                         continue
                        
#                     for subcategory, pattern in subcategories.items():
#                         try:
#                             # Chercher UNIQUEMENT dans la valeur décodée
#                             if re.search(pattern, decoded_value, re.IGNORECASE):
#                                 new_matches.append({
#                                     'category': category,
#                                     'subcategory': subcategory,
#                                     'match_type': 'value',
#                                     'pattern': pattern,
#                                     'matched_content': decoded_value[:200] + '...' if len(decoded_value) > 200 else decoded_value,
#                                     'decoded': True,
#                                     'decoded_value': decoded_value,
#                                     'decoded_from': f'SUSPICIOUS_VALUES::{subcat}'
#                                 })
#                                 break  # Une seule correspondance par pattern
#                         except re.error:
#                             pass
                
#                 # Si on a trouvé de nouvelles catégories, les utiliser
#                 if new_matches:
#                     other_matches.extend(new_matches)
#                 else:
#                     # Sinon, garder le match SUSPICIOUS original
#                     other_matches.append(match)
#         else:
#             # Décodage échoué, garder le match SUSPICIOUS original
#             other_matches.append(match)
    
#     return other_matches


# def get_patterns_for_user(user_id):
#     """Retourne les patterns avec le bon DIRECT_PII pour l'utilisateur"""
#     patterns = dict(TRACKING_PATTERNS_COMPLETE)
#     user_index = USER_ID_TO_INDEX.get(user_id, 0)
#     if isinstance(TRACKING_PATTERNS_COMPLETE['DIRECT_PII'], list):
#         patterns['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII'][user_index]
#     return patterns


# def categorize_cookie(cookie, patterns, source_type='added'):
#     """Catégorise un cookie selon les patterns définis"""
#     matches = []
#     name = cookie.get('name', '')
#     value = cookie.get('value', '')
    
#     # Pour les cookies modifiés, on vérifie aussi les anciennes valeurs
#     if source_type == 'modified':
#         value_from = cookie.get('value_from', '')
#         value_to = cookie.get('value_to', '')
#         values_to_check = [value, value_from, value_to]
#     else:
#         values_to_check = [value]
    
#     # Créer une liste avec valeur originale + valeurs décodées
#     all_values_with_original = []
#     for val in values_to_check:
#         if val:
#             # Ajouter la valeur originale en premier
#             all_values_with_original.append({'value': val, 'is_decoded': False, 'original': val})
#             # Ajouter les valeurs décodées
#             decoded_vals = try_decode_value(val)
#             for decoded_val in decoded_vals:
#                 all_values_with_original.append({
#                     'value': decoded_val,
#                     'is_decoded': True,
#                     'original': val
#                 })
    
#     # Dédupliquer par valeur
#     seen_values = set()
#     unique_values = []
#     for item in all_values_with_original:
#         if item['value'] not in seen_values:
#             seen_values.add(item['value'])
#             unique_values.append(item)
    
#     for category, subcategories in patterns.items():
#         for subcategory, pattern in subcategories.items():
#             try:
#                 # Vérification du NOM du cookie
#                 if re.search(pattern, name, re.IGNORECASE):
#                     matches.append({
#                         'category': category,
#                         'subcategory': subcategory,
#                         'match_type': 'name',
#                         'pattern': pattern,
#                         'matched_content': name,
#                         'decoded': False,
#                         'decoded_value': None
#                     })
#                     continue
                
#                 # Vérification des VALEURS (originale + décodées)
#                 for item in unique_values:
#                     val = item['value']
#                     if val and re.search(pattern, val, re.IGNORECASE):
#                         match_data = {
#                             'category': category,
#                             'subcategory': subcategory,
#                             'match_type': 'value',
#                             'pattern': pattern,
#                             'matched_content': val[:200] + '...' if len(val) > 200 else val,
#                             'decoded': item['is_decoded']
#                         }
#                         # Ajouter la valeur décodée si différente de l'originale
#                         if item['is_decoded']:
#                             match_data['decoded_value'] = val
#                         else:
#                             match_data['decoded_value'] = None
                        
#                         matches.append(match_data)
#                         break  # Une seule correspondance par pattern suffit
                        
#             except re.error as e:
#                 print(f"Erreur regex pour {category}/{subcategory}: {e}")
    
#     return matches


# def calculate_modified_metrics(cookie):
#     """Calcule des métriques pour les cookies modifiés"""
#     metrics = {}
    
#     # Vérifier quels champs ont changé en comparant _from et _to
#     changed_fields = []
    
#     # Value
#     if cookie.get('value_from') != cookie.get('value_to'):
#         changed_fields.append('value')
    
#     # Expires
#     if cookie.get('expires_from') != cookie.get('expires_to'):
#         changed_fields.append('expires')
    
#     # HttpOnly
#     if cookie.get('httpOnly_from') != cookie.get('httpOnly_to'):
#         changed_fields.append('httpOnly')
    
#     # Secure
#     if cookie.get('secure_from') != cookie.get('secure_to'):
#         changed_fields.append('secure')
    
#     # SameSite
#     if cookie.get('sameSite_from') != cookie.get('sameSite_to'):
#         changed_fields.append('sameSite')
    
#     metrics['changed_fields'] = ','.join(changed_fields) if changed_fields else 'none'
#     metrics['num_changes'] = len(changed_fields)
    
#     # Calculer la différence de durée d'expiration
#     try:
#         expires_from = float(cookie.get('expires_from', 0))
#         expires_to = float(cookie.get('expires_to', 0))
#         if expires_from > 0 and expires_to > 0:
#             duration_change = expires_to - expires_from
#             metrics['duration_change_days'] = round(duration_change / 86400, 2)  # Convertir en jours
#         else:
#             metrics['duration_change_days'] = 'N/A'
#     except:
#         metrics['duration_change_days'] = 'N/A'
    
#     return metrics


# def main():
    
#     base_dir = Path(__file__).resolve().parent.parent / 'data'
#     if not base_dir.exists():
#         print(f"Dossier {base_dir} non trouvé")
#         return
#     users  = ('FR_0417', 'FR_0446', 'FR_0458')
#     auth_statuses = ('Auth', 'UnAuth')
    
#     policies = ('ALL', 'PARTIAL', 'NONE')

#     for user in users:
#         # Obtenir les patterns spécifiques à cet utilisateur
#         user_patterns = get_patterns_for_user(user)
        
#         for auth_status in auth_statuses:
#             for policy in policies:
#                 input_dir = base_dir / 'preprocessing' / auth_status / user / policy / 'cookies'
#                 if not input_dir.exists():
#                     print(f"Le dossier {input_dir} n'existe pas, passage à la configuration suivante.")
#                     continue
#                 output_added_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'added'
#                 output_modified_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'modified'
#                 output_removed_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'removed'
                
#                 output_added_dir.mkdir(parents=True, exist_ok=True)
#                 output_modified_dir.mkdir(parents=True, exist_ok=True)
#                 output_removed_dir.mkdir(parents=True, exist_ok=True)

#                 # Fichiers à traiter
#                 files_to_process = [
#                     ('added', input_dir / 'added_cookies.json', output_added_dir),
#                     ('modified', input_dir / 'modified_cookies.json', output_modified_dir),
#                     ('removed', input_dir / 'removed_cookies.json', output_removed_dir)
#                 ]
                
#                 print(f"=== Classification des cookies pour {user} avec décodage ===\n")
                
#                 for source_type, filepath, output_dir in files_to_process:
#                     if not filepath.exists():
#                         print(f"Fichier non trouvé: {filepath}")
#                         continue
                    
#                     print(f"Traitement de {filepath.name} ({source_type})...")
                    
#                     # Dictionnaire pour stocker les résultats par catégorie
#                     categorized_data = {cat: [] for cat in user_patterns.keys()}
#                     categorized_data['UNCATEGORIZED'] = []
                    
#                     cookies = load_cookies(filepath)
#                     total_cookies = len(cookies)
#                     processed_cookies = 0
                    
#                     for cookie in cookies:
#                         matches = categorize_cookie(cookie, user_patterns, source_type)
                        
#                         # Décodage récursif et re-classification des SUSPICIOUS_VALUES
#                         matches = recursive_decode_and_reclassify(cookie, matches, user_patterns, source_type)
                        
#                         # Ajouter les métriques pour les cookies modifiés
#                         if source_type == 'modified':
#                             metrics = calculate_modified_metrics(cookie)
#                             cookie.update(metrics)
                        
#                         if not matches:
#                             cookie_copy = cookie.copy()
#                             cookie_copy['source_file'] = filepath.name
#                             categorized_data['UNCATEGORIZED'].append(cookie_copy)
#                         else:
#                             for match in matches:
#                                 category = match['category']
                                
#                                 cookie_enriched = cookie.copy()
#                                 cookie_enriched['source_file'] = filepath.name
#                                 cookie_enriched['matched_subcategory'] = match['subcategory']
#                                 cookie_enriched['match_type'] = match['match_type']
#                                 cookie_enriched['was_decoded'] = match['decoded']
#                                 cookie_enriched['matched_pattern'] = match['pattern'][:100]  # Tronquer le pattern
                                
#                                 # Ajouter la valeur décodée si disponible
#                                 if match.get('decoded_value'):
#                                     cookie_enriched['decoded_value'] = match['decoded_value']
                                
#                                 # Ajouter l'origine du décodage si disponible
#                                 if match.get('decoded_from'):
#                                     cookie_enriched['decoded_from'] = match['decoded_from']
                                
#                                 categorized_data[category].append(cookie_enriched)
                        
#                         processed_cookies += 1
#                         if processed_cookies % 500 == 0:
#                             print(f"  {processed_cookies}/{total_cookies} cookies traités...")
                    
#                     print(f"  ✓ {processed_cookies} cookies analysés\n")
                    
#                     # Écriture des fichiers de sortie en JSON
#                     print(f"Génération des fichiers JSON pour {source_type}...")
                    
#                     summary = []
                    
#                     for category, rows in categorized_data.items():
#                         if not rows:
#                             continue
                        
#                         filename = f"{category}.json"
#                         filepath_out = output_dir / filename
                        
#                         # Sauvegarder en JSON
#                         with open(filepath_out, 'w', encoding='utf-8') as f:
#                             json.dump(rows, f, ensure_ascii=False, indent=2)
                        
#                         count = len(rows)
#                         # Compter les décodages réussis
#                         decoded_count = sum(1 for r in rows if r.get('was_decoded') == True)
#                         print(f"  ✓ {filename}: {count} cookies ({decoded_count} décodés)")
#                         summary.append((category, count, decoded_count))
                    
#                     # Afficher le résumé
#                     print(f"\n=== Résumé {source_type.upper()} ===")
#                     for cat, count, decoded in sorted(summary, key=lambda x: x[1], reverse=True):
#                         print(f"{cat:<30}: {count:>4} cookies ({decoded} décodés)")
#                     print()

# if __name__ == '__main__':
#     main()


#!/usr/bin/env python3
"""
Script final de catégorisation des cookies.
Logique : Hiérarchie stricte (PII > Tracking > Consent) + Exclusion mutuelle.
"""

import re
import os
import sys
import base64
import json
import urllib.parse
from pathlib import Path

# Ajouter le dossier courant au path pour importer regex
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from regex import TRACKING_PATTERNS_COMPLETE

USER_ID_TO_INDEX = {'FR_0417': 0, 'FR_0446': 1, 'FR_0458': 2}

def try_decode_value(value):
    """Tente de décoder une valeur (URL, Base64, JSON, Hex)."""
    if not value or not isinstance(value, str): return [value]
    decoded_values = [value]
    # URL Decoding
    try:
        u = urllib.parse.unquote(value)
        if u != value: decoded_values.append(u)
    except: pass
    # Base64
    try:
        if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) % 4 == 0:
            b = base64.b64decode(value).decode('utf-8', errors='ignore')
            if b and b.isprintable(): decoded_values.append(b)
    except: pass
    # JSON
    try:
        j = json.loads(value)
        if isinstance(j, dict): decoded_values.append(json.dumps(j, ensure_ascii=False))
    except: pass
    return list(set(decoded_values))


def get_patterns_for_user(user_id):
    """Retourne les patterns avec le bon DIRECT_PII pour l'utilisateur"""
    patterns = dict(TRACKING_PATTERNS_COMPLETE)
    user_index = USER_ID_TO_INDEX.get(user_id, 0)
    if isinstance(TRACKING_PATTERNS_COMPLETE['DIRECT_PII'], list):
        patterns['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII'][user_index]
    return patterns
USER_ID_TO_INDEX = {'FR_0417': 0, 'FR_0446': 1, 'FR_0458': 2}



def categorize_cookie(cookie, patterns):
    name = cookie.get('name', '')
    value = str(cookie.get('value', ''))
    
    # 1. On définit l'ordre de priorité
    priority_order = ['DIRECT_PII', 'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES', 'CONSENT_AND_PRIVACY']
    for cat in patterns.keys():
        if cat not in priority_order: priority_order.append(cat)

    # 2. On prépare les valeurs décodées UNIQUEMENT pour la PII
    vals_to_check = try_decode_value(value)

    for category in priority_order:
        if category not in patterns: continue
        
        for subcat, pattern in patterns[category].items():
            
            # --- STRATÉGIE HYBRIDE ---
            
            # A. On vérifie TOUJOURS le NOM (Key) pour toutes les catégories
            if re.search(pattern, name, re.IGNORECASE):
                return {
                    'category': category, 'subcategory': subcat, 
                    'match_type': 'name', 'was_decoded': False, 'pattern': pattern
                }
            
            # B. On vérifie la VALEUR (Value) UNIQUEMENT pour DIRECT_PII
            if category == 'DIRECT_PII':
                for val in vals_to_check:
                    if val and re.search(pattern, str(val), re.IGNORECASE):
                        return {
                            'category': category, 'subcategory': subcat, 
                            'match_type': 'value', 'was_decoded': val != value, 
                            'decoded_value': val if val != value else None, 'pattern': pattern
                        }
            
            # Pour les autres catégories, on ignore la VALUE.
            
    return None

def calculate_modified_metrics(cookie):
    """Calcule les changements pour les cookies modifiés."""
    fields = ['value', 'expires', 'httpOnly', 'secure', 'sameSite']
    changed = [f for f in fields if cookie.get(f'{f}_from') != cookie.get(f'{f}_to')]
    return {
        'changed_fields': ','.join(changed) if changed else 'none',
        'num_changes': len(changed)
    }

def main():
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    users = ('FR_0417', 'FR_0446', 'FR_0458')
    auth_statuses = ('Auth', 'UnAuth')
    policies = ('ALL', 'PARTIAL', 'NONE')

    for user in users:
        user_patterns = dict(TRACKING_PATTERNS_COMPLETE)
        idx = USER_ID_TO_INDEX.get(user, 0)
        user_patterns['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII'][idx]
        
        for auth in auth_statuses:
            for pol in policies:
                input_path = base_dir / 'preprocessing' / auth / user / pol / 'cookies'
                if not input_path.exists(): continue
                
                output_base = base_dir / 'user' / auth / user / pol / 'cookies'
                
                for lifecycle in ['added', 'modified', 'removed']:
                    f_name = f"{lifecycle}_cookies.json"
                    f_path = input_path / f_name
                    if not f_path.exists(): continue
                    
                    print(f"Analyse {user} | {auth} | {pol} | {lifecycle}")
                    
                    with open(f_path, 'r', encoding='utf-8') as f:
                        cookies = json.load(f)
                    
                    out_dir = output_base / lifecycle
                    out_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Rangement par catégorie
                    categorized = {cat: [] for cat in list(user_patterns.keys()) + ['UNCATEGORIZED']}
                    
                    for cookie in cookies:
                        match = categorize_cookie(cookie, user_patterns)
                        
                        cookie_out = cookie.copy()
                        cookie_out['source_file'] = f_name
                        
                        if lifecycle == 'modified':
                            cookie_out.update(calculate_modified_metrics(cookie))
                        
                        if match:
                            cookie_out.update({
                                'matched_subcategory': match['subcategory'],
                                'match_type': match['match_type'],
                                'was_decoded': match['was_decoded'],
                                'matched_pattern': match['pattern'],
                                'decoded_value': match.get('decoded_value')
                            })
                            categorized[match['category']].append(cookie_out)
                        else:
                            categorized['UNCATEGORIZED'].append(cookie_out)
                    
                    # Écriture des fichiers (Un cookie = Un seul fichier)
                    for cat, rows in categorized.items():
                        if rows:
                            with open(out_dir / f"{cat}.json", 'w', encoding='utf-8') as f:
                                json.dump(rows, f, indent=2, ensure_ascii=False)

if __name__ == '__main__':
    main()