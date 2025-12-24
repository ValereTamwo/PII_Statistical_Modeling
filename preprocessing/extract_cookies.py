#!/usr/bin/env python3
"""
Script pour extraire et analyser les cookies depuis les fichiers JSON de Playwright.
Génère des fichiers JSON pour les cookies ajoutés et modifiés.
"""

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def load_cookies_from_json(filepath):
    """Charge les cookies depuis un fichier JSON"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def format_timestamp(ts):
    """Convertit un timestamp Unix en format lisible"""
    if ts and ts > 0:
        try:
            return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return ''
    return ''


def cookie_key(cookie):
    """Génère une clé unique pour identifier un cookie"""
    return f"{cookie['name']}|{cookie['domain']}|{cookie['path']}"


def cookies_equal(c1, c2):
    """Compare deux cookies pour détecter les modifications"""
    fields_to_compare = ['value', 'expires', 'httpOnly', 'secure', 'sameSite']
    return all(c1.get(f) == c2.get(f) for f in fields_to_compare)


def main():
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    if not base_dir.exists():
        print(f"Dossier {base_dir} non trouvé")
        return
    users  = ('FR_0017', 'FR_0018', 'FR_0019')
    auth_statuses = ('Auth', 'UnAuth')
    
    policies = ('ALL', 'PARTIAL', 'NONE')

    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                # Chemin dynamique : NotAUTH si UnAuth, sinon Auth
                storage_state_folder = 'NotAUTH' if auth_status == 'UnAuth' else 'Auth'
                input_dir = base_dir / 'raw' / auth_status / user / policy / 'storage_state' / storage_state_folder / policy.lower()
                if not input_dir.exists():
                    print(f"Le dossier {input_dir} n'existe pas, passage à la configuration suivante.")
                    continue
                output_dir = base_dir / 'preprocessing' / auth_status / user / policy / 'cookies'
                output_dir.mkdir(parents=True, exist_ok=True)


                # input_dir = base_dir / 'FR_0017' / 'storage_state' / 'NotAUTH' / 'all'
                # output_dir = base_dir / 'preprocessing' / 'cookies'
                # output_dir.mkdir(parents=True, exist_ok=True)

                # Listes pour stocker les cookies
                added_cookies = []
                modified_cookies = []
                
                print("=== Extraction des cookies ===\n")
                
                # Charger tous les cookies de tous les fichiers
                json_files = sorted(input_dir.glob('*.json'), key=lambda x: int(x.stem))
                
                if not json_files:
                    print(f"Aucun fichier trouvé dans {input_dir}")
                    return
                
                for filepath in json_files:
                    task_id = filepath.stem
                    print(f"Traitement de {filepath.name}...")
                    
                    try:
                        data = load_cookies_from_json(filepath)
                        
                        # Métadonnées
                        metadata = data.get('metadata', {})
                        initial_url = metadata.get('initial url', '')
                        final_url = metadata.get('final_url', '')
                        timestamp = metadata.get('timestamp', '')
                        
                        cookies_data = data.get('cookies', {})
                        
                        # Traiter les cookies ajoutés
                        added = cookies_data.get('added', {})
                        for cookie_key, cookie in added.items():
                            cookie_info = {
                                'task_id': task_id,
                                'cookie_key': cookie_key,
                                'name': cookie.get('name', ''),
                                'value': cookie.get('value', ''),
                                'domain': cookie.get('domain', ''),
                                'path': cookie.get('path', ''),
                                'expires': cookie.get('expires', -1),
                                'expires_human': format_timestamp(cookie.get('expires', -1)),
                                'httpOnly': cookie.get('httpOnly', False),
                                'secure': cookie.get('secure', False),
                                'sameSite': cookie.get('sameSite', None),
                                'initial_url': initial_url,
                                'final_url': final_url,
                                'timestamp': timestamp
                            }
                            added_cookies.append(cookie_info)
                        
                        # Traiter les cookies modifiés
                        modified = cookies_data.get('modified', {})
                        for cookie_key, change_data in modified.items():
                            from_cookie = change_data.get('from', {})
                            to_cookie = change_data.get('to', {})
                            
                            modified_info = {
                                'task_id': task_id,
                                'cookie_key': cookie_key,
                                'name': from_cookie.get('name', ''),
                                'domain': from_cookie.get('domain', ''),
                                'path': from_cookie.get('path', ''),
                                
                                # Valeurs
                                'value': to_cookie.get('value', ''),
                                'value_from': from_cookie.get('value', ''),
                                'value_to': to_cookie.get('value', ''),
                                'value_changed': from_cookie.get('value') != to_cookie.get('value'),
                                
                                # Expiration
                                'expires': to_cookie.get('expires', -1),
                                'expires_from': from_cookie.get('expires', -1),
                                'expires_to': to_cookie.get('expires', -1),
                                'expires_human': format_timestamp(to_cookie.get('expires', -1)),
                                'expires_changed': from_cookie.get('expires') != to_cookie.get('expires'),
                                
                                # Flags de sécurité
                                'httpOnly': to_cookie.get('httpOnly', False),
                                'httpOnly_from': from_cookie.get('httpOnly', False),
                                'httpOnly_to': to_cookie.get('httpOnly', False),
                                'httpOnly_changed': from_cookie.get('httpOnly') != to_cookie.get('httpOnly'),
                                
                                'secure': to_cookie.get('secure', False),
                                'secure_from': from_cookie.get('secure', False),
                                'secure_to': to_cookie.get('secure', False),
                                'secure_changed': from_cookie.get('secure') != to_cookie.get('secure'),
                                
                                'sameSite': to_cookie.get('sameSite', None),
                                'sameSite_from': from_cookie.get('sameSite', None),
                                'sameSite_to': to_cookie.get('sameSite', None),
                                'sameSite_changed': from_cookie.get('sameSite') != to_cookie.get('sameSite'),
                                
                                # Métadonnées
                                'initial_url': initial_url,
                                'final_url': final_url,
                                'timestamp': timestamp
                            }
                            modified_cookies.append(modified_info)
                    
                    except Exception as e:
                        print(f"  ⚠ Erreur lors du traitement de {filepath.name}: {e}")
                        continue
                
                print(f"\n{len(json_files)} fichiers traités\n")
                
                # Sauvegarder en JSON
                print("Génération des fichiers JSON...\n")
                
                # Cookies ajoutés
                if added_cookies:
                    output_file = output_dir / 'added_cookies.json'
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(added_cookies, f, ensure_ascii=False, indent=2)
                    
                    print(f"✓ {len(added_cookies)} cookies ajoutés → {output_file}")
                
                # Cookies modifiés
                if modified_cookies:
                    output_file = output_dir / 'modified_cookies.json'
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(modified_cookies, f, ensure_ascii=False, indent=2)
                    
                    print(f"✓ {len(modified_cookies)} cookies modifiés → {output_file}")
                
                print("\n=== Extraction terminée ===")


if __name__ == '__main__':
    main()

