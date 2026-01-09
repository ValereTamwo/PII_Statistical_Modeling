#!/usr/bin/env python3
"""
Script de Catégorisation Batch - Version Complète
Utilise la logique complète de categorize_cookies.py avec décodage et détection PII
"""

import json
from pathlib import Path
import sys

# Ajouter le dossier scripts au path
sys.path.insert(0, str(Path(__file__).parent))

# Importer les fonctions de categorize_cookies.py
from categorize_cookies import (
    categorize_cookie,
    try_decode_value,
    recursive_decode_and_reclassify,
    TRACKING_PATTERNS_COMPLETE
)


def extract_and_categorize_cookies(storage_state_dir: Path, output_dir: Path):
    """
    Extrait les cookies des fichiers storage_state et les catégorise
    avec décodage automatique et détection PII
    
    Args:
        storage_state_dir: Dossier contenant les fichiers storage_state/*.json
        output_dir: Dossier de sortie pour les cookies catégorisés
    """
    
    # Créer dossier de sortie
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Dictionnaire pour stocker les cookies par catégorie
    categorized = {}
    for category in TRACKING_PATTERNS_COMPLETE.keys():
        categorized[category] = []
    categorized['UNCATEGORIZED'] = []
    
    # Parcourir tous les fichiers JSON dans storage_state
    json_files = list(storage_state_dir.rglob("*.json"))
    
    total_cookies = 0
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extraire cookies (structure: cookies.added, cookies.removed, cookies.modified)
            if 'cookies' in data:
                cookies_data = data['cookies']
                
                # Traiter added, removed, modified
                for action in ['added', 'removed', 'modified']:
                    if action in cookies_data:
                        cookies_dict = cookies_data[action]
                        
                        # Les cookies sont dans un dictionnaire
                        if isinstance(cookies_dict, dict):
                            for cookie_key, cookie in cookies_dict.items():
                                if isinstance(cookie, dict):
                                    total_cookies += 1
                                    
                                    # Ajouter action au cookie
                                    cookie['action'] = action
                                    cookie['source_file'] = json_file.name
                                    
                                    # Catégoriser le cookie avec la logique complète
                                    matches = categorize_cookie(
                                        cookie, 
                                        TRACKING_PATTERNS_COMPLETE,
                                        source_type=action
                                    )
                                    
                                    # Appliquer décodage récursif pour SUSPICIOUS_VALUES
                                    matches = recursive_decode_and_reclassify(
                                        cookie,
                                        matches,
                                        TRACKING_PATTERNS_COMPLETE,
                                        source_type=action
                                    )
                                    
                                    # Ajouter les matches au cookie
                                    cookie['matches'] = matches
                                    
                                    # Déterminer catégorie principale
                                    if matches:
                                        # Prendre la première catégorie non-SUSPICIOUS
                                        primary_category = None
                                        for match in matches:
                                            if match['category'] != 'SUSPICIOUS_VALUES':
                                                primary_category = match['category']
                                                break
                                        
                                        if primary_category is None:
                                            primary_category = matches[0]['category']
                                        
                                        cookie['primary_category'] = primary_category
                                        categorized[primary_category].append(cookie)
                                    else:
                                        cookie['primary_category'] = 'UNCATEGORIZED'
                                        categorized['UNCATEGORIZED'].append(cookie)
        
        except Exception as e:
            # Ignorer les erreurs silencieusement
            continue
    
    # Sauvegarder par catégorie
    for category, cookies in categorized.items():
        if len(cookies) > 0:
            category_file = output_dir / f"{category}.json"
            with open(category_file, 'w', encoding='utf-8') as f:
                json.dump(cookies, f, indent=2, ensure_ascii=False)
    
    return total_cookies, categorized


def extract_and_categorize_localstorage(storage_state_dir: Path, output_dir: Path):
    """
    Extrait le localStorage des fichiers storage_state et le catégorise
    avec décodage automatique
    
    Args:
        storage_state_dir: Dossier contenant les fichiers storage_state/*.json
        output_dir: Dossier de sortie pour le localStorage catégorisé
    """
    
    # Créer dossier de sortie
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Dictionnaire pour stocker localStorage par catégorie
    categorized = {}
    for category in TRACKING_PATTERNS_COMPLETE.keys():
        categorized[category] = []
    categorized['UNCATEGORIZED'] = []
    
    # Parcourir tous les fichiers JSON dans storage_state
    json_files = list(storage_state_dir.rglob("*.json"))
    
    total_items = 0
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extraire localStorage (structure: localStorage.added, localStorage.removed, localStorage.modified)
            if 'localStorage' in data:
                ls_data = data['localStorage']
                
                # Traiter added, removed, modified
                for action in ['added', 'removed', 'modified']:
                    if action in ls_data:
                        ls_dict = ls_data[action]
                        
                        # Les items sont dans un dictionnaire
                        if isinstance(ls_dict, dict):
                            for ls_key, ls_value in ls_dict.items():
                                total_items += 1
                                
                                # Créer objet localStorage
                                ls_item = {
                                    'name': ls_key,
                                    'value': ls_value if isinstance(ls_value, str) else str(ls_value),
                                    'action': action,
                                    'source_file': json_file.name
                                }
                                
                                # Catégoriser avec la logique complète
                                matches = categorize_cookie(
                                    ls_item,
                                    TRACKING_PATTERNS_COMPLETE,
                                    source_type=action
                                )
                                
                                # Appliquer décodage récursif
                                matches = recursive_decode_and_reclassify(
                                    ls_item,
                                    matches,
                                    TRACKING_PATTERNS_COMPLETE,
                                    source_type=action
                                )
                                
                                # Ajouter les matches
                                ls_item['matches'] = matches
                                
                                # Déterminer catégorie principale
                                if matches:
                                    primary_category = None
                                    for match in matches:
                                        if match['category'] != 'SUSPICIOUS_VALUES':
                                            primary_category = match['category']
                                            break
                                    
                                    if primary_category is None:
                                        primary_category = matches[0]['category']
                                    
                                    ls_item['primary_category'] = primary_category
                                    categorized[primary_category].append(ls_item)
                                else:
                                    ls_item['primary_category'] = 'UNCATEGORIZED'
                                    categorized['UNCATEGORIZED'].append(ls_item)
        
        except Exception as e:
            # Ignorer les erreurs silencieusement
            continue
    
    # Sauvegarder par catégorie
    for category, items in categorized.items():
        if len(items) > 0:
            category_file = output_dir / f"{category}.json"
            with open(category_file, 'w', encoding='utf-8') as f:
                json.dump(items, f, indent=2, ensure_ascii=False)
    
    return total_items, categorized


def process_all_configurations():
    """
    Traite toutes les configurations dans data/raw/
    """
    
    print("=" * 70)
    print("CATÉGORISATION BATCH COMPLÈTE - TOUTES CONFIGURATIONS")
    print("=" * 70)
    print("Avec décodage automatique et détection PII")
    
    raw_dir = Path("data/raw")
    
    if not raw_dir.exists():
        print(f"❌ Dossier {raw_dir} non trouvé")
        print("   Exécutez d'abord: python scripts/replicate_data_structure.py")
        return
    
    users = ['FR_0417', 'FR_0446', 'FR_0458']
    auth_statuses = ['Auth', 'UnAuth']
    policies = ['ALL', 'PARTIAL', 'NONE']
    
    total_configs = 0
    total_cookies_all = 0
    total_ls_all = 0
    
    for auth in auth_statuses:
        print(f"\n{'='*70}")
        print(f"Statut: {auth}")
        print(f"{'='*70}")
        
        for user in users:
            print(f"\n  👤 Utilisateur: {user}")
            
            for policy in policies:
                config_dir = raw_dir / auth / user / policy
                
                if not config_dir.exists():
                    print(f"    ⚠️  {policy}: Configuration non trouvée")
                    continue
                
                # Dossier storage_state
                storage_state_dir = config_dir / "storage_state"
                
                if not storage_state_dir.exists():
                    print(f"    ⚠️  {policy}: storage_state/ non trouvé")
                    continue
                
                # Catégoriser cookies
                cookies_output = config_dir / "categorized_cookies"
                total_cookies, cookies_cat = extract_and_categorize_cookies(
                    storage_state_dir, cookies_output
                )
                
                # Catégoriser localStorage
                ls_output = config_dir / "categorized_localstorage"
                total_ls, ls_cat = extract_and_categorize_localstorage(
                    storage_state_dir, ls_output
                )
                
                # Afficher résumé
                cookies_categories = sum(1 for c in cookies_cat.values() if len(c) > 0)
                ls_categories = sum(1 for c in ls_cat.values() if len(c) > 0)
                
                print(f"    ✅ {policy:8s} : {total_cookies:4d} cookies ({cookies_categories} catégories)")
                print(f"               : {total_ls:4d} localStorage ({ls_categories} catégories)")
                
                total_configs += 1
                total_cookies_all += total_cookies
                total_ls_all += total_ls
    
    # Résumé global
    print("\n" + "=" * 70)
    print("RÉSUMÉ GLOBAL")
    print("=" * 70)
    
    print(f"\n✅ Configurations traitées: {total_configs}")
    print(f"✅ Total cookies: {total_cookies_all:,}")
    print(f"✅ Total localStorage: {total_ls_all:,}")
    print(f"\n📂 Résultats dans: data/raw/{{Auth}}/{{User}}/{{Policy}}/categorized_*")
    print(f"\n💡 Chaque cookie/localStorage contient:")
    print(f"  - matches: Liste des patterns détectés")
    print(f"  - primary_category: Catégorie principale")
    print(f"  - decoded: Valeurs décodées si applicable")
    print(f"  - action: added/removed/modified")


if __name__ == '__main__':
    try:
        process_all_configurations()
        
        print("\n" + "=" * 70)
        print("🎉 CATÉGORISATION COMPLÈTE TERMINÉE!")
        print("=" * 70)
        print("\n💡 Prochaines étapes:")
        print("  1. Vérifier les résultats dans data/raw/")
        print("  2. Analyser les PII détectées")
        print("  3. Calculer les métriques de criticité")
        
    except Exception as e:
        print(f"\n❌ ERREUR: {e}")
        import traceback
        traceback.print_exc()
