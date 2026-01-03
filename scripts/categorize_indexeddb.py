import os
from pathlib import Path
import json
import re
import shutil
from regex import TRACKING_PATTERNS_COMPLETE

# Mapping user_id vers index dans DIRECT_PII
USER_ID_TO_INDEX = {
    'FR_0017': 0,
    'FR_0018': 1,
    'FR_0019': 2
}

from categorize_cookies import (
    try_decode_value,
    categorize_cookie,
    recursive_decode_and_reclassify,
    get_patterns_for_user
)
def extract_all_fields_recursive(data, parent_key='', separator='.'):
    """
    Extrait récursivement tous les champs d'une structure JSON complexe
    
    Returns:
        Liste de tuples (chemin_complet, valeur)
    """
    fields = []
    
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else key
            
            if isinstance(value, (dict, list)):
                # Récursion pour structures imbriquées
                fields.extend(extract_all_fields_recursive(value, new_key, separator))
            else:
                # Feuille : stocker le champ
                fields.append((new_key, value))
    
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            new_key = f"{parent_key}[{idx}]"
            
            if isinstance(item, (dict, list)):
                fields.extend(extract_all_fields_recursive(item, new_key, separator))
            else:
                fields.append((new_key, item))
    
    return fields


def categorize_indexeddb_for_config(input_dir: Path, output_dir: Path, patterns: dict):
    """
    Catégorise les fichiers IndexedDB pour une configuration donnée.
    Parse récursivement toute la structure JSON.
    """
    json_files = list(input_dir.glob("*.json"))
    if not json_files:
        print(f"  Aucun fichier IndexedDB trouvé dans {input_dir}")
        return
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    categorized = {}
    total_items = 0
    for category in patterns.keys():
        categorized[category] = []
    categorized['UNCATEGORIZED'] = []

    for json_file in json_files:
        with open(json_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                
    
                if isinstance(data, dict) and "site" in data and "data" in data:
                    # Nouveau format (real_raw): extraire depuis le champ "data"
                    data_to_process = data["data"]
                else:
                    # Ancien format (raw): utiliser directement
                    data_to_process = data
                
                # Extraire TOUS les champs récursivement
                all_fields = extract_all_fields_recursive(data_to_process)
                
                print(f"   {json_file.name}: {len(all_fields)} champs extraits")
                
                for field_path, field_value in all_fields:
                    total_items += 1
                    
                    # Créer un objet pour la catégorisation
                    indexeddb_item = {
                        'field_path': field_path,
                        'name': field_path.split('.')[-1],  # Dernier élément du chemin
                        'value': str(field_value) if not isinstance(field_value, str) else field_value,
                        'source_file': json_file.name,
                        'type': 'indexedDB',
                        'full_path': field_path
                    }
                    
                    # Catégoriser avec la logique complète (décodage automatique)
                    matches = categorize_cookie(
                        indexeddb_item,
                        patterns,
                        source_type='added'
                    )
                    
                    # Appliquer décodage récursif pour SUSPICIOUS_VALUES
                    matches = recursive_decode_and_reclassify(
                        indexeddb_item,
                        matches,
                        patterns,
                        source_type='added'
                    )
                    
                    # Ajouter les matches à l'item
                    indexeddb_item['matches'] = matches
                    
                    # Stocker dans TOUTES les catégories où il match
                    if matches:
                        # Déterminer catégorie principale (première non-SUSPICIOUS)
                        primary_category = None
                        for match in matches:
                            if match['category'] != 'SUSPICIOUS_VALUES':
                                primary_category = match['category']
                                break
                        
                        if primary_category is None:
                            primary_category = matches[0]['category']
                        
                        indexeddb_item['primary_category'] = primary_category
                        
                        # Ajouter à TOUTES les catégories matchées
                        categories_matched = set(match['category'] for match in matches)
                        for category in categories_matched:
                            categorized[category].append(indexeddb_item)
                    else:
                        indexeddb_item['primary_category'] = 'UNCATEGORIZED'
                        categorized['UNCATEGORIZED'].append(indexeddb_item)
                
            except json.JSONDecodeError:
                print(f" Erreur de décodage JSON dans {json_file}, fichier ignoré.")
                continue
    
    # Sauvegarder par catégorie
    categories_created = 0
    for category, items in categorized.items():
        if len(items) > 0:
            category_file = output_dir / f"{category}.json"
            with open(category_file, 'w', encoding='utf-8') as f:
                json.dump(items, f, indent=2, ensure_ascii=False)
            categories_created += 1
    
    if total_items > 0:
        print(f" {total_items} champs IndexedDB catégorisés ({categories_created} catégories)")


def main ():
    """Script principal pour catégoriser les fichiers IndexedDB"""
    raw_dir = Path(__file__).resolve().parent.parent / 'data' / 'raw'
    
    if not raw_dir.exists():
        print(f" dossier {raw_dir} non trouvé")
        return
    
    users = ['FR_0017', 'FR_0018', 'FR_0019']
    auth_statuses = ['Auth', 'UnAuth']
    policies = ['ALL', 'PARTIAL', 'NONE']
    
    total_files = 0
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    
    for auth in auth_statuses:
        
        for user in users:
            # Obtenir les patterns spécifiques à cet utilisateur
            user_patterns = get_patterns_for_user(user)
            
            for policy in policies:
                config_dir = raw_dir / auth / user / policy
                
                if not config_dir.exists():
                    continue
                
                # Dossier de sortie
                input_dir = base_dir / 'preprocessing' / auth / user / policy / 'indexeddb'
                output_dir = base_dir / 'user' / auth / user / policy / 'indexeddb'
                categorize_indexeddb_for_config(input_dir, output_dir, user_patterns)


if __name__ == '__main__':
    main()