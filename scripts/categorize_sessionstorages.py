#!/usr/bin/env python3
"""
Script de catégorisation localStorage - Version simplifiée.

Logique :
1. Utiliser UNIQUEMENT les regex de regex.py
2. Appliquer sur valeurs (JSON ou string)
3. Appliquer sur noms de champs JSON pour affiner
4. Appliquer sur clés localStorage
5. Catégorisation précise sans patterns supplémentaires
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional

# Importer les regex existantes
sys.path.insert(0, str(Path(__file__).parent))
from regex import TRACKING_PATTERNS_COMPLETE

# Mapping user_id vers index dans DIRECT_PII
USER_ID_TO_INDEX = {
    'FR_0017': 0,
    'FR_0018': 1,
    'FR_0019': 2
}


def get_patterns_for_user(user_id):
    """Retourne les patterns avec le bon DIRECT_PII pour l'utilisateur"""
    patterns = dict(TRACKING_PATTERNS_COMPLETE)
    user_index = USER_ID_TO_INDEX.get(user_id, 0)
    if isinstance(TRACKING_PATTERNS_COMPLETE['DIRECT_PII'], list):
        patterns['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII'][user_index]
    return patterns


def apply_regex_to_text(text: str, patterns: Dict) -> Optional[str]:
    """
    Applique les regex sur un texte.
    
    Returns:
        Category name (avec sous-catégorie si DIRECT_PII) ou None
    """
    if not text or not isinstance(text, str):
        return None
    
    for category, patterns_dict in patterns.items():
        for pattern_name, pattern in patterns_dict.items():
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    # Pour DIRECT_PII, retourner avec sous-catégorie
                    if category == 'DIRECT_PII':
                        # Déduire sous-catégorie du nom du pattern
                        if 'email' in pattern_name:
                            return 'DIRECT_PII::email'
                        elif 'phone' in pattern_name:
                            return 'DIRECT_PII::phone'
                        elif 'name' in pattern_name:
                            return 'DIRECT_PII::name'
                        elif 'address' in pattern_name or 'city' in pattern_name:
                            return 'DIRECT_PII::address'
                        elif 'birth' in pattern_name:
                            return 'DIRECT_PII::birthdate'
                        elif 'gender' in pattern_name:
                            return 'DIRECT_PII::gender'
                        elif 'blood' in pattern_name:
                            return 'DIRECT_PII::blood_type'
                        elif 'password' in pattern_name:
                            return 'DIRECT_PII::password'
                        elif 'user_id' in pattern_name:
                            return 'DIRECT_PII::user_id'
                        else:
                            return 'DIRECT_PII'
                    else:
                        return category
            except re.error:
                continue
    
    return None


def extract_all_text_from_json(obj: Any, texts: List[str], depth: int = 0, max_depth: int = 10):
    """
    Extrait récursivement tous les textes d'un objet JSON.
    Inclut les noms de champs ET les valeurs.
    """
    if depth > max_depth:
        return
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            # Ajouter le nom du champ
            texts.append(key)
            # Récursion sur la valeur
            extract_all_text_from_json(value, texts, depth + 1, max_depth)
    elif isinstance(obj, list):
        for item in obj:
            extract_all_text_from_json(item, texts, depth + 1, max_depth)
    elif isinstance(obj, str):
        # Ajouter la valeur string
        texts.append(obj)
    elif obj is not None:
        # Convertir nombres, bool, etc. en string
        texts.append(str(obj))


def categorize_localstorage_item(item: Dict, patterns: Dict) -> Dict:
    """
    Catégorise un item localStorage en utilisant UNIQUEMENT les regex existantes.
    
    Stratégie :
    1. Parser JSON si possible
    2. Extraire TOUS les textes (champs + valeurs)
    3. Appliquer regex sur chaque texte
    4. Appliquer regex sur la clé
    5. Agréger les catégories trouvées
    """
    key = item.get('key', '')
    value = item.get('value', '')
    
    categories_found = []
    is_json = False
    json_depth = 0
    all_texts = []
    
    # 1. Tenter de parser JSON
    try:
        parsed = json.loads(value)
        is_json = True
        
        # 2. Extraire tous les textes (champs + valeurs)
        extract_all_text_from_json(parsed, all_texts)
        
        # Calculer profondeur
        def get_depth(obj, current=0):
            if isinstance(obj, dict) and obj:
                return max(get_depth(v, current + 1) for v in obj.values())
            elif isinstance(obj, list) and obj:
                return max(get_depth(item, current + 1) for item in obj)
            return current
        
        json_depth = get_depth(parsed)
        
    except (json.JSONDecodeError, TypeError):
        # Valeur simple string
        all_texts.append(value)
    
    # 3. Appliquer regex sur tous les textes extraits
    for text in all_texts:
        cat = apply_regex_to_text(text, patterns)
        if cat:
            categories_found.append(cat)
    
    # 4. Appliquer regex sur la clé
    cat = apply_regex_to_text(key, patterns)
    if cat:
        categories_found.append(cat)
    
    # 5. Dédupliquer et déterminer catégorie principale
    categories_found = list(set(categories_found))
    
    if not categories_found:
        categories_found = ['UNCATEGORIZED']
    
    # Priorité : DIRECT_PII > AUTH_TOKENS > IDENTITY_TRACKING > autres
    primary_category = categories_found[0]
    
    for cat in categories_found:
        if 'DIRECT_PII' in cat:
            primary_category = cat
            break
    
    if primary_category == categories_found[0]:  # Pas de DIRECT_PII trouvé
        if 'SUSPICIOUS_VALUES' in categories_found:
            primary_category = 'SUSPICIOUS_VALUES'
        elif any('IDENTITY_TRACKING' in cat for cat in categories_found):
            primary_category = next(cat for cat in categories_found if 'IDENTITY_TRACKING' in cat)
    
    # Calculer taille
    size_bytes = len(value.encode('utf-8')) if value else 0
    
    return {
        'original': item,
        'categories': categories_found,
        'primary_category': primary_category,
        'is_json': is_json,
        'json_depth': json_depth,
        'size_bytes': size_bytes,
        'num_texts_analyzed': len(all_texts)
    }


def categorize_all_sessionStorage(input_file: Path, output_dir: Path,patterns: Dict):
    """
    Catégorise tous les items localStorage.
    """
    print(f"\nCatégorisation localStorage : {input_file.name}")
    print("=" * 70)
    
    # Charger les données
    with open(input_file, 'r', encoding='utf-8') as f:
        items = json.load(f)
    
    print(f"\nTotal items: {len(items)}")
    
    # Catégoriser chaque item
    categorized_data = defaultdict(list)
    stats = {
        'total': len(items),
        'json_count': 0,
        'string_count': 0,
        'category_counts': Counter(),
        'total_size_bytes': 0,
        'max_depth': 0,
        'total_texts_analyzed': 0
    }
    
    for item in items:
        result = categorize_localstorage_item(item, patterns)
        
        # Statistiques
        if result['is_json']:
            stats['json_count'] += 1
        else:
            stats['string_count'] += 1
        
        stats['category_counts'][result['primary_category']] += 1
        stats['total_size_bytes'] += result['size_bytes']
        stats['max_depth'] = max(stats['max_depth'], result['json_depth'])
        stats['total_texts_analyzed'] += result['num_texts_analyzed']
        
        # Ajouter à la catégorie
        categorized_data[result['primary_category']].append(result)
    
    # Sauvegarder par catégorie
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for category, items_list in categorized_data.items():
        output_file = output_dir / f'{category}.json'
        
        # Simplifier pour sauvegarde
        simplified = []
        for item in items_list:
            simplified.append({
                **item['original'],
                '_categories': item['categories'],
                '_primary_category': item['primary_category'],
                '_is_json': item['is_json'],
                '_json_depth': item['json_depth'],
                '_size_bytes': item['size_bytes']
            })
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(simplified, f, indent=2, ensure_ascii=False)
        
        print(f"  {category}: {len(items_list)} items")
    
    # Afficher statistiques
    print(f"\nStatistiques:")
    print(f"  JSON: {stats['json_count']} ({stats['json_count']/stats['total']*100:.1f}%)")
    print(f"  String: {stats['string_count']} ({stats['string_count']/stats['total']*100:.1f}%)")
    print(f"  Taille totale: {stats['total_size_bytes'] / 1024:.1f} KB")
    print(f"  Profondeur JSON max: {stats['max_depth']}")
    print(f"  Textes analysés: {stats['total_texts_analyzed']}")
    
    print(f"\nTop 10 catégories:")
    for cat, count in stats['category_counts'].most_common(10):
        print(f"  {cat}: {count} ({count/stats['total']*100:.1f}%)")
    
    print("\n" + "=" * 70)


def main():
    """Script principal"""
  
    

    base_dir = Path(__file__).resolve().parent.parent / 'data'
    if not base_dir.exists():
        print(f"Dossier {base_dir} non trouvé")
        return
    users  = ('FR_0017', 'FR_0018', 'FR_0019')
    auth_statuses = ('Auth', 'UnAuth')
    
    policies = ('ALL', 'PARTIAL', 'NONE')

    for user in users:
        # Obtenir les patterns spécifiques à cet utilisateur
        user_patterns = get_patterns_for_user(user)
        
        for auth_status in auth_statuses:
            for policy in policies:
                input_dir = base_dir / 'preprocessing' / auth_status / user / policy / 'sessionstorage'
                if not input_dir.exists():
                    print(f"Le dossier {input_dir} n'existe pas, passage à la configuration suivante.")
                    continue
                output_base_dir = base_dir / 'user' / auth_status / user / policy / 'sessionstorage'
                # output_modified_dir = base_dir / 'user' / auth_status / user / policy / 'localstorage'/ 'modified'
                
                output_base_dir.mkdir(parents=True, exist_ok=True)
                # output_modified_dir.mkdir(parents=True, exist_ok=True)


                # Fichiers à traiter
                files_to_process = [
                    ('added', input_dir / 'added_sessionstorage.json', output_base_dir / 'added'),
                    ('modified', input_dir / 'modified_sessionstorage.json', output_base_dir / 'modified'),
                    ('removed', input_dir / 'removed_sessionstorage.json', output_base_dir / 'removed')
                ]
                
                for source_type, input_file, output_dir in files_to_process:
                    if input_file.exists():
                        categorize_all_sessionStorage(input_file, output_dir,user_patterns)
                    else:
                        print(f"\nFichier non trouvé: {input_file}")


if __name__ == '__main__':
    main()
