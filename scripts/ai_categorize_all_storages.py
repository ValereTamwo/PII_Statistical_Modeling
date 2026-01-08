#!/usr/bin/env python3
"""
Catégorisation IA pour tous les storages UNCATEGORIZED.

Itère sur tous les fichiers UNCATEGORIZED.json dans data/user/ et les catégorise
via LLM (Groq) en batches de 30 items.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import Counter

# Pour Groq API
try:
    from groq import Groq
except ImportError:
    print("Installation de groq...")
    os.system("pip install groq")
    from groq import Groq

# Importer regex pour catégories
sys.path.insert(0, str(Path(__file__).parent))
from regex import TRACKING_PATTERNS_COMPLETE

# Charger les profils utilisateurs
USER_PROFILES_FILE = Path(__file__).parent / 'user_profiles.json'
with open(USER_PROFILES_FILE, 'r', encoding='utf-8') as f:
    USER_PROFILES = {profile['id']: profile for profile in json.load(f)}


def discover_uncategorized_files(base_path: Path) -> List[Tuple[str, str, str, str, str, Path]]:
    """
    Découvre tous les fichiers UNCATEGORIZED.json dans la structure data/user/.
    
    Returns:
        List of tuples: (auth_mode, user_id, policy, storage_type, lifecycle, file_path)
    """
    uncategorized_files = []
    
    for auth_mode in ['Auth', 'UnAuth']:
        auth_path = base_path / auth_mode
        if not auth_path.exists():
            continue
            
        for user_dir in auth_path.iterdir():
            if not user_dir.is_dir():
                continue
            user_id = user_dir.name
            
            for policy_dir in user_dir.iterdir():
                if not policy_dir.is_dir():
                    continue
                policy = policy_dir.name
                
                for storage_dir in policy_dir.iterdir():
                    if not storage_dir.is_dir():
                        continue
                    storage_type = storage_dir.name
                    
                    # Pour indexeddb, pas de sous-dossier added/modified
                    if storage_type == 'indexeddb':
                        uncategorized_file = storage_dir / 'UNCATEGORIZED.json'
                        if uncategorized_file.exists():
                            uncategorized_files.append((
                                auth_mode, user_id, policy, storage_type, 'all', uncategorized_file
                            ))
                    else:
                        # Pour cookies, localstorage, sessionstorage
                        for lifecycle in ['added', 'modified', 'removed']:
                            lifecycle_dir = storage_dir / lifecycle
                            if not lifecycle_dir.exists():
                                continue
                            
                            uncategorized_file = lifecycle_dir / 'UNCATEGORIZED.json'
                            if uncategorized_file.exists():
                                uncategorized_files.append((
                                    auth_mode, user_id, policy, storage_type, lifecycle, uncategorized_file
                                ))
    
    return uncategorized_files



# Mapping user_id vers index dans DIRECT_PII
USER_ID_TO_INDEX = {
    'FR_0417': 0,
    'FR_0018': 1,
    'FR_0419': 2
}


def get_pii_categories_list() -> List[str]:
    """Retourne la liste des catégories PII disponibles"""
    categories = list(TRACKING_PATTERNS_COMPLETE.keys())
    
    # Ajouter sous-catégories DIRECT_PII
    direct_pii_subcats = [
        'DIRECT_PII::email',
        'DIRECT_PII::phone',
        'DIRECT_PII::name',
        'DIRECT_PII::address',
        'DIRECT_PII::birthdate',
        'DIRECT_PII::gender',
        'DIRECT_PII::blood_type',
        'DIRECT_PII::password'
    ]
    
    return categories + direct_pii_subcats


def format_regex_patterns_for_prompt(user_id: str) -> str:
    """Formate les patterns regex de manière lisible pour le LLM"""
    formatted = "PATTERNS DE DÉTECTION COMPLETS (regex.py):\n\n"
    
    # Créer une copie des patterns avec le bon DIRECT_PII pour cet utilisateur
    patterns_with_user_pii = dict(TRACKING_PATTERNS_COMPLETE)
    
    # Sélectionner le bon DIRECT_PII selon l'index de l'utilisateur
    user_index = USER_ID_TO_INDEX.get(user_id, 0)  # Défaut: index 0
    if isinstance(TRACKING_PATTERNS_COMPLETE['DIRECT_PII'], list):
        patterns_with_user_pii['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII'][user_index]
    else:
        # Fallback si DIRECT_PII n'est pas encore une liste
        patterns_with_user_pii['DIRECT_PII'] = TRACKING_PATTERNS_COMPLETE['DIRECT_PII']
    
    for category, patterns in patterns_with_user_pii.items():
        formatted += f"## {category}\n"
        if isinstance(patterns, dict):
            for pattern_name, pattern_value in patterns.items():
                # Limiter la longueur pour éviter un prompt trop long
                if len(str(pattern_value)) > 100:
                    pattern_display = str(pattern_value)[:100] + "..."
                else:
                    pattern_display = pattern_value
                formatted += f"  - {pattern_name}: {pattern_display}\n"
        formatted += "\n"
    
    return formatted


def build_batch_prompt(
    items_batch: List[Dict], 
    storage_type: str,
    categories: List[str],
    regex_patterns: str
) -> str:
    """
    Construit le prompt pour analyser un batch d'items.
    """
    # Préparer les items pour le prompt
    items_text = ""
    for i, item in enumerate(items_batch, 1):
        if storage_type == 'cookies':
            key = item.get('name', item.get('cookie_key', ''))
            value = item.get('value', '')
            domain = item.get('domain', '')
            items_text += f"""
ITEM {i}:
Type: Cookie
Nom: {key}
Domaine: {domain}
Valeur: {value[:200] if len(value) > 200 else value}
HttpOnly: {item.get('httpOnly', False)}
Secure: {item.get('secure', False)}
SameSite: {item.get('sameSite', 'None')}
---
"""
        else:  # localStorage, sessionStorage, indexedDB
            key = item.get('key', '')
            value = item.get('value', '')
            items_text += f"""
ITEM {i}:
Type: {storage_type}
Clé: {key}
Valeur: {value[:500] if len(value) > 500 else value}
---
"""
    
    prompt = f"""Vous êtes un expert en conformité RGPD spécialisé dans la détection de données personnelles dans le stockage web.

TYPE DE STORAGE ANALYSÉ: {storage_type.upper()}

{regex_patterns}

CATÉGORIES PII DISPONIBLES:
{', '.join(categories)}

ITEMS À ANALYSER ({len(items_batch)} items):
{items_text}

TÂCHE:
Analysez CHAQUE item et identifiez TOUTES les données personnelles présentes selon le RGPD.

INSTRUCTIONS:
1. Utilisez les PATTERNS ci-dessus pour identifier trackeurs et technologies
2. Identifiez les vendors/trackeurs (Google, Meta, Criteo, Taboola, etc.)
3. N'HÉSITEZ PAS à identifier d'autres trackeurs/vendors basés sur vos connaissances
4. Expliquez comment les trackeurs collectent/partagent les données
5. Évaluez les risques RGPD
6. Un item peut avoir plusieurs catégories

RÉPONDEZ UNIQUEMENT EN JSON avec cette structure EXACTE (un objet par item):
{{
  "items": [
    {{
      "item_number": 1,
      "categories": ["liste des catégories"],
      "primary_category": "catégorie principale",
      "confidence": 0.0-1.0,
      "explanation": "explication concise",
      "pii_detected": [
        {{
          "type": "type de PII",
          "value": "valeur exacte ou 'présent'",
          "location": "où dans l'item",
          "certainty": "low|medium|high",
          "tracker": "trackeur si applicable"
        }}
      ],
      "trackers_identified": ["liste trackeurs"],
      "technologies_detected": ["fingerprinting, behavioral tracking, etc."],
      "gdpr_violations": [
        {{
          "article": "Article RGPD",
          "severity": "low|medium|high|critical",
          "description": "description courte"
        }}
      ],
      "vulnerabilities": ["liste vulnérabilités"],
      "risk_score": 0-10,
      "recommendations": ["liste recommandations"]
    }},
    ... (répéter pour chaque item)
  ]
}}

IMPORTANT:
- Analysez TOUS les {len(items_batch)} items
- Pour pii_detected: TOUJOURS inclure type, value, location, certainty
- Utilisez les PATTERNS fournis ET vos propres connaissances
- Identifiez TOUS les trackeurs, même ceux non listés
- Soyez concis mais précis
- Répondez UNIQUEMENT en JSON valide
"""
    
    return prompt


def analyze_batch_with_ai(
    items_batch: List[Dict],
    storage_type: str,
    categories: List[str],
    regex_patterns: str,
    client: Groq,
    model: str = "llama-3.3-70b-versatile"
) -> Optional[List[Dict]]:
    """
    Analyse un batch d'items avec l'IA Groq.
    """
    try:
        prompt = build_batch_prompt(items_batch, storage_type, categories, regex_patterns)
        
        # Appel API Groq
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "Vous êtes un expert RGPD. Répondez UNIQUEMENT en JSON valide avec un tableau 'items'."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model=model,
            temperature=0.1,
            max_tokens=4000,
            response_format={"type": "json_object"}
        )
        
        # Parser réponse
        response_text = chat_completion.choices[0].message.content
        response_json = json.loads(response_text)
        
        # Extraire analyses
        if 'items' in response_json:
            return response_json['items']
        else:
            print(f"  Erreur: format JSON invalide (pas de clé 'items')")
            return None
        
    except json.JSONDecodeError as e:
        print(f"  Erreur parsing JSON: {e}")
        return None
    except Exception as e:
        print(f"  Erreur API: {e}")
        return None


def load_existing_category_file(category_file: Path) -> List[Dict]:
    """Charge un fichier de catégorie existant s'il existe"""
    if category_file.exists():
        with open(category_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []


def save_categorized_items(
    items_with_analysis: List[Tuple[Dict, Dict]],
    output_dir: Path,
    storage_type: str
):
    """
    Sauvegarde les items catégorisés dans les fichiers appropriés.
    Respecte le format existant des fichiers de catégories (regex-based).
    
    Args:
        items_with_analysis: List of (original_item, ai_analysis) tuples
        output_dir: Directory where category files are stored
        storage_type: Type of storage (cookies, localstorage, sessionstorage, indexeddb)
    """
    # Grouper par catégorie primaire
    categorized_data = {}
    
    for original_item, analysis in items_with_analysis:
        primary_cat = analysis.get('primary_category', 'FAILED_ANALYSIS')
        
        # Créer l'item enrichi en respectant le format existant + flag ai_categorized
        enriched_item = {**original_item}
        
        # Ajouter le flag ai_categorized pour tous les types
        enriched_item['ai_categorized'] = True
        
        if storage_type == 'cookies':
            # Format cookies: ajouter matched_subcategory, match_type, was_decoded, matched_pattern
            enriched_item['matched_subcategory'] = 'ai_categorized'
            enriched_item['match_type'] = 'ai_analysis'
            enriched_item['was_decoded'] = False
            enriched_item['matched_pattern'] = f"AI: {analysis.get('explanation', '')[:100]}"
        else:
            # Format localStorage/sessionStorage/indexedDB: ajouter _categories, _primary_category, etc.
            # Ces champs existent déjà dans UNCATEGORIZED, on les met à jour
            enriched_item['_categories'] = analysis.get('categories', [primary_cat])
            enriched_item['_primary_category'] = primary_cat
            # Garder _is_json, _json_depth, _size_bytes s'ils existent déjà
        
        if primary_cat not in categorized_data:
            categorized_data[primary_cat] = []
        categorized_data[primary_cat].append(enriched_item)
    
    # Sauvegarder dans les fichiers de catégories
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for category, new_items in categorized_data.items():
        category_file = output_dir / f'{category}.json'
        
        # Charger items existants
        existing_items = load_existing_category_file(category_file)
        
        # Fusionner (append)
        all_items = existing_items + new_items
        
        # Sauvegarder
        with open(category_file, 'w', encoding='utf-8') as f:
            json.dump(all_items, f, indent=2, ensure_ascii=False)
        
        print(f"    → {category}: +{len(new_items)} items (total: {len(all_items)})")


def process_uncategorized_file(
    file_info: Tuple[str, str, str, str, str, Path],
    client: Groq,
    categories: List[str],
    batch_size: int = 30,
    limit_per_file: Optional[int] = None,
    dry_run: bool = False
) -> Dict:
    """
    Traite un fichier UNCATEGORIZED.json.
    
    Returns:
        Statistics dict
    """
    auth_mode, user_id, policy, storage_type, lifecycle, file_path = file_info
    
    # Générer les regex patterns pour cet utilisateur spécifique
    regex_patterns = format_regex_patterns_for_prompt(user_id)
    
    print(f"\n{'='*80}")
    print(f"Traitement: {auth_mode}/{user_id}/{policy}/{storage_type}/{lifecycle}")
    print(f"Fichier: {file_path}")
    
    # Charger items
    with open(file_path, 'r', encoding='utf-8') as f:
        all_items = json.load(f)
    
    original_count = len(all_items)
    
    # Limiter si demandé
    if limit_per_file:
        items_to_process = all_items[:limit_per_file]
        print(f"Mode limité: {len(items_to_process)}/{original_count} items")
    else:
        items_to_process = all_items
        print(f"Total items: {len(items_to_process)}")
    
    if dry_run:
        print("Mode DRY-RUN: simulation sans appels API")
        return {
            'file': str(file_path),
            'total': len(items_to_process),
            'processed': 0,
            'failed': 0,
            'dry_run': True
        }
    
    # Statistiques
    stats = {
        'file': str(file_path),
        'total': len(items_to_process),
        'processed': 0,
        'failed': 0,
        'categories_count': Counter()
    }
    
    # Output directory (même que le fichier UNCATEGORIZED)
    output_dir = file_path.parent
    
    # Suivre les items traités avec succès pour les retirer de UNCATEGORIZED
    successfully_processed_items = []
    
    # Traiter par batches
    for batch_start in range(0, len(items_to_process), batch_size):
        batch_end = min(batch_start + batch_size, len(items_to_process))
        items_batch = items_to_process[batch_start:batch_end]
        
        print(f"  Batch [{batch_start+1}-{batch_end}/{len(items_to_process)}]...", end=' ')
        
        # Analyser avec IA
        analyses = analyze_batch_with_ai(
            items_batch, storage_type, categories, regex_patterns, client
        )
        
        if analyses and len(analyses) == len(items_batch):
            # Créer les paires (item, analysis)
            items_with_analysis = list(zip(items_batch, analyses))
            
            # Sauvegarder
            save_categorized_items(items_with_analysis, output_dir, storage_type)
            
            # Marquer comme traités avec succès
            successfully_processed_items.extend(items_batch)
            
            # Stats
            stats['processed'] += len(analyses)
            for analysis in analyses:
                stats['categories_count'][analysis.get('primary_category', 'UNKNOWN')] += 1
            
            print(f"OK ({len(analyses)} items)")
        else:
            print(f"FAILED (attendu {len(items_batch)}, reçu {len(analyses) if analyses else 0})")
            stats['failed'] += len(items_batch)
        
        # Rate limiting
        if batch_end < len(items_to_process):
            time.sleep(2.5)
    
    # Mettre à jour UNCATEGORIZED.json en retirant les items traités
    if successfully_processed_items:
        # Créer un set des items traités pour comparaison rapide
        # On utilise une clé unique selon le type de storage
        if storage_type == 'cookies':
            processed_keys = {item.get('cookie_key', '') for item in successfully_processed_items}
            remaining_items = [item for item in all_items if item.get('cookie_key', '') not in processed_keys]
        else:
            # Pour localStorage/sessionStorage/indexedDB, utiliser la clé
            processed_keys = {item.get('key', '') for item in successfully_processed_items}
            remaining_items = [item for item in all_items if item.get('key', '') not in processed_keys]
        
        # Sauvegarder le fichier UNCATEGORIZED mis à jour
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(remaining_items, f, indent=2, ensure_ascii=False)
        
        print(f"  ✓ UNCATEGORIZED mis à jour: {len(remaining_items)} items restants (retiré {len(successfully_processed_items)})")
    
    return stats


def process_all_uncategorized(
    base_path: Path,
    api_key: str,
    batch_size: int = 30,
    limit_per_file: Optional[int] = None,
    dry_run: bool = False
):
    """
    Traite tous les fichiers UNCATEGORIZED.json trouvés.
    """
    print("="*80)
    print("CATÉGORISATION IA - TOUS LES STORAGES")
    print("="*80)
    
    # Découvrir fichiers
    print("\nDécouverte des fichiers UNCATEGORIZED...")
    uncategorized_files = discover_uncategorized_files(base_path)
    print(f"Trouvé: {len(uncategorized_files)} fichiers UNCATEGORIZED")
    
    if not uncategorized_files:
        print("Aucun fichier à traiter.")
        return
    
    # Initialiser client Groq
    if not dry_run:
        client = Groq(api_key=api_key)
    else:
        client = None
    
    # Préparer contexte
    categories = get_pii_categories_list()
    
    print(f"Catégories PII: {len(categories)}")
    print(f"Batch size: {batch_size}")
    if limit_per_file:
        print(f"Limite par fichier: {limit_per_file} items")
    if dry_run:
        print("Mode: DRY-RUN (simulation)")
    
    # Statistiques globales
    global_stats = {
        'files_processed': 0,
        'total_items': 0,
        'processed_items': 0,
        'failed_items': 0,
        'categories_distribution': Counter()
    }
    
    # Traiter chaque fichier
    for i, file_info in enumerate(uncategorized_files, 1):
        print(f"\n[{i}/{len(uncategorized_files)}]")
        
        file_stats = process_uncategorized_file(
            file_info, client, categories,
            batch_size, limit_per_file, dry_run
        )
        
        # Agréger stats
        global_stats['files_processed'] += 1
        global_stats['total_items'] += file_stats['total']
        global_stats['processed_items'] += file_stats['processed']
        global_stats['failed_items'] += file_stats['failed']
        if 'categories_count' in file_stats:
            global_stats['categories_distribution'].update(file_stats['categories_count'])
    
    # Afficher résumé global
    print("\n" + "="*80)
    print("RÉSUMÉ GLOBAL")
    print("="*80)
    print(f"Fichiers traités: {global_stats['files_processed']}")
    print(f"Items totaux: {global_stats['total_items']}")
    print(f"Items catégorisés: {global_stats['processed_items']}")
    print(f"Items échoués: {global_stats['failed_items']}")
    
    if global_stats['categories_distribution']:
        print(f"\nDistribution des catégories:")
        for cat, count in global_stats['categories_distribution'].most_common(10):
            pct = count / global_stats['processed_items'] * 100 if global_stats['processed_items'] > 0 else 0
            print(f"  {cat}: {count} ({pct:.1f}%)")


def main():
    """Script principal"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Catégorisation IA pour tous les storages UNCATEGORIZED'
    )
    parser.add_argument('--api-key', help='Groq API key (ou variable GROQ_API_KEY)')
    parser.add_argument('--batch-size', type=int, default=30, help='Taille des batches (défaut: 30)')
    parser.add_argument('--limit-per-file', type=int, help='Limite d\'items par fichier (pour tests)')
    parser.add_argument('--dry-run', action='store_true', help='Simulation sans appels API')
    
    args = parser.parse_args()
    
    # Récupérer API key
    api_key = args.api_key or os.environ.get('GROQ_API_KEY')
    
    if not api_key and not args.dry_run:
        print("Erreur: API key requise (sauf en mode --dry-run)")
        print("Utilisez --api-key ou définissez GROQ_API_KEY")
        sys.exit(1)
    
    base_path = Path(__file__).parent.parent / 'data' / 'user'
    
    if not base_path.exists():
        print(f"Erreur: chemin introuvable: {base_path}")
        sys.exit(1)
    
    process_all_uncategorized(
        base_path,
        api_key,
        batch_size=args.batch_size,
        limit_per_file=args.limit_per_file,
        dry_run=args.dry_run
    )


if __name__ == '__main__':
    main()
