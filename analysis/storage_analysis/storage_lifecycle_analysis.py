#!/usr/bin/env python3
"""
Analyse de cycle de vie des stockages web (localStorage, sessionStorage, IndexedDB).


"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Tuple
from analysis.storage_analysis import storage_lifecycle_visualizations as slviz
from analysis import privacy_metrics as pm
# Imports des modules d'analyse
# import analysis.privacy_metrics as pm
# import analysis.storage_analysis.storage_lifecycle_visualizations as slviz


def create_storage_key(item: Dict) -> str:
    """
    Crée une clé unique pour un item de stockage.
    
    Pour localStorage/sessionStorage: utilise le champ 'key'
    Pour IndexedDB: utilise 'name|source_file'
    """
    # localStorage/sessionStorage utilisent 'key'
    if 'key' in item:
        return item['key']
    
    # IndexedDB utilise 'name' et 'source_file'
    name = item.get('name', '')
    source_file = item.get('source_file', '')
    return f"{name}|{source_file}"


def load_storage_by_key(input_dir: Path, storage_type: str) -> Dict[str, List[Dict]]:
    """
    Charge tous les items de stockage et les indexe par clé.
    
    Returns:
        {storage_key: [items]}
    """
    items_by_key = defaultdict(list)
    
    category_files = sorted(input_dir.glob('*.json'))
    
    for category_file in category_files:
        category_name = category_file.stem
        
        with open(category_file, 'r', encoding='utf-8') as f:
            items = json.load(f)
        
        for item in items:
            item['_category'] = category_name
            item['_storage_type'] = storage_type
            key = create_storage_key(item)
            items_by_key[key].append(item)
    
    return items_by_key


def build_storage_timeline(storage_key: str, added_items: List[Dict], 
                           modified_items: List[Dict], deleted_items: List[Dict]) -> Dict:
    """
    Construit la timeline complte d'un item de stockage avec ordre chronologique.
    
    Returns:
        {
            'key': str,
            'events': [(event_type, metrics, task_id, timestamp, url), ...],
            'entropy_evolution': [values],
            'pii_categories': [categories],
            'size_evolution': [values],
            'task_ids': [task_ids],
            'timestamps': [timestamps],
            'urls': [urls]
        }
    """
    events = []
    
    # Événements added
    for item in added_items:
        value = str(item.get('value', ''))
        entropy = pm.calculate_entropy(value)
        size = len(value.encode('utf-8'))
        task_id = int(item.get('task_id', 0))
        timestamp = item.get('timestamp', '')
        url = item.get('final_url', item.get('initial_url', ''))
        
        # Créer pii_category
        category = item.get('_category', 'unknown')
        matches = item.get('matches', [])
        if matches and len(matches) > 0:
            subcategory = matches[0].get('subcategory', '')
            pii_category = f"{category}::{subcategory}" if subcategory else category
        else:
            pii_category = category
        
        events.append({
            'type': 'added',
            'entropy': entropy,
            'pii_category': pii_category,
            'size': size,
            'task_id': task_id,
            'timestamp': timestamp,
            'url': url
        })
    
    # Événements modified
    for item in modified_items:
        value = str(item.get('value', ''))
        entropy = pm.calculate_entropy(value)
        size = len(value.encode('utf-8'))
        task_id = int(item.get('task_id', 0))
        timestamp = item.get('timestamp', '')
        url = item.get('final_url', item.get('initial_url', ''))
        
        category = item.get('_category', 'unknown')
        matches = item.get('matches', [])
        if matches and len(matches) > 0:
            subcategory = matches[0].get('subcategory', '')
            pii_category = f"{category}::{subcategory}" if subcategory else category
        else:
            pii_category = category
        
        events.append({
            'type': 'modified',
            'entropy': entropy,
            'pii_category': pii_category,
            'size': size,
            'task_id': task_id,
            'timestamp': timestamp,
            'url': url
        })
    
    # Événements deleted
    for item in deleted_items:
        value = str(item.get('value', ''))
        entropy = pm.calculate_entropy(value)
        size = len(value.encode('utf-8'))
        task_id = int(item.get('task_id', 0))
        timestamp = item.get('timestamp', '')
        url = item.get('final_url', item.get('initial_url', ''))
        
        category = item.get('_category', 'unknown')
        matches = item.get('matches', [])
        if matches and len(matches) > 0:
            subcategory = matches[0].get('subcategory', '')
            pii_category = f"{category}::{subcategory}" if subcategory else category
        else:
            pii_category = category
        
        events.append({
            'type': 'deleted',
            'entropy': entropy,
            'pii_category': pii_category,
            'size': size,
            'task_id': task_id,
            'timestamp': timestamp,
            'url': url
        })
    
    # Trier par task_id pour ordre chronologique
    events.sort(key=lambda e: e['task_id'])
    
    # Extraire évolutions (maintenant dans l'ordre chronologique)
    entropy_evolution = [e['entropy'] for e in events]
    pii_categories = [e['pii_category'] for e in events]
    size_evolution = [e['size'] for e in events]
    task_ids = [e['task_id'] for e in events]
    timestamps = [e['timestamp'] for e in events]
    urls = [e['url'] for e in events]
    
    # Calculer la fréquence de changement (écart entre task_ids)
    task_id_gaps = []
    if len(task_ids) > 1:
        for i in range(1, len(task_ids)):
            gap = task_ids[i] - task_ids[i-1]
            task_id_gaps.append(gap)
    
    return {
        'key': storage_key,
        'events': events,
        'entropy_evolution': entropy_evolution,
        'pii_categories': pii_categories,
        'size_evolution': size_evolution,
        'task_ids': task_ids,
        'timestamps': timestamps,
        'urls': urls,
        'task_id_gaps': task_id_gaps,
        'num_modifications': len([e for e in events if e['type'] == 'modified']),
        'num_deletions': len([e for e in events if e['type'] == 'deleted'])
    }


def analyze_storage_lifecycle(base_dir: Path, storage_type: str) -> Dict:
    """
    Analyse complte du cycle de vie d'un type de stockage.
    """
    print(f"Analyse de Cycle de Vie - {storage_type.upper()}")
    
    # Définir les répertoires (s'ils existent)
    added_dir = base_dir / 'added'
    modified_dir = base_dir / 'modified'
    removed_dir = base_dir / 'removed'
    deleted_dir = base_dir / 'deleted'
    
    # Charger les items
    print("\n Chargement des items...")
    added_by_key = load_storage_by_key(added_dir, storage_type) if added_dir.exists() else {}
    modified_by_key = load_storage_by_key(modified_dir, storage_type) if modified_dir.exists() else {}
    
    # Chercher removed d'abord, puis deleted (compatibilité)
    if removed_dir.exists():
        deleted_by_key = load_storage_by_key(removed_dir, storage_type)
    elif deleted_dir.exists():
        deleted_by_key = load_storage_by_key(deleted_dir, storage_type)
    else:
        deleted_by_key = {}
    
    print(f"   Added: {len(added_by_key)} clés uniques")
    print(f"   Modified: {len(modified_by_key)} clés uniques")
    print(f"   Removed/Deleted: {len(deleted_by_key)} clés uniques")
    
    # Identifier tous les items
    all_keys = set(added_by_key.keys()) | set(modified_by_key.keys()) | set(deleted_by_key.keys())
    
    print(f"   Total: {len(all_keys)} items uniques")
    
    # Construire les timelines
    print("\n Construction des timelines...")
    timelines = {}
    
    for key in all_keys:
        added = added_by_key.get(key, [])
        modified = modified_by_key.get(key, [])
        deleted = deleted_by_key.get(key, [])
        
        if added or modified or deleted:
            timeline = build_storage_timeline(key, added, modified, deleted)
            timelines[key] = timeline
    
    print(f"   {len(timelines)} timelines construites")
    
    # Analyser les patterns
    print("\n Analyse des patterns...")
    
    # Métriques globales
    total_items = len(timelines)
    items_modified = len([t for t in timelines.values() if t['num_modifications'] > 0])
    items_deleted = len([t for t in timelines.values() if t['num_deletions'] > 0])
    
    # Évolution entropie
    entropy_increases = 0
    entropy_decreases = 0
    for timeline in timelines.values():
        if len(timeline['entropy_evolution']) > 1:
            if timeline['entropy_evolution'][-1] > timeline['entropy_evolution'][0]:
                entropy_increases += 1
            elif timeline['entropy_evolution'][-1] < timeline['entropy_evolution'][0]:
                entropy_decreases += 1
    
    # Évolution taille
    size_increases = 0
    size_decreases = 0
    for timeline in timelines.values():
        if len(timeline['size_evolution']) > 1:
            if timeline['size_evolution'][-1] > timeline['size_evolution'][0]:
                size_increases += 1
            elif timeline['size_evolution'][-1] < timeline['size_evolution'][0]:
                size_decreases += 1
    
    # Transitions PII
    pii_transitions = Counter()
    for timeline in timelines.values():
        if len(timeline['pii_categories']) > 1:
            initial = timeline['pii_categories'][0]
            final = timeline['pii_categories'][-1]
            if initial != final:
                pii_transitions[(initial, final)] += 1
    
    # Volatilité
    volatility_dist = Counter()
    for timeline in timelines.values():
        num_changes = timeline['num_modifications'] + timeline['num_deletions']
        if num_changes == 0:
            volatility_dist['stable'] += 1
        elif num_changes <= 2:
            volatility_dist['moderate'] += 1
        else:
            volatility_dist['high'] += 1
    
    # === NOUVELLES MÉTRIQUES TEMPORELLES ===
    
    # Fréquence de changement (écart moyen entre task_ids)
    all_gaps = []
    for timeline in timelines.values():
        all_gaps.extend(timeline.get('task_id_gaps', []))
    
    avg_gap = sum(all_gaps) / len(all_gaps) if all_gaps else 0
    min_gap = min(all_gaps) if all_gaps else 0
    max_gap = max(all_gaps) if all_gaps else 0
    
    # Items modifiés fréquemment (gap moyen < 50)
    frequent_changes = []
    for key, timeline in timelines.items():
        gaps = timeline.get('task_id_gaps', [])
        if gaps:
            avg_item_gap = sum(gaps) / len(gaps)
            if avg_item_gap < 50 and timeline['num_modifications'] > 0:
                frequent_changes.append({
                    'key': key,
                    'avg_gap': avg_item_gap,
                    'num_modifications': timeline['num_modifications'],
                    'pii_category': timeline['pii_categories'][-1] if timeline['pii_categories'] else 'unknown'
                })
    
    # Trier par fréquence (gap le plus petit = changement le plus fréquent)
    frequent_changes.sort(key=lambda x: x['avg_gap'])
    
    # URLs qui modifient le plus de données
    url_modifications = Counter()
    for timeline in timelines.values():
        for event in timeline['events']:
            if event['type'] == 'modified':
                # Extraire le domaine de l'URL
                url = event.get('url', '')
                if url:
                    # Simplifier l'URL (garder juste le domaine)
                    domain = url.split('/')[2] if len(url.split('/')) > 2 else url
                    url_modifications[domain] += 1
    
    # Patterns de modification par catégorie PII
    pii_modification_patterns = defaultdict(lambda: {'count': 0, 'avg_gap': 0, 'gaps': []})
    for timeline in timelines.values():
        if timeline['num_modifications'] > 0:
            pii_cat = timeline['pii_categories'][-1] if timeline['pii_categories'] else 'unknown'
            pii_modification_patterns[pii_cat]['count'] += timeline['num_modifications']
            pii_modification_patterns[pii_cat]['gaps'].extend(timeline.get('task_id_gaps', []))
    
    # Calculer les moyennes
    for pii_cat, data in pii_modification_patterns.items():
        if data['gaps']:
            data['avg_gap'] = sum(data['gaps']) / len(data['gaps'])
        else:
            data['avg_gap'] = 0
        del data['gaps']  # Supprimer pour alléger le JSON
    
    return {
        'storage_type': storage_type,
        'timelines': timelines,
        'metrics': {
            'total_items': total_items,
            'items_modified': items_modified,
            'items_deleted': items_deleted,
            'entropy_increases': entropy_increases,
            'entropy_decreases': entropy_decreases,
            'size_increases': size_increases,
            'size_decreases': size_decreases,
            'pii_transitions': dict(pii_transitions),
            'volatility_distribution': dict(volatility_dist),
            # Nouvelles métriques temporelles
            'change_frequency': {
                'avg_gap': avg_gap,
                'min_gap': min_gap,
                'max_gap': max_gap
            },
            'frequent_changes': frequent_changes[:20],  # Top 20
            'url_modifications': dict(url_modifications.most_common(10)),  # Top 10 URLs
            'pii_modification_patterns': dict(pii_modification_patterns)
        }
    }


def main():
    """Script principal"""
    base_dir = Path(__file__).resolve().parent.parent.parent / 'data'
    output_base = Path(__file__).resolve().parent.parent.parent / 'results'
    
    if not base_dir.exists():
        print(f" Dossier {base_dir} non trouvé")
        return
    
    users = ('FR_0417', 'FR_0446', 'FR_0458')
    auth_statuses = ('Auth', 'UnAuth')
    policies = ('ALL', 'PARTIAL', 'NONE')
    storage_types = ('localstorage', 'sessionstorage', 'indexeddb')
    
    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                for storage_type in storage_types:
                    storage_base_dir = base_dir / 'user' / auth_status / user / policy / storage_type
                    output_dir = output_base / auth_status / user / policy / storage_type / 'lifecycle'
                    
                    if not storage_base_dir.exists():
                        print(f"  {storage_base_dir} n'existe pas, passage  la configuration suivante.")
                        continue
                    
                    # Vérifier qu'il y a au moins un sous-dossier (added/modified/deleted)
                    has_data = any([
                        (storage_base_dir / 'added').exists(),
                        (storage_base_dir / 'modified').exists(),
                        (storage_base_dir / 'deleted').exists()
                    ])
                    
                    if not has_data:
                        print(f"  Aucun dossier added/modified/deleted dans {storage_base_dir}")
                        continue
                    
                    output_dir.mkdir(parents=True, exist_ok=True)
                    
                    print(f"\n{'='*70}")
                    print(f" Configuration: {user} / {auth_status} / {policy} / {storage_type}")
                    print(f"{'='*70}")
                    
                    # Analyser
                    results = analyze_storage_lifecycle(storage_base_dir, storage_type)
                    
                    if results['metrics']['total_items'] == 0:
                        print(f"  Aucun item trouvé, passage  la configuration suivante.")
                        continue
                    
                    # Sauvegarder les résultats
                    output_path = output_dir / 'lifecycle_data.json'
                    
                    serializable_results = {
                        'storage_type': storage_type,
                        'metrics': {
                            **results['metrics'],
                            'pii_transitions': {f"{k[0]}  {k[1]}": v 
                                               for k, v in results['metrics']['pii_transitions'].items()}
                        },
                        'num_timelines': len(results['timelines'])
                    }
                    
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(serializable_results, f, indent=2, ensure_ascii=False)
                    
                    print(f" Résultats sauvegardés : {output_path}")
                    
                    # Générer les visualisations
                    print(f"\n Génération des visualisations...")
                    graphs_dir = output_dir / 'graphs'
                    graphs_dir.mkdir(parents=True, exist_ok=True)
                    
                    # slviz.generate_lifecycle_visualizations(results, graphs_dir, storage_type)
    
    print(" Analyse de cycle de vie des stockages terminée avec succs!")
    print("=" * 70)


if __name__ == '__main__':
    main()
