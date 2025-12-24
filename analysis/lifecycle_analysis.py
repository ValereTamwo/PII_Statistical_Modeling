#!/usr/bin/env python3
"""
Analyse de cycle de vie des cookies.
Combine added et modified pour raconter l'histoire complète de chaque cookie.

Génère 5 graphiques temporels :
- 29. Sankey temporel (timeline)
- 30. Évolution durée de vie
- 31. Évolution entropie
- 32. Matrice transitions PII
- 33. Heatmap activité
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Imports des modules d'analyse
sys.path.insert(0, str(Path(__file__).parent))
import privacy_metrics as pm
import lifecycle_visualizations as lviz


def create_cookie_key(cookie: Dict) -> str:
    """
    Crée une clé unique pour un cookie.
    Format: name|domain|path
    """
    name = cookie.get('name', '')
    domain = cookie.get('domain', '')
    path = cookie.get('path', '/')
    return f"{name}|{domain}|{path}"


def load_cookies_by_key(input_dir: Path) -> Dict[str, List[Dict]]:
    """
    Charge tous les cookies et les indexe par clé.
    
    Returns:
        {cookie_key: [cookies]}
    """
    cookies_by_key = defaultdict(list)
    
    category_files = sorted(input_dir.glob('*.json'))
    
    for category_file in category_files:
        category_name = category_file.stem
        
        with open(category_file, 'r', encoding='utf-8') as f:
            cookies = json.load(f)
        
        for cookie in cookies:
            cookie['_category'] = category_name
            key = create_cookie_key(cookie)
            cookies_by_key[key].append(cookie)
    
    return cookies_by_key


def build_cookie_timeline(cookie_key: str, added_cookies: List[Dict], modified_cookies: List[Dict]) -> Dict:
    """
    Construit la timeline complète d'un cookie.
    
    Returns:
        {
            'key': str,
            'events': [(task_id, event_type, metrics), ...],
            'duration_evolution': [values],
            'entropy_evolution': [values],
            'pii_categories': [categories]
        }
    """
    events = []
    
    # Événement added
    for cookie in added_cookies:
        task_id = int(cookie.get('task_id', 0))
        
        # Calculer métriques
        expires = cookie.get('expires', -1)
        if expires > 0:
            now = datetime.now().timestamp()
            duration = (expires - now) / (24 * 3600)
        else:
            duration = 0
        
        value = cookie.get('value', '')
        entropy = pm.calculate_entropy(value)
        
        # Créer pii_category avec format CATEGORY::subcategory
        category = cookie.get('_category', 'unknown')
        subcategory = cookie.get('matched_subcategory', '')
        
        if subcategory:
            pii_category = f"{category}::{subcategory}"
        else:
            pii_category = category
        
        events.append({
            'task_id': task_id,
            'type': 'added',
            'duration': duration,
            'entropy': entropy,
            'pii_category': pii_category,
            'changed_fields': []
        })
    
    # Événements modified
    for cookie in modified_cookies:
        task_id = int(cookie.get('task_id', 0))
        
        # Calculer métriques
        expires = cookie.get('expires', -1)
        if expires > 0:
            now = datetime.now().timestamp()
            duration = (expires - now) / (24 * 3600)
        else:
            duration = 0
        
        value = cookie.get('value', '')
        entropy = pm.calculate_entropy(value)
        
        # Créer pii_category avec format CATEGORY::subcategory
        category = cookie.get('_category', 'unknown')
        subcategory = cookie.get('matched_subcategory', '')
        
        if subcategory:
            pii_category = f"{category}::{subcategory}"
        else:
            pii_category = category
        
        # Champs modifiés
        changed_fields_raw = cookie.get('changed_fields', 'none')
        if isinstance(changed_fields_raw, str):
            if changed_fields_raw and changed_fields_raw != 'none':
                changed_fields = [f.strip() for f in changed_fields_raw.split(',')]
            else:
                changed_fields = []
        else:
            changed_fields = changed_fields_raw if changed_fields_raw else []
        
        events.append({
            'task_id': task_id,
            'type': 'modified',
            'duration': duration,
            'entropy': entropy,
            'pii_category': pii_category,
            'changed_fields': changed_fields
        })
    
    # Trier par task_id
    events.sort(key=lambda x: x['task_id'])
    
    # Extraire évolutions
    duration_evolution = [e['duration'] for e in events]
    entropy_evolution = [e['entropy'] for e in events]
    pii_categories = [e['pii_category'] for e in events]
    
    return {
        'key': cookie_key,
        'events': events,
        'duration_evolution': duration_evolution,
        'entropy_evolution': entropy_evolution,
        'pii_categories': pii_categories,
        'num_modifications': len([e for e in events if e['type'] == 'modified'])
    }


def analyze_lifecycle(added_dir: Path, modified_dir: Path) -> Dict:
    """
    Analyse complète du cycle de vie des cookies.
    """
    print("\n Analyse de Cycle de Vie des Cookies")
    print("=" * 70)
    
    # Charger les cookies
    print("\n Chargement des cookies...")
    added_by_key = load_cookies_by_key(added_dir)
    modified_by_key = load_cookies_by_key(modified_dir)
    
    print(f"   Added: {len(added_by_key)} clés uniques")
    print(f"   Modified: {len(modified_by_key)} clés uniques")
    
    # Identifier les cookies avec cycle de vie complet
    all_keys = set(added_by_key.keys()) | set(modified_by_key.keys())
    cookies_with_modifications = set(added_by_key.keys()) & set(modified_by_key.keys())
    
    print(f"   Total: {len(all_keys)} cookies uniques")
    print(f"   Avec modifications: {len(cookies_with_modifications)} cookies")
    
    # Construire les timelines
    print("\n Construction des timelines...")
    timelines = {}
    
    for key in all_keys:
        added = added_by_key.get(key, [])
        modified = modified_by_key.get(key, [])
        
        if added or modified:
            timeline = build_cookie_timeline(key, added, modified)
            timelines[key] = timeline
    
    print(f"   {len(timelines)} timelines construites")
    
    # Analyser les patterns
    print("\n Analyse des patterns...")
    
    # Métriques globales
    total_cookies = len(timelines)
    cookies_modified = len([t for t in timelines.values() if t['num_modifications'] > 0])
    
    # Évolution durée
    duration_increases = 0
    duration_decreases = 0
    for timeline in timelines.values():
        if len(timeline['duration_evolution']) > 1:
            if timeline['duration_evolution'][-1] > timeline['duration_evolution'][0]:
                duration_increases += 1
            elif timeline['duration_evolution'][-1] < timeline['duration_evolution'][0]:
                duration_decreases += 1
    
    # Évolution entropie
    entropy_increases = 0
    entropy_decreases = 0
    for timeline in timelines.values():
        if len(timeline['entropy_evolution']) > 1:
            if timeline['entropy_evolution'][-1] > timeline['entropy_evolution'][0]:
                entropy_increases += 1
            elif timeline['entropy_evolution'][-1] < timeline['entropy_evolution'][0]:
                entropy_decreases += 1
    
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
        num_mods = timeline['num_modifications']
        if num_mods == 0:
            volatility_dist['stable'] += 1
        elif num_mods <= 2:
            volatility_dist['moderate'] += 1
        else:
            volatility_dist['high'] += 1
    
    # Top cookies modifiés
    top_modified = sorted(
        timelines.values(),
        key=lambda x: x['num_modifications'],
        reverse=True
    )[:50]
    
    return {
        'timelines': timelines,
        'metrics': {
            'total_cookies': total_cookies,
            'cookies_modified': cookies_modified,
            'duration_increases': duration_increases,
            'duration_decreases': duration_decreases,
            'entropy_increases': entropy_increases,
            'entropy_decreases': entropy_decreases,
            'pii_transitions': dict(pii_transitions),
            'volatility_distribution': dict(volatility_dist)
        },
        'top_modified': top_modified
    }


def main():
    """Script principal"""
    # base_dir = Path(__file__).parent.parent
    
    # added_dir = base_dir / 'categorized_cookies' / 'added'
    # modified_dir = base_dir / 'categorized_cookies' / 'modified'
    # output_dir = base_dir / 'analysis' / 'results' / 'lifecycle'

    # ---------------------------------------------------------------------------------

    output_base = Path(__file__).resolve().parent.parent / 'results' 



    base_dir = Path(__file__).resolve().parent.parent / 'data'
    output_base = Path(__file__).resolve().parent.parent / 'results' 

    if not base_dir.exists():
        print(f"Dossier {base_dir} non trouvé")
        return
    users  = ('FR_0017', 'FR_0018', 'FR_0019')
    auth_statuses = ('Auth', 'UnAuth')
    
    policies = ('ALL', 'PARTIAL', 'NONE')

    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:

                # input_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'added'
                added_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'added'
                modified_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'modified'

                output_dir = output_base / auth_status / user / policy / 'cookies'/ 'lifecycle'

                if not added_dir.exists() and not modified_dir.exists():
                    print(f"Le dossier {added_dir} n'existe pas, passage à la configuration suivante.")
                    continue
                # output_added_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'added'
                # output_modified_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'modified'
                
                output_dir.mkdir(parents=True, exist_ok=True)
    
                # Analyser
                results = analyze_lifecycle(added_dir, modified_dir)
                
                # Sauvegarder les résultats
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / 'lifecycle_data.json'
                
                # Convertir pour JSON (exclure les timelines complètes, trop volumineuses)
                serializable_results = {
                    'metrics': {
                        **results['metrics'],
                        'pii_transitions': {f"{k[0]} → {k[1]}": v for k, v in results['metrics']['pii_transitions'].items()}
                    },
                    'num_timelines': len(results['timelines']),
                    'top_modified_keys': [t['key'] for t in results['top_modified'][:20]]
                }
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(serializable_results, f, indent=2, ensure_ascii=False)
                
                print(f"\n Résultats sauvegardés : {output_path}")
                
                # Sauvegarder les timelines complètes (fichier séparé)
                print("\n Sauvegarde des timelines complètes...")
                timelines_output = output_dir / 'consolidated' / 'timelines_complete.json'
                timelines_output.parent.mkdir(parents=True, exist_ok=True)
                
                # Convertir les timelines pour JSON
                timelines_serializable = {}
                for key, timeline in results['timelines'].items():
                    timelines_serializable[key] = {
                        'key': timeline['key'],
                        'num_modifications': timeline['num_modifications'],
                        'events': timeline['events'],
                        'duration_evolution': timeline['duration_evolution'],
                        'entropy_evolution': timeline['entropy_evolution'],
                        'pii_categories': timeline['pii_categories']
                    }
                
                with open(timelines_output, 'w', encoding='utf-8') as f:
                    json.dump(timelines_serializable, f, indent=2, ensure_ascii=False)
                
                print(f"    {len(timelines_serializable)} timelines complètes sauvegardées")
                print(f"   → {timelines_output}")
                print(f"   → Taille: {timelines_output.stat().st_size / 1024 / 1024:.1f} MB")
                
                # Afficher résumé
                print("\n" + "=" * 70)
                print(" RÉSUMÉ")
                print("=" * 70)
                print(f"\nCookies totaux: {results['metrics']['total_cookies']:,}")
                print(f"Cookies modifiés: {results['metrics']['cookies_modified']:,} ({results['metrics']['cookies_modified']/results['metrics']['total_cookies']*100:.1f}%)")
                
                print(f"\n Évolution Durée:")
                print(f"   Augmentation: {results['metrics']['duration_increases']:,}")
                print(f"   Diminution: {results['metrics']['duration_decreases']:,}")
                
                print(f"\n Évolution Entropie:")
                print(f"   Augmentation: {results['metrics']['entropy_increases']:,}")
                print(f"   Diminution: {results['metrics']['entropy_decreases']:,}")
                
                print(f"\n Volatilité:")
                for level, count in results['metrics']['volatility_distribution'].items():
                    print(f"   {level.capitalize()}: {count:,}")
                
                print("\n" + "=" * 70)
                print(" Analyse de cycle de vie terminée!")
                print("=" * 70)
                
                # Générer les visualisations
                print("\n Génération des visualisations...")
                graphs_dir = output_dir / 'graphs'
                graphs_dir.mkdir(parents=True, exist_ok=True)
                
                try:
                    print("  → Graphique 29: Lifecycle Sankey...")
                    lviz.plot_lifecycle_sankey(
                        results['timelines'],
                        graphs_dir / '29_lifecycle_sankey.png',
                        top_n=10  # Ultra-réduit pour clarté maximale
                    )
                    print("   Graphique 29 généré")
                    
                    print("  → Graphique 30: Duration Evolution...")
                    lviz.plot_duration_evolution(
                        results['timelines'],
                        graphs_dir / '30_duration_evolution.png',
                        top_n=15  # Limiter pour lisibilité
                    )
                    print("   Graphique 30 généré")
                    
                    print("  → Graphique 31: Entropy Evolution...")
                    lviz.plot_entropy_evolution(
                        results['timelines'],
                        graphs_dir / '31_entropy_evolution.png',
                        top_n=15  # Limiter pour lisibilité
                    )
                    print("   Graphique 31 généré")
                    
                    print("  → Graphique 32: PII Transition Matrix...")
                    lviz.plot_pii_transition_matrix(
                        results['timelines'],
                        graphs_dir / '32_pii_transition_matrix.png'
                    )
                    print("   Graphique 32 généré")
                    
                    print("  → Graphique 33: Activity Heatmap...")
                    lviz.plot_activity_heatmap(
                        results['timelines'],
                        graphs_dir / '33_activity_heatmap.png',
                        top_n=30  # Limiter pour lisibilité
                    )
                    print("   Graphique 33 généré")
                    
                    print(f"\n 5 graphiques générés dans {graphs_dir}")
                except Exception as e:
                    print(f"\n Erreur lors de la génération des graphiques: {e}")
                    import traceback
                    traceback.print_exc()


if __name__ == '__main__':
    main()
