#!/usr/bin/env python3
"""
Script d'analyse consolidée pour les stockages web (localStorage, sessionStorage, IndexedDB).

Adapté de l'analyse des cookies, mais sans les attributs de sécurité spécifiques aux cookies
(HttpOnly, Secure, SameSite) qui n'existent pas pour les autres types de stockage.

Focus RGPD :
- Quantification des données personnelles par catégorie
- Analyse du cycle de vie et de la persistance
- Analyse des modifications (added/modified/deleted)
- Calcul des risques RGPD basés sur le contenu et la durée de vie
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

# Imports des modules d'analyse
sys.path.insert(0, str(Path(__file__).parent.parent))
import analysis.privacy_metrics as pm
import analysis.storage_analysis.storage_visualizations as sviz


def load_all_storage_items(input_dir: Path, storage_type: str) -> Tuple[List[Dict], List[Dict]]:
    """
    Charge tous les items de stockage et les sépare en 2 groupes.
    
    Args:
        input_dir: Répertoire contenant les fichiers JSON catégorisés
        storage_type: Type de stockage ('localstorage', 'sessionstorage', 'indexeddb')
    
    Returns:
        (direct_pii_items, other_items)
    """
    direct_pii_items = []
    other_items = []
    
    category_files = sorted(input_dir.glob('*.json'))
    
    for category_file in category_files:
        category_name = category_file.stem
        
        with open(category_file, 'r', encoding='utf-8') as f:
            items = json.load(f)
        
        # Ajouter le nom de catégorie et le type de stockage à chaque item
        for item in items:
            item['_category'] = category_name
            item['_storage_type'] = storage_type
        
        # Séparer DIRECT_PII des autres
        if category_name == 'DIRECT_PII':
            direct_pii_items.extend(items)
        else:
            other_items.extend(items)
    
    return direct_pii_items, other_items


def create_unified_pii_type(item: Dict) -> str: 

    """
    Super Important: 
    Crée un type de PII unifié pour un item de stockage.
    
    - Si DIRECT_PII : retourne la sous-catégorie (email, gender, etc.)
    - Sinon : retourne le nom de catégorie (BEHAVIORAL_DATA, etc.)
    """
    category = item.get('_category', 'unknown')
    
    if category == 'DIRECT_PII':
        # Utiliser la sous-catégorie du premier match
        matches = item.get('matches', [])
        if matches and len(matches) > 0:
            return matches[0].get('subcategory', 'unknown')
        return 'unknown'
    else:
        # Utiliser le nom de catégorie
        return category


def calculate_storage_size(item: Dict) -> int:
    """
    // tres important car permet d'estimer la quantité de données stockées par rapport a la taille par defaut du cookie
    Calcule la taille approximative d'un item de stockage en bytes.
    """
    value = item.get('value', '')
    name = item.get('name', '')
    
    # Taille approximative : nom + valeur en UTF-8
    return len(str(name).encode('utf-8')) + len(str(value).encode('utf-8'))


def get_persistence_type(storage_type: str) -> str:
    """
    Retourne le type de persistance selon le type de stockage.
    """
    persistence_map = {
        'localstorage': 'Persistent',
        'indexeddb': 'Persistent',
        'sessionstorage': 'Session'
    }
    return persistence_map.get(storage_type.lower(), 'Unknown')


def analyze_storage_consolidated(direct_pii_items: List[Dict], other_items: List[Dict], 
                                 storage_type: str) -> Dict:
    """
    Analyse consolidée de tous les items de stockage.
    
    Args:
        direct_pii_items: Items contenant des PII directes
        other_items: Autres items
        storage_type: Type de stockage analysé
    """
    all_items = direct_pii_items + other_items
    total = len(all_items)
    
    print(f"\n📊 Analyse Consolidée - {storage_type.upper()}")
    print(f"   DIRECT_PII: {len(direct_pii_items)} items")
    print(f"   Autres: {len(other_items)} items")
    print(f"   TOTAL: {total} items\n")
    
    # Structures de données pour les métriques
    pii_distribution = Counter()
    pii_by_category = defaultdict(Counter)
    
    persistence_dist = Counter()
    persistence_by_pii = defaultdict(Counter)
    
    size_by_pii = defaultdict(list)
    total_size_by_pii = defaultdict(int)
    
    content_hierarchy = defaultdict(lambda: defaultdict(int))
    content_types = Counter()
    vendor_counts = Counter()
    category_vendor_flows = []
    
    entropy_data = []
    entropy_by_pii = defaultdict(list)
    
    risk_levels = Counter()
    risk_by_pii = defaultdict(Counter)
    
    # Analyser chaque item
    for item in all_items:
        # Type de PII unifié
        pii_type = create_unified_pii_type(item)
        pii_distribution[pii_type] += 1
        
        category = item.get('_category', 'unknown')
        pii_by_category[category][pii_type] += 1
        
        # Persistance
        persistence = get_persistence_type(storage_type)
        persistence_dist[persistence] += 1
        persistence_by_pii[pii_type][persistence] += 1
        
        # Taille
        size = calculate_storage_size(item)
        size_by_pii[pii_type].append(size)
        total_size_by_pii[pii_type] += size
        
        # Analyse vie privée
        value = item.get('value', '')
        
        # Calcul de l'entropie
        entropy = pm.calculate_entropy(str(value))
        entropy_data.append((entropy, pii_type))
        entropy_by_pii[pii_type].append(entropy)
        
        # Décodage et type de données
        decoded_value, decode_method, decode_success = pm.decode_value(str(value))
        data_type = pm.detect_data_type(str(value), decoded_value if decode_success else None)
        
        content_hierarchy[data_type][pii_type] += 1
        content_types[data_type] += 1
        
        # Vendor (basé sur source_file ou field_path)
        source_file = item.get('source_file', '')
        if source_file:
            # Extraire le domaine du nom de fichier
            # Ex: "https_www.youtube.com_0.indexeddb.leveldb.json" -> "youtube.com"
            domain_match = source_file.replace('https_', '').replace('http_', '').split('_')[0:3]
            domain = '.'.join(domain_match).replace('.json', '')
            vendor = pm.extract_vendor_from_domain(domain)
        else:
            vendor = 'Unknown'
        
        vendor_counts[vendor] += 1
        category_vendor_flows.append((pii_type, vendor, 1))
        
        # Calcul du risque RGPD UNIFIÉ
        from analysis.unified_risk_metrics import calculate_unified_risk_score
        
        # Calculer le score de risque unifié
        risk_result = calculate_unified_risk_score(item, storage_type)
        
        # Stocker les résultats détaillés dans l'item
        item['_unified_risk'] = risk_result
        
        # Extraire catégorie et score
        risk_level = risk_result['risk_category']
        total_score = risk_result['total_score']
        
        # Agréger les statistiques
        risk_levels[risk_level] += 1
        risk_by_pii[pii_type][risk_level] += 1
    
    # Agréger les flux pour Sankey
    flow_aggregated = defaultdict(int)
    for cat, vendor, count in category_vendor_flows:
        flow_aggregated[(cat, vendor)] += count
    category_vendor_flows_agg = [(cat, vendor, count) for (cat, vendor), count in flow_aggregated.items()]
    
    return {
        'storage_type': storage_type,
        'total_items': total,
        'direct_pii_count': len(direct_pii_items),
        'other_count': len(other_items),
        
        # Distribution PII
        'pii_distribution': dict(pii_distribution),
        'pii_by_category': {k: dict(v) for k, v in pii_by_category.items()},
        
        # Persistance
        'persistence_distribution': dict(persistence_dist),
        'persistence_by_pii': {k: dict(v) for k, v in persistence_by_pii.items()},
        
        # Taille
        'size_by_pii': {k: {'total': total_size_by_pii[k], 
                            'average': total_size_by_pii[k] / len(v) if v else 0,
                            'count': len(v)} 
                        for k, v in size_by_pii.items()},
        
        # Vie privée
        'content_hierarchy': {k: dict(v) for k, v in content_hierarchy.items()},
        'content_types': dict(content_types),
        'vendor_counts': dict(vendor_counts),
        'category_vendor_flows': category_vendor_flows_agg,
        'entropy_by_pii': {k: v for k, v in entropy_by_pii.items()},
        
        # Risques
        'risk_levels': dict(risk_levels),
        'risk_by_pii': {k: dict(v) for k, v in risk_by_pii.items()},
    }


def main():
    """Script principal"""
    # Le script est dans analysis/storage_analysis/, donc parent.parent.parent pour atteindre la racine
    base_dir = Path(__file__).resolve().parent.parent.parent / 'data'
    output_base = Path(__file__).resolve().parent.parent.parent / 'results'
    
    if not base_dir.exists():
        print(f"❌ Dossier {base_dir} non trouvé")
        return
    
    users = ('FR_0017', 'FR_0018', 'FR_0019')
    auth_statuses = ('Auth', 'UnAuth')
    policies = ('ALL', 'PARTIAL', 'NONE')
    storage_types = ('localstorage', 'sessionstorage', 'indexeddb')
    
    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                for storage_type in storage_types:
                    storage_base_dir = base_dir / 'user' / auth_status / user / policy / storage_type
                    
                    if not storage_base_dir.exists():
                        continue
                    
                    # Traiter added, modified, removed
                    for lifecycle in ['added', 'modified', 'removed']:
                        input_dir = storage_base_dir / lifecycle
                        
                        # Mapper 'removed' vers 'deleted' pour la sortie
                        output_lifecycle = 'deleted' if lifecycle == 'removed' else lifecycle
                        output_dir = output_base / auth_status / user / policy / storage_type / output_lifecycle
                        
                        # Vérifier si le dossier lifecycle existe
                        if not input_dir.exists():
                            # Pour indexeddb, pas de sous-dossiers lifecycle
                            if lifecycle == 'added' and storage_type == 'indexeddb' and storage_base_dir.exists():
                                input_dir = storage_base_dir
                            else:
                                continue
                        
                        # Vérifier s'il y a des fichiers JSON
                        if not any(input_dir.glob('*.json')):
                            continue
                        
                        output_dir.mkdir(parents=True, exist_ok=True)
                        
                        # Charger tous les items
                        print(f"\n{'='*70}")
                        print(f"📊 Configuration: {user} / {auth_status} / {policy} / {storage_type} / {lifecycle}")
                        print(f"{'='*70}")
                        
                        direct_pii_items, other_items = load_all_storage_items(input_dir, storage_type)
                        
                        if len(direct_pii_items) == 0 and len(other_items) == 0:
                            print(f"  Aucun item trouvé, passage.")
                            continue
                        
                        # Analyser
                        analysis_results = analyze_storage_consolidated(
                            direct_pii_items, other_items, storage_type
                        )
                        
                        # Sauvegarder les résultats
                        output_path = output_dir / 'consolidated' / 'analysis.json'
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        with open(output_path, 'w', encoding='utf-8') as f:
                            json.dump(analysis_results, f, indent=2, ensure_ascii=False)
                        
                        print(f"✓ Résultats sauvegardés : {output_path}")
                        
                        # Générer les visualisations
                        sviz.generate_all_visualizations(analysis_results, output_dir, storage_type)
                        
                        print(f"\n✓ Analyse {lifecycle} terminée!")
    
    print("\n" + "=" * 70)
    print("✅ Analyse consolidée des stockages terminée avec succès!")
    print("=" * 70)



if __name__ == '__main__':
    main()
