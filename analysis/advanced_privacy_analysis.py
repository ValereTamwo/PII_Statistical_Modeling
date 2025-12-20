#!/usr/bin/env python3
"""
Script d'analyse vie privée avancée par catégorie.
Génère 6 graphiques orientés RGPD en complément des 16 graphiques techniques.

Axes d'analyse :
1. Introspection Profonde (contenu décodé)
2. Fuite de Données (vendors)
3. Indice de Traçabilité (entropie)
4. Matrice de Risque Affinée (avec entropie)
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List

# Imports des modules d'analyse
sys.path.insert(0, str(Path(__file__).parent))
import privacy_metrics as pm
import advanced_visualizations as aviz


def load_categorized_cookies(category_file: Path) -> List[Dict]:
    """Charge les cookies d'une catégorie"""
    with open(category_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def analyze_privacy_category(cookies: List[Dict], category_name: str) -> Dict:
    """
    Analyse vie privée complète d'une catégorie.
    
    Returns:
        Dictionnaire avec toutes les métriques vie privée
    """
    print(f"\n Analyse vie privée: {category_name}")
    print(f"   {len(cookies)} cookies\n")
    
    # Structures de données
    content_hierarchy = defaultdict(lambda: defaultdict(int))  # {data_type: {subcategory: count}}
    content_types = Counter()
    vendor_counts = Counter()
    category_vendor_flows = []  # [(category, vendor, count)]
    entropy_lifetime_data = []  # [(entropy, lifetime_days, data_type)]
    entropy_by_subcat = defaultdict(list)
    
    # Métriques de risque affinées
    advanced_risk_levels = Counter()
    
    # Analyser chaque cookie
    for cookie in cookies:
        # Analyse vie privée complète
        privacy_analysis = pm.analyze_cookie_privacy(cookie)
        
        # Axe 1: Introspection Profonde
        data_type = privacy_analysis['data_type']
        subcategory = cookie.get('matched_subcategory', 'unknown')
        content_hierarchy[data_type][subcategory] += 1
        content_types[data_type] += 1
        
        # Axe 2: Fuite de Données
        vendor = privacy_analysis['vendor']
        vendor_counts[vendor] += 1
        
        # Flux catégorie → vendor (pour Sankey)
        category_vendor_flows.append((subcategory, vendor, 1))
        
        # Axe 3: Indice de Traçabilité
        entropy = privacy_analysis['entropy']
        expires = cookie.get('expires', -1)
        if expires > 0:
            now = datetime.now().timestamp()
            lifetime_days = (expires - now) / (24 * 3600)
        else:
            lifetime_days = 0  # Session cookie
        
        entropy_lifetime_data.append((entropy, lifetime_days, data_type))
        entropy_by_subcat[subcategory].append(entropy)
        
        # Axe 4: Matrice de Risque Affinée (avec entropie)
        is_high_entropy = entropy > 4.0
        is_persistent = lifetime_days > 365
        is_third_party = pm.is_third_party(cookie.get('domain', ''), cookie.get('initial_url', ''))
        is_httponly_false = not cookie.get('httpOnly', False)
        
        # Nouvelle formule de risque
        if is_high_entropy and is_third_party and is_persistent:
            risk_level = 'Critical'  # Super Tracker
        elif is_high_entropy and is_httponly_false:
            risk_level = 'High'  # Volable + Unique
        elif is_high_entropy or (is_third_party and is_persistent):
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        advanced_risk_levels[risk_level] += 1
    
    # Agréger les flux pour Sankey
    flow_aggregated = defaultdict(int)
    for cat, vendor, count in category_vendor_flows:
        flow_aggregated[(cat, vendor)] += count
    
    category_vendor_flows_agg = [(cat, vendor, count) for (cat, vendor), count in flow_aggregated.items()]
    
    return {
        'category_name': category_name,
        'total_cookies': len(cookies),
        'content_hierarchy': {k: dict(v) for k, v in content_hierarchy.items()},
        'content_types': dict(content_types),
        'vendor_counts': dict(vendor_counts),
        'category_vendor_flows': category_vendor_flows_agg,
        'entropy_lifetime_data': entropy_lifetime_data,
        'entropy_by_subcategory': {k: v for k, v in entropy_by_subcat.items()},
        'advanced_risk_levels': dict(advanced_risk_levels)
    }


def generate_privacy_visualizations(analysis_results: Dict, output_dir: Path):
    """Génère les 6 graphiques vie privée"""
    category_name = analysis_results['category_name']
    graphs_dir = output_dir / category_name / 'privacy_graphs'
    graphs_dir.mkdir(parents=True, exist_ok=True)
    
    print(f" Génération des graphiques vie privée pour {category_name}...\n")
    
    # Graphique 17: Sunburst - Hiérarchie des contenus
    if analysis_results['content_hierarchy']:
        print(f"   Graphique 17: Content Hierarchy (Sunburst)")
        aviz.plot_content_sunburst(
            analysis_results['content_hierarchy'],
            graphs_dir / '17_content_sunburst.png'
        )
    
    # Graphique 18: Distribution des types de contenu
    if analysis_results['content_types']:
        print(f"   Graphique 18: Content Types Distribution")
        aviz.plot_content_types_distribution(
            analysis_results['content_types'],
            graphs_dir / '18_content_types.png'
        )
    
    # Graphique 19: Sankey - Flux vers vendors
    if analysis_results['category_vendor_flows']:
        print(f"   Graphique 19: Data Flow to Vendors (Sankey)")
        aviz.plot_vendor_sankey(
            analysis_results['category_vendor_flows'],
            graphs_dir / '19_vendor_sankey.png'
        )
    
    # Graphique 20: Top vendors
    if analysis_results['vendor_counts']:
        print(f"   Graphique 20: Top Vendors Receiving PII")
        aviz.plot_top_vendors(
            analysis_results['vendor_counts'],
            graphs_dir / '20_top_vendors.png'
        )
    
    # Graphique 21: Scatter - Entropie × Durée
    if analysis_results['entropy_lifetime_data']:
        print(f"   Graphique 21: Entropy × Lifetime (Scatter)")
        aviz.plot_entropy_scatter(
            analysis_results['entropy_lifetime_data'],
            graphs_dir / '21_entropy_scatter.png'
        )
    
    # Graphique 22: Distribution entropie par sous-catégorie
    if analysis_results['entropy_by_subcategory']:
        print(f"   Graphique 22: Entropy Distribution by PII Type")
        aviz.plot_entropy_distribution(
            analysis_results['entropy_by_subcategory'],
            graphs_dir / '22_entropy_distribution.png'
        )
    
    print(f"\n 6 graphiques vie privée générés dans {graphs_dir}")


def save_privacy_analysis(analysis_results: Dict, output_path: Path):
    """Sauvegarde les résultats de l'analyse vie privée"""
    # Convertir les données non-sérialisables
    serializable_results = {
        'category_name': analysis_results['category_name'],
        'total_cookies': analysis_results['total_cookies'],
        'content_hierarchy': analysis_results['content_hierarchy'],
        'content_types': analysis_results['content_types'],
        'vendor_counts': analysis_results['vendor_counts'],
        'advanced_risk_levels': analysis_results['advanced_risk_levels'],
        'entropy_stats': {
            'by_subcategory': {
                k: {
                    'mean': sum(v) / len(v) if v else 0,
                    'max': max(v) if v else 0,
                    'min': min(v) if v else 0
                }
                for k, v in analysis_results['entropy_by_subcategory'].items()
            }
        }
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(serializable_results, f, indent=2, ensure_ascii=False)


def main():
    """Script principal"""
    base_dir = Path(__file__).parent.parent
    input_dir = base_dir / 'categorized_cookies' / 'added'
    output_dir = base_dir / 'analysis' / 'results' / 'added' / 'by_category'
    
    print("=" * 70)
    print("ANALYSE VIE PRIVÉE AVANCÉE - COOKIES ADDED")
    print("=" * 70)
    
    # Trouver tous les fichiers JSON de catégories
    category_files = sorted(input_dir.glob('*.json'))
    
    if not category_files:
        print(f" Aucun fichier trouvé dans {input_dir}")
        return
    
    print(f"\n {len(category_files)} catégories trouvées\n")
    
    # Analyser chaque catégorie
    for category_file in category_files:
        category_name = category_file.stem
        
        try:
            # Charger les cookies
            cookies = load_categorized_cookies(category_file)
            
            if not cookies:
                print(f"️  {category_name}: Aucun cookie")
                continue
            
            # Analyser
            analysis_results = analyze_privacy_category(cookies, category_name)
            
            # Sauvegarder les résultats
            output_path = output_dir / category_name / 'privacy_analysis.json'
            output_path.parent.mkdir(parents=True, exist_ok=True)
            save_privacy_analysis(analysis_results, output_path)
            print(f" Résultats sauvegardés : {output_path}")
            
            # Générer les visualisations
            generate_privacy_visualizations(analysis_results, output_dir)
            
            print("\n" + "-" * 70 + "\n")
            
        except Exception as e:
            print(f" Erreur lors de l'analyse de {category_name}: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    print("\n" + "=" * 70)
    print(" Analyse vie privée terminée avec succès!")
    print("=" * 70)


if __name__ == '__main__':
    main()
