#!/usr/bin/env python3
"""
Script d'analyse consolidée pour cookies MODIFIED - Approche mixte.

Stratégie :
- DIRECT_PII : Analysé par sous-catégories (email, gender, phone, etc.)
- Autres catégories : Analysées comme types de PII (BEHAVIORAL_DATA, IDENTITY_TRACKING, etc.)

Résultat : 28 graphiques pour TOUS les cookies modified.
- 22 graphiques standards (techniques + vie privée)
- 6 graphiques spécifiques aux changements
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

# Imports des modules d'analyse
sys.path.insert(0, str(Path(__file__).parent))
import privacy_metrics as pm
import visualizations as viz
import advanced_visualizations as aviz
import change_visualizations as cviz  
from analyze_by_category import (
    calculate_lifetime_category,
    normalize_samesite,
    extract_keywords,
    is_third_party
)


def load_all_cookies(input_dir: Path) -> Tuple[List[Dict], List[Dict]]:
    """
    Charge tous les cookies et les sépare en 2 groupes.
    
    Returns:
        (direct_pii_cookies, other_cookies)
    """
    direct_pii_cookies = []
    other_cookies = []
    
    category_files = sorted(input_dir.glob('*.json'))
    
    for category_file in category_files:
        category_name = category_file.stem
        
        with open(category_file, 'r', encoding='utf-8') as f:
            cookies = json.load(f)
        
        # Ajouter le nom de catégorie à chaque cookie
        for cookie in cookies:
            cookie['_category'] = category_name
        
        # Séparer DIRECT_PII des autres
        if category_name == 'DIRECT_PII':
            direct_pii_cookies.extend(cookies)
        else:
            other_cookies.extend(cookies)
    
    return direct_pii_cookies, other_cookies


def create_unified_pii_type(cookie: Dict) -> str:
    """
    Crée un type de PII unifié pour un cookie.
    
    - Si DIRECT_PII : retourne la sous-catégorie (email, gender, etc.)
    - Sinon : retourne le nom de catégorie (BEHAVIORAL_DATA, etc.)
    """
    category = cookie.get('_category', 'unknown')
    
    if category == 'DIRECT_PII':
        # Utiliser la sous-catégorie
        return cookie.get('matched_subcategory', 'unknown')
    else:
        # Utiliser le nom de catégorie
        return category


def analyze_consolidated(direct_pii_cookies: List[Dict], other_cookies: List[Dict]) -> Dict:
    """
    Analyse consolidée de tous les cookies.
    """
    all_cookies = direct_pii_cookies + other_cookies
    total = len(all_cookies)
    
    print(f"\n Analyse Consolidée")
    print(f"   DIRECT_PII: {len(direct_pii_cookies)} cookies")
    print(f"   Autres: {len(other_cookies)} cookies")
    print(f"   TOTAL: {total} cookies\n")
    
    # Structures de données pour les 16 graphiques techniques
    lifetime_dist = Counter()
    lifetime_by_pii = defaultdict(Counter)
    
    httponly_dist = Counter()
    httponly_by_pii = defaultdict(Counter)
    
    secure_dist = Counter()
    secure_by_pii = defaultdict(Counter)
    
    samesite_dist = Counter()
    samesite_by_pii = defaultdict(Counter)
    
    security_matrix = Counter()
    security_by_pii = defaultdict(Counter)
    
    thirdparty_dist = Counter()
    thirdparty_by_pii = defaultdict(Counter)
    thirdparty_httponly = Counter()
    thirdparty_secure = Counter()
    
    risk_levels = Counter()
    risk_by_pii = defaultdict(Counter)
    
    all_keywords = Counter()
    
    # Structures pour les 6 graphiques vie privée
    content_hierarchy = defaultdict(lambda: defaultdict(int))
    content_types = Counter()
    vendor_counts = Counter()
    category_vendor_flows = []
    entropy_lifetime_data = []
    entropy_by_pii = defaultdict(list)
    advanced_risk_levels = Counter()
    
    # Structures pour les changements (MODIFIED spécifique)
    changed_fields_dist = Counter()
    num_changes_dist = Counter()
    duration_changes = []  # [(duration_before, duration_after, pii_type)]
    entropy_changes = []  # [(entropy_before, entropy_after, pii_type)]
    changes_by_pii = defaultdict(Counter)
    modifications_timeline = Counter()  # {task_id: count}
    
    # Analyser chaque cookie
    for cookie in all_cookies:
        # Type de PII unifié
        pii_type = create_unified_pii_type(cookie)
        
        # === ANALYSE TECHNIQUE (16 graphiques) ===
        
        # Durée de vie (utiliser le timestamp de collecte si disponible)
        collection_timestamp = cookie.get('timestamp')
        # Convertir le timestamp si c'est une chaîne
        if isinstance(collection_timestamp, str):
            try:
                # Essayer de parser comme ISO format
                collection_timestamp = datetime.fromisoformat(collection_timestamp.replace('Z', '+00:00')).timestamp()
            except:
                try:
                    # Essayer comme timestamp numérique en chaîne
                    collection_timestamp = float(collection_timestamp)
                except:
                    collection_timestamp = None
        
        lifetime_cat = calculate_lifetime_category(cookie.get('expires', -1), collection_timestamp)
        lifetime_dist[lifetime_cat] += 1
        lifetime_by_pii[pii_type][lifetime_cat] += 1
        
        # HttpOnly
        http_only = cookie.get('httpOnly', False)
        httponly_dist[str(http_only)] += 1
        httponly_by_pii[pii_type][str(http_only)] += 1
        
        # Secure
        secure = cookie.get('secure', False)
        secure_dist[str(secure)] += 1
        secure_by_pii[pii_type][str(secure)] += 1
        
        # SameSite
        samesite = normalize_samesite(cookie.get('sameSite'))
        samesite_dist[samesite] += 1
        samesite_by_pii[pii_type][samesite] += 1
        
        # Matrice de sécurité
        security_matrix[(http_only, secure)] += 1
        
        # Score de sécurité
        if not http_only and not secure:
            security_score = 'Lowly Secure'
        elif http_only and secure:
            security_score = 'Secure'
        else:
            security_score = 'Partially Secure'
        security_by_pii[pii_type][security_score] += 1
        
        # Third-party
        is_tp = is_third_party(cookie.get('domain', ''), cookie.get('initial_url', ''))
        tp_status = 'Third-Party' if is_tp else 'First-Party'
        thirdparty_dist[tp_status] += 1
        thirdparty_by_pii[pii_type][tp_status] += 1
        thirdparty_httponly[(tp_status, http_only)] += 1
        thirdparty_secure[(tp_status, secure)] += 1
        
        # Risque RGPD UNIFIÉ
        from unified_risk_metrics import calculate_unified_risk_score
        
        # Préparer l'item (ajouter _category si manquant)
        cookie_item = cookie.copy()
        if '_category' not in cookie_item:
            cookie_item['_category'] = cookie.get('category', 'UNCATEGORIZED')
        
        # Calculer le score de risque unifié
        risk_result = calculate_unified_risk_score(cookie_item, 'cookies')
        
        # Stocker les résultats détaillés
        cookie['_unified_risk'] = risk_result
        
        # Extraire catégorie de risque
        risk_level = risk_result['risk_category']
        
        risk_levels[risk_level] += 1
        risk_by_pii[pii_type][risk_level] += 1
        
        # Mots-clés
        keywords = extract_keywords(cookie.get('name', ''))
        all_keywords.update(keywords)
        
        # === ANALYSE VIE PRIVÉE (6 graphiques) ===
        
        privacy_analysis = pm.analyze_cookie_privacy(cookie)
        
        data_type = privacy_analysis['data_type']
        content_hierarchy[data_type][pii_type] += 1
        content_types[data_type] += 1
        
        vendor = privacy_analysis['vendor']
        vendor_counts[vendor] += 1
        category_vendor_flows.append((pii_type, vendor, 1))
        
        entropy = privacy_analysis['entropy']
                # Calculer duration_days à partir du champ 'expires' si disponible (supporte timestamp et ISO/str)
        expires_val = cookie.get('expires', None)
        if isinstance(expires_val, (int, float)):
            try:
                duration_days = max(int((datetime.fromtimestamp(expires_val) - datetime.now()).total_seconds() / 86400), 0)
            except Exception:
                duration_days = -1
        elif isinstance(expires_val, str):
            try:
                # Essayer ISO format first
                exp_dt = datetime.fromisoformat(expires_val)
                duration_days = max(int((exp_dt - datetime.now()).total_seconds() / 86400), 0)
            except Exception:
                try:
                    # Essayer une chaîne numérique représentant un timestamp
                    exp_ts = int(expires_val)
                    duration_days = max(int((datetime.fromtimestamp(exp_ts) - datetime.now()).total_seconds() / 86400), 0)
                except Exception:
                    duration_days = -1
        else:
            duration_days = -1
        entropy_lifetime_data.append((entropy, duration_days, data_type))
        entropy_by_pii[pii_type].append(entropy)
        
        # Risque avancé (avec entropie)
        is_high_entropy = entropy > 4.0
        if is_high_entropy and is_tp and duration_days > 365:
            adv_risk = 'Critical'
        elif is_high_entropy and not http_only:
            adv_risk = 'High'
        elif is_high_entropy or (is_tp and duration_days > 365):
            adv_risk = 'Medium'
        else:
            adv_risk = 'Low'
        advanced_risk_levels[adv_risk] += 1
        
        # === MÉTRIQUES DE CHANGEMENT (MODIFIED spécifique) ===
        
        # Champs modifiés
        changed_fields_raw = cookie.get('changed_fields', 'none')
        if isinstance(changed_fields_raw, str):
            # Si c'est une string, splitter par virgule
            if changed_fields_raw and changed_fields_raw != 'none':
                changed_fields = [f.strip() for f in changed_fields_raw.split(',')]
            else:
                changed_fields = []
        else:
            # Si c'est déjà une liste
            changed_fields = changed_fields_raw if changed_fields_raw else []
        
        for field in changed_fields:
            changed_fields_dist[field] += 1
            changes_by_pii[pii_type][field] += 1
        
        # Nombre de changements
        num_changes = cookie.get('num_changes', len(changed_fields))
        num_changes_dist[num_changes] += 1
        
        # Changement de durée
        duration_change_days = cookie.get('duration_change_days', 0)
        try:
            duration_change_days = float(duration_change_days) if duration_change_days else 0
        except (ValueError, TypeError):
            duration_change_days = 0
            
        if duration_change_days != 0:
            # Calculer durée avant et après
            expires_to = cookie.get('expires', -1)
            if expires_to > 0:
                now = datetime.now().timestamp()
                duration_after = (expires_to - now) / (24 * 3600)
                duration_before = duration_after - duration_change_days
                duration_changes.append((duration_before, duration_after, pii_type))
        
        # Changement d'entropie
        value_from = cookie.get('value_from', '')
        value_to = cookie.get('value_to', cookie.get('value', ''))
        if value_from and value_to:
            entropy_before = pm.calculate_entropy(value_from)
            entropy_after = pm.calculate_entropy(value_to)
            entropy_changes.append((entropy_before, entropy_after, pii_type))
        
        # Timeline
        task_id = cookie.get('task_id', 'unknown')
        modifications_timeline[task_id] += 1
        
        # Mots-clés
        keywords = extract_keywords(cookie.get('name', ''))
        all_keywords.update(keywords)
    
    # Agréger les flux pour Sankey
    flow_aggregated = defaultdict(int)
    for cat, vendor, count in category_vendor_flows:
        flow_aggregated[(cat, vendor)] += count
    category_vendor_flows_agg = [(cat, vendor, count) for (cat, vendor), count in flow_aggregated.items()]
    
    return {
        'total_cookies': total,
        'direct_pii_count': len(direct_pii_cookies),
        'other_count': len(other_cookies),
        
        # Technique
        'lifetime_distribution': dict(lifetime_dist),
        'lifetime_by_pii': {k: dict(v) for k, v in lifetime_by_pii.items()},
        'httponly_distribution': dict(httponly_dist),
        'httponly_by_pii': {k: dict(v) for k, v in httponly_by_pii.items()},
        'secure_distribution': dict(secure_dist),
        'secure_by_pii': {k: dict(v) for k, v in secure_by_pii.items()},
        'samesite_distribution': dict(samesite_dist),
        'samesite_by_pii': {k: dict(v) for k, v in samesite_by_pii.items()},
        'security_matrix': {str(k): v for k, v in security_matrix.items()},
        'security_by_pii': {k: dict(v) for k, v in security_by_pii.items()},
        'thirdparty_distribution': dict(thirdparty_dist),
        'thirdparty_by_pii': {k: dict(v) for k, v in thirdparty_by_pii.items()},
        'thirdparty_httponly': {f"{k[0]}_{k[1]}": v for k, v in thirdparty_httponly.items()},
        'thirdparty_secure': {f"{k[0]}_{k[1]}": v for k, v in thirdparty_secure.items()},
        'risk_levels': dict(risk_levels),
        'risk_by_pii': {k: dict(v) for k, v in risk_by_pii.items()},
        'keywords': dict(all_keywords.most_common(15)),
        
        # Vie privée
        'content_hierarchy': {k: dict(v) for k, v in content_hierarchy.items()},
        'content_types': dict(content_types),
        'vendor_counts': dict(vendor_counts),
        'category_vendor_flows': category_vendor_flows_agg,
        'entropy_lifetime_data': entropy_lifetime_data,
        'entropy_by_pii': {k: v for k, v in entropy_by_pii.items()},
        'advanced_risk_levels': dict(advanced_risk_levels),
        
        # Changements (MODIFIED spécifique)
        'changed_fields_distribution': dict(changed_fields_dist),
        'num_changes_distribution': dict(num_changes_dist),
        'duration_changes': duration_changes,
        'entropy_changes': entropy_changes,
        'changes_by_pii': {k: dict(v) for k, v in changes_by_pii.items()},
        'modifications_timeline': dict(modifications_timeline)
    }


def generate_all_visualizations(analysis_results: Dict, output_dir: Path):
    """Génère les 22 graphiques consolidés"""
    graphs_dir = output_dir / 'consolidated' / 'graphs'
    graphs_dir.mkdir(parents=True, exist_ok=True)
    
    privacy_graphs_dir = output_dir / 'consolidated' / 'privacy_graphs'
    privacy_graphs_dir.mkdir(parents=True, exist_ok=True)
    
    print(f" Génération des 22 graphiques consolidés...\n")
    
    # === 16 GRAPHIQUES TECHNIQUES ===
    
    print(" Graphiques techniques (1-16)...")
    
    # 1-2: Durées de vie
    viz.plot_lifetime_distribution(
        analysis_results['lifetime_distribution'],
        graphs_dir / '01_lifetime_distribution.png'
    )
    viz.plot_lifetime_by_pii_type(
        analysis_results['lifetime_by_pii'],
        graphs_dir / '02_lifetime_by_pii_type.png'
    )
    
    # 3-4: HttpOnly
    viz.plot_httponly_distribution(
        analysis_results['httponly_distribution'],
        graphs_dir / '03_httponly_distribution.png'
    )
    viz.plot_httponly_by_pii_type(
        analysis_results['httponly_by_pii'],
        graphs_dir / '04_httponly_by_pii_type.png'
    )
    
    # 5-6: Secure
    viz.plot_secure_distribution(
        analysis_results['secure_distribution'],
        graphs_dir / '05_secure_distribution.png'
    )
    viz.plot_secure_by_pii_type(
        analysis_results['secure_by_pii'],
        graphs_dir / '06_secure_by_pii_type.png'
    )
    
    # 7-8: SameSite
    viz.plot_samesite_distribution(
        analysis_results['samesite_distribution'],
        graphs_dir / '07_samesite_distribution.png'
    )
    viz.plot_samesite_by_pii_type(
        analysis_results['samesite_by_pii'],
        graphs_dir / '08_samesite_by_pii_type.png'
    )
    
    # 9-10: Sécurité
    matrix_data = {eval(k): v for k, v in analysis_results['security_matrix'].items()}
    viz.plot_security_matrix(
        matrix_data,
        graphs_dir / '09_security_matrix.png'
    )
    viz.plot_security_posture(
        analysis_results['security_by_pii'],
        graphs_dir / '10_security_posture.png'
    )
    
    # 11: Mots-clés
    viz.plot_keyword_frequency(
        Counter(analysis_results['keywords']),
        graphs_dir / '11_keyword_frequency.png',
        top_n=15
    )
    
    # 12-15: Third-party
    viz.plot_thirdparty_distribution(
        analysis_results['thirdparty_distribution'],
        graphs_dir / '12_thirdparty_distribution.png'
    )
    viz.plot_thirdparty_by_subcategory(
        analysis_results['thirdparty_by_pii'],
        graphs_dir / '13_thirdparty_by_pii.png'
    )
    viz.plot_thirdparty_security_matrix(
        analysis_results['thirdparty_httponly'],
        'HttpOnly',
        graphs_dir / '14_thirdparty_httponly.png'
    )
    viz.plot_thirdparty_security_matrix(
        analysis_results['thirdparty_secure'],
        'Secure',
        graphs_dir / '15_thirdparty_secure.png'
    )
    
    # 16: Risque RGPD
    viz.plot_risk_matrix(
        analysis_results['risk_levels'],
        analysis_results['risk_by_pii'],
        graphs_dir / '16_risk_matrix.png'
    )
    
    print(f" 16 graphiques techniques générés\n")
    
    # === 6 GRAPHIQUES VIE PRIVÉE ===
    
    print(" Graphiques vie privée (17-22)...")
    
    # 17-18: Contenu
    aviz.plot_content_sunburst(
        analysis_results['content_hierarchy'],
        privacy_graphs_dir / '17_content_sunburst.png'
    )
    aviz.plot_content_types_distribution(
        analysis_results['content_types'],
        privacy_graphs_dir / '18_content_types.png'
    )
    
    # 19-20: Vendors
    aviz.plot_vendor_sankey(
        analysis_results['category_vendor_flows'],
        privacy_graphs_dir / '19_vendor_sankey.png'
    )
    aviz.plot_top_vendors(
        analysis_results['vendor_counts'],
        privacy_graphs_dir / '20_top_vendors.png'
    )
    
    # 21-22: Entropie
    aviz.plot_entropy_scatter(
        analysis_results['entropy_lifetime_data'],
        privacy_graphs_dir / '21_entropy_scatter.png'
    )
    aviz.plot_entropy_distribution(
        analysis_results['entropy_by_pii'],
        privacy_graphs_dir / '22_entropy_distribution.png'
    )
    
    print(f" 6 graphiques vie privée générés\n")
    
    # === 6 GRAPHIQUES CHANGEMENTS (MODIFIED spécifique) ===
    
    change_graphs_dir = output_dir / 'consolidated' / 'change_graphs'
    change_graphs_dir.mkdir(parents=True, exist_ok=True)
    
    print(" Graphiques changements (23-28)...")
    
    # 23: Champs modifiés
    if analysis_results.get('changed_fields_distribution'):
        cviz.plot_changed_fields_distribution(
            analysis_results['changed_fields_distribution'],
            change_graphs_dir / '23_changed_fields.png'
        )
    
    # 24: Nombre de changements
    if analysis_results.get('num_changes_distribution'):
        cviz.plot_num_changes_distribution(
            analysis_results['num_changes_distribution'],
            change_graphs_dir / '24_num_changes.png'
        )
    
    # 25: Changement de durée
    if analysis_results.get('duration_changes'):
        cviz.plot_duration_change_scatter(
            analysis_results['duration_changes'],
            change_graphs_dir / '25_duration_change.png'
        )
    
    # 26: Évolution entropie
    if analysis_results.get('entropy_changes'):
        cviz.plot_entropy_evolution_scatter(
            analysis_results['entropy_changes'],
            change_graphs_dir / '26_entropy_evolution.png'
        )
    
    # 27: Changements par PII
    if analysis_results.get('changes_by_pii'):
        cviz.plot_changes_by_pii_type(
            analysis_results['changes_by_pii'],
            change_graphs_dir / '27_changes_by_pii.png'
        )
    
    # 28: Timeline
    if analysis_results.get('modifications_timeline'):
        cviz.plot_modifications_timeline(
            analysis_results['modifications_timeline'],
            change_graphs_dir / '28_timeline.png'
        )
    
    print(f" 6 graphiques changements générés\n")
    
    print(f"\n 28 graphiques consolidés générés dans {output_dir / 'consolidated'}")


def main():
    """Script principal"""

  # ---------------------------------------------------------------------------------
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    output_base = Path(__file__).resolve().parent.parent / 'results' 

    if not base_dir.exists():
        print(f"Dossier {base_dir} non trouvé")
        return
    users  = ('FR_0417', 'FR_0446', 'FR_0458')
    auth_statuses = ('Auth', 'UnAuth')
    
    policies = ('ALL', 'PARTIAL', 'NONE')

    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                input_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'modified'
                output_dir = output_base / auth_status / user / policy / 'cookies'/ 'modified'

                if not input_dir.exists():
                    print(f"Le dossier {input_dir} n'existe pas, passage à la configuration suivante.")
                    continue
                # output_added_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'added'
                # output_modified_dir = base_dir / 'user' / auth_status / user / policy / 'cookies'/ 'modified'
                
                output_dir.mkdir(parents=True, exist_ok=True)
    
                # Charger tous les cookies
                print("\n Chargement des cookies...")
                direct_pii_cookies, other_cookies = load_all_cookies(input_dir)
                
                # Analyser
                analysis_results = analyze_consolidated(direct_pii_cookies, other_cookies)
                
                # Sauvegarder les résultats
                output_path = output_dir / 'consolidated' / 'analysis.json'
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Convertir pour JSON
                serializable_results = {k: v for k, v in analysis_results.items() 
                                    if k not in ['entropy_lifetime_data']}
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(serializable_results, f, indent=2, ensure_ascii=False)
                
                print(f" Résultats sauvegardés : {output_path}")
                
                # Générer les visualisations
                generate_all_visualizations(analysis_results, output_dir)
    


if __name__ == '__main__':
    main()
    