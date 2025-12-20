#!/usr/bin/env python3
"""
Script d'analyse des cookies PII PAR CATÉGORIE.
Génère des visualisations spécifiques pour chaque catégorie de données personnelles.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, List

sys.path.append(str(Path(__file__).parent))
from pii_detector import extract_keywords
import visualizations as viz


def calculate_lifetime_category(expires: float) -> str:
    """Calcule la catégorie de durée de vie d'un cookie"""
    if expires == -1 or expires <= 0:
        return 'Session'
    
    now = datetime.now().timestamp()
    duration_seconds = expires - now
    duration_months = duration_seconds / (30 * 24 * 3600)
    
    if duration_months < 6:
        return '<6 months'
    elif duration_months <= 18:
        return '6-18 months'
    else:
        return '>18 months'


def normalize_samesite(samesite_value) -> str:
    """Normalise la valeur SameSite"""
    if samesite_value is None or samesite_value == 'None':
        return 'No Restriction'
    elif samesite_value == 'Strict':
        return 'Strict'
    else:  # Lax ou autres
        return 'Lax'


def is_third_party(cookie_domain: str, initial_url: str) -> bool:
    """
    Détermine si un cookie est third-party en comparant son domaine avec l'URL initiale.
    
    Args:
        cookie_domain: Domaine du cookie (ex: '.example.com')
        initial_url: URL initiale de la page (ex: 'https://www.example.com/page')
    
    Returns:
        True si le cookie est third-party
    """
    if not cookie_domain or not initial_url:
        return False
    
    # Extraire le domaine de l'URL
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(initial_url)
        url_domain = parsed_url.netloc.lower()
        
        # Nettoyer le domaine du cookie (enlever le point initial)
        clean_cookie_domain = cookie_domain.lower().lstrip('.')
        
        # Vérifier si le domaine du cookie correspond à l'URL
        # First-party si le domaine de l'URL se termine par le domaine du cookie
        return not url_domain.endswith(clean_cookie_domain)
    except:
        return False


def analyze_category(cookies: List[Dict], category_name: str) -> Dict:
    """Analyse une catégorie spécifique de cookies"""
    print(f"\n Analyse de la catégorie: {category_name}")
    print(f"   {len(cookies)} cookies dans cette catégorie\n")
    
    # Structures de données pour les 11 graphiques + third-party
    lifetime_dist = Counter()
    lifetime_by_subcat = defaultdict(Counter)
    
    httponly_dist = Counter()
    httponly_by_subcat = defaultdict(Counter)
    
    secure_dist = Counter()
    secure_by_subcat = defaultdict(Counter)
    
    samesite_dist = Counter()
    samesite_by_subcat = defaultdict(Counter)
    
    security_matrix = Counter()
    security_by_subcat = defaultdict(Counter)
    
    # Nouvelles métriques third-party
    thirdparty_dist = Counter()
    thirdparty_by_subcat = defaultdict(Counter)
    thirdparty_httponly = Counter()
    thirdparty_secure = Counter()
    
    # Matrice de risque RGPD
    risk_levels = Counter()
    risk_by_subcat = defaultdict(Counter)
    
    all_keywords = Counter()
    
    # Analyser chaque cookie
    for cookie in cookies:
        subcategory = cookie.get('matched_subcategory', 'unknown')
        
        # Déterminer si third-party
        is_tp = is_third_party(cookie.get('domain', ''), cookie.get('initial_url', ''))
        tp_status = 'Third-Party' if is_tp else 'First-Party'
        
        # Durée de vie
        lifetime_cat = calculate_lifetime_category(cookie.get('expires', -1))
        lifetime_dist[lifetime_cat] += 1
        lifetime_by_subcat[subcategory][lifetime_cat] += 1
        
        # HttpOnly
        http_only = cookie.get('httpOnly', False)
        httponly_dist[str(http_only)] += 1
        httponly_by_subcat[subcategory][str(http_only)] += 1
        
        # Secure
        secure = cookie.get('secure', False)
        secure_dist[str(secure)] += 1
        secure_by_subcat[subcategory][str(secure)] += 1
        
        # SameSite
        samesite = normalize_samesite(cookie.get('sameSite'))
        samesite_dist[samesite] += 1
        samesite_by_subcat[subcategory][samesite] += 1
        
        # Matrice de sécurité
        security_matrix[(http_only, secure)] += 1
        
        # Score de sécurité par sous-catégorie
        if not http_only and not secure:
            security_score = 'Lowly Secure'
        elif http_only and secure:
            security_score = 'Secure'
        else:
            security_score = 'Partially Secure'
        security_by_subcat[subcategory][security_score] += 1
        
        # Third-party metrics
        thirdparty_dist[tp_status] += 1
        thirdparty_by_subcat[subcategory][tp_status] += 1
        thirdparty_httponly[(tp_status, http_only)] += 1
        thirdparty_secure[(tp_status, secure)] += 1
        
        # Calcul du niveau de risque RGPD
        # Critères : PII (toujours vrai) + Durée >1 an + HttpOnly=False + Third-Party
        risk_score = 0
        
        # Critère 1: Durée > 1 an (365 jours)
        expires = cookie.get('expires', -1)
        if expires > 0:
            now = datetime.now().timestamp()
            duration_days = (expires - now) / (24 * 3600)
            if duration_days > 365:
                risk_score += 1
        
        # Critère 2: HttpOnly=False
        if not http_only:
            risk_score += 1
        
        # Critère 3: Third-Party
        if is_tp:
            risk_score += 1
        
        # Déterminer le niveau de risque
        if risk_score == 3:
            risk_level = 'Critical Risk'
        elif risk_score == 2:
            risk_level = 'High Risk'
        elif risk_score == 1:
            risk_level = 'Medium Risk'
        else:
            risk_level = 'Low Risk'
        
        risk_levels[risk_level] += 1
        risk_by_subcat[subcategory][risk_level] += 1
        
        # Mots-clés
        keywords = extract_keywords(cookie.get('name', ''))
        all_keywords.update(keywords)
    
    return {
        'category_name': category_name,
        'total_cookies': len(cookies),
        'lifetime_distribution': dict(lifetime_dist),
        'lifetime_by_subcategory': {k: dict(v) for k, v in lifetime_by_subcat.items()},
        'httponly_distribution': dict(httponly_dist),
        'httponly_by_subcategory': {k: dict(v) for k, v in httponly_by_subcat.items()},
        'secure_distribution': dict(secure_dist),
        'secure_by_subcategory': {k: dict(v) for k, v in secure_by_subcat.items()},
        'samesite_distribution': dict(samesite_dist),
        'samesite_by_subcategory': {k: dict(v) for k, v in samesite_by_subcat.items()},
        'security_matrix': {str(k): v for k, v in security_matrix.items()},
        'security_by_subcategory': {k: dict(v) for k, v in security_by_subcat.items()},
        'thirdparty_distribution': dict(thirdparty_dist),
        'thirdparty_by_subcategory': {k: dict(v) for k, v in thirdparty_by_subcat.items()},
        'thirdparty_httponly': {f"{k[0]}_{k[1]}": v for k, v in thirdparty_httponly.items()},
        'thirdparty_secure': {f"{k[0]}_{k[1]}": v for k, v in thirdparty_secure.items()},
        'risk_levels': dict(risk_levels),
        'risk_by_subcategory': {k: dict(v) for k, v in risk_by_subcat.items()},
        'keywords': dict(all_keywords.most_common(15))
    }


def generate_category_visualizations(analysis_results: Dict, output_dir: Path):
    """Génère les 11 visualisations standards pour une catégorie"""
    category_name = analysis_results['category_name']
    graphs_dir = output_dir / category_name / 'graphs'
    graphs_dir.mkdir(parents=True, exist_ok=True)
    
    print(f" Génération des 11 graphiques pour {category_name}...\n")
    
    # Graphique 1: Distribution globale des durées de vie
    print(f"   Graphique 1: Distribution of PII Cookie Lifetimes")
    viz.plot_lifetime_distribution(
        analysis_results['lifetime_distribution'],
        graphs_dir / '01_lifetime_distribution.png'
    )
    
    # Graphique 2: Durées de vie par sous-catégorie PII
    print(f"   Graphique 2: Lifetimes Per PII Type (Subcategory)")
    viz.plot_lifetime_by_pii_type(
        analysis_results['lifetime_by_subcategory'],
        graphs_dir / '02_lifetime_by_pii_type.png'
    )
    
    # Graphique 3: Distribution globale HttpOnly
    print(f"   Graphique 3: Distribution isHttpOnly")
    viz.plot_httponly_distribution(
        analysis_results['httponly_distribution'],
        graphs_dir / '03_httponly_distribution.png'
    )
    
    # Graphique 4: HttpOnly par sous-catégorie PII
    print(f"   Graphique 4: HttpOnly Per PII Type (Subcategory)")
    viz.plot_httponly_by_pii_type(
        analysis_results['httponly_by_subcategory'],
        graphs_dir / '04_httponly_by_pii_type.png'
    )
    
    # Graphique 5: Distribution globale Secure
    print(f"   Graphique 5: Distribution isSecure")
    viz.plot_secure_distribution(
        analysis_results['secure_distribution'],
        graphs_dir / '05_secure_distribution.png'
    )
    
    # Graphique 6: Secure par sous-catégorie PII
    print(f"   Graphique 6: Secure Per PII Type (Subcategory)")
    viz.plot_secure_by_pii_type(
        analysis_results['secure_by_subcategory'],
        graphs_dir / '06_secure_by_pii_type.png'
    )
    
    # Graphique 7: Distribution globale SameSite
    print(f"   Graphique 7: Distribution sameSite")
    viz.plot_samesite_distribution(
        analysis_results['samesite_distribution'],
        graphs_dir / '07_samesite_distribution.png'
    )
    
    # Graphique 8: SameSite par sous-catégorie PII
    print(f"   Graphique 8: SameSite Per PII Type (Subcategory)")
    viz.plot_samesite_by_pii_type(
        analysis_results['samesite_by_subcategory'],
        graphs_dir / '08_samesite_by_pii_type.png'
    )
    
    # Graphique 9: Matrice de sécurité
    print(f"   Graphique 9: PII Cookies Security Matrix")
    matrix_data = {eval(k): v for k, v in analysis_results['security_matrix'].items()}
    viz.plot_security_matrix(
        matrix_data,
        graphs_dir / '09_security_matrix.png'
    )
    
    # Graphique 10: Posture de sécurité par sous-catégorie PII
    print(f"   Graphique 10: Security Posture by PII Type (Subcategory)")
    viz.plot_security_posture(
        analysis_results['security_by_subcategory'],
        graphs_dir / '10_security_posture.png'
    )
    
    # Graphique 11: Mots-clés fréquents
    print(f"   Graphique 11: Most Frequent Keywords")
    viz.plot_keyword_frequency(
        Counter(analysis_results['keywords']),
        graphs_dir / '11_keyword_frequency.png',
        top_n=15
    )
    
    # Graphique 12: Distribution Third-Party
    if analysis_results.get('thirdparty_distribution'):
        print(f"   Graphique 12: Third-Party vs First-Party Distribution")
        viz.plot_thirdparty_distribution(
            analysis_results['thirdparty_distribution'],
            graphs_dir / '12_thirdparty_distribution.png'
        )
    
    # Graphique 13: Third-Party par sous-catégorie PII
    if analysis_results.get('thirdparty_by_subcategory'):
        print(f"   Graphique 13: Third-Party Per PII Type (Subcategory)")
        viz.plot_thirdparty_by_subcategory(
            analysis_results['thirdparty_by_subcategory'],
            graphs_dir / '13_thirdparty_by_subcategory.png'
        )
    
    # Graphique 14: Third-Party × HttpOnly
    if analysis_results.get('thirdparty_httponly'):
        print(f"   Graphique 14: Third-Party × HttpOnly Matrix")
        viz.plot_thirdparty_security_matrix(
            analysis_results['thirdparty_httponly'],
            'HttpOnly',
            graphs_dir / '14_thirdparty_httponly.png'
        )
    
    # Graphique 15: Third-Party × Secure
    if analysis_results.get('thirdparty_secure'):
        print(f"   Graphique 15: Third-Party × Secure Matrix")
        viz.plot_thirdparty_security_matrix(
            analysis_results['thirdparty_secure'],
            'Secure',
            graphs_dir / '15_thirdparty_secure.png'
        )
    
    # Graphique 16: Matrice de Risque RGPD
    if analysis_results.get('risk_levels'):
        print(f"   Graphique 16: GDPR Risk Matrix")
        viz.plot_risk_matrix(
            analysis_results['risk_levels'],
            analysis_results.get('risk_by_subcategory', {}),
            graphs_dir / '16_risk_matrix.png'
        )
    
    total_graphs = sum([
        bool(analysis_results['lifetime_distribution']),
        bool(analysis_results.get('thirdparty_distribution')),
        bool(analysis_results.get('thirdparty_by_subcategory')),
        bool(analysis_results.get('thirdparty_httponly')),
        bool(analysis_results.get('thirdparty_secure')),
        bool(analysis_results.get('risk_levels'))
    ]) + 11  # 11 graphiques de base
    
    print(f"\n {total_graphs} graphiques générés dans {graphs_dir}")


def generate_category_report(analysis_results: Dict, output_path: Path):
    """Génère un rapport markdown pour une catégorie"""
    category_name = analysis_results['category_name']
    total = analysis_results['total_cookies']
    
    # Calculer les pourcentages
    httponly_false = analysis_results['httponly_distribution'].get('False', 0)
    secure_false = analysis_results['secure_distribution'].get('False', 0)
    samesite_none = analysis_results['samesite_distribution'].get('No Restriction', 0)
    lifetime_long = (analysis_results['lifetime_distribution'].get('6-18 months', 0) + 
                     analysis_results['lifetime_distribution'].get('>18 months', 0))
    
    report = f"""# Analyse RGPD - {category_name} (Added)

**Date d'analyse** : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Résumé

- **Total de cookies** : {total:,}
- **Catégorie** : {category_name}

---

## 1. Durées de Vie

{_format_dict(analysis_results['lifetime_distribution'])}

**️ Constat** : {lifetime_long} cookies ({lifetime_long/total*100:.1f}%) ont une durée de vie ≥ 6 mois.

---

## 2. Attribut HttpOnly

{_format_dict(analysis_results['httponly_distribution'])}

** Vulnérabilité XSS** : {httponly_false} cookies ({httponly_false/total*100:.1f}%) sont vulnérables aux attaques XSS.

---

## 3. Attribut Secure

{_format_dict(analysis_results['secure_distribution'])}

** Risque MITM** : {secure_false} cookies ({secure_false/total*100:.1f}%) peuvent être interceptés.

---

## 4. Attribut SameSite

{_format_dict(analysis_results['samesite_distribution'])}

** Risque CSRF** : {samesite_none} cookies ({samesite_none/total*100:.1f}%) sont vulnérables aux attaques CSRF.

---

## 5. Matrice de Sécurité

{_format_dict(analysis_results['security_matrix'])}

---

## Graphiques

Les 6 graphiques sont disponibles dans le dossier `graphs/`.

---

## Conclusion

Cette catégorie **{category_name}** présente des vulnérabilités RGPD nécessitant une attention immédiate.
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f" Rapport généré : {output_path}")


def _format_dict(d: Dict) -> str:
    """Formate un dictionnaire pour le markdown"""
    return '\n'.join([f"- **{k}** : {v}" for k, v in sorted(d.items())])


def main():
    base_dir = Path(__file__).parent.parent
    input_dir = base_dir / 'categorized_cookies' / 'added'
    output_base_dir = base_dir / 'analysis' / 'results' / 'added' / 'by_category'
    
    print("=" * 70)
    print("  ANALYSE RGPD PAR CATÉGORIE - COOKIES PII (ADDED)")
    print("=" * 70)
    
    # Lister tous les fichiers JSON
    json_files = sorted(input_dir.glob('*.json'))
    
    if not json_files:
        print(f" Aucun fichier trouvé dans {input_dir}")
        return
    
    print(f"\n {len(json_files)} catégories trouvées\n")
    
    # Analyser chaque catégorie
    for json_file in json_files:
        category_name = json_file.stem
        
        # Charger les cookies de cette catégorie
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                cookies = json.load(f)
        except Exception as e:
            print(f" Erreur lors du chargement de {json_file.name}: {e}")
            continue
        
        if not cookies:
            print(f" {category_name}: aucun cookie, ignoré\n")
            continue
        
        # Analyser
        analysis_results = analyze_category(cookies, category_name)
        
        # Créer le dossier de sortie
        category_output_dir = output_base_dir / category_name
        category_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Sauvegarder les résultats JSON
        results_file = category_output_dir / 'analysis.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_results, f, ensure_ascii=False, indent=2)
        print(f" Résultats sauvegardés : {results_file}")
        
        # Générer les visualisations
        generate_category_visualizations(analysis_results, output_base_dir)
        
        # Générer le rapport
        generate_category_report(analysis_results, category_output_dir / 'report.md')
        
        print("\n" + "-" * 70 + "\n")
    
    print("=" * 70)
    print(" Analyse par catégorie terminée avec succès!")
    print("=" * 70)


if __name__ == '__main__':
    main()
