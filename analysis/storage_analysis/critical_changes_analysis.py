#!/usr/bin/env python3
"""
Analyse des changements critiques RGPD dans les stockages web.

Identifie:
- Les items qui changent le plus fréquemment
- Les types de données sensibles modifiées (timestamps, UIDs, emails, etc.)
- Les catégories PII des données qui changent
- Les items critiques nécessitant un audit RGPD prioritaire
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
import re

sys.path.insert(0, str(Path(__file__).parent.parent))
import analysis.privacy_metrics as pm


def analyze_value_for_sensitive_data(value: str) -> List[str]:
    """
    Détecte les types de données sensibles dans une valeur.
    
    Returns:
        Liste des types sensibles détectés
    """
    sensitive_types = []
    value_str = str(value)
    
    # Timestamps Unix (10-13 chiffres)
    if re.search(r'\b\d{10,13}\b', value_str):
        sensitive_types.append('timestamp')
    
    # Dates ISO
    if re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}', value_str):
        sensitive_types.append('iso_datetime')
    
    # UUIDs
    if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value_str, re.I):
        sensitive_types.append('uuid')
    
    # IDs/tokens longs (20+ caractères)
    if re.search(r'\b[A-Za-z0-9_-]{20,}\b', value_str):
        sensitive_types.append('long_id_token')
    
    # Emails
    if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', value_str):
        sensitive_types.append('email')
    
    # Adresses IP
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', value_str):
        sensitive_types.append('ip_address')
    
    # Session IDs
    if re.search(r'(session|sess|sid)[_-]?[A-Za-z0-9]{10,}', value_str, re.I):
        sensitive_types.append('session_id')
    
    # User IDs
    if re.search(r'(user|uid|userid)[_-]?[A-Za-z0-9]{5,}', value_str, re.I):
        sensitive_types.append('user_id')
    
    return sensitive_types


def calculate_gdpr_risk_score(change_data: Dict) -> Tuple[int, str]:
    """
    Calcule un score de risque RGPD pour un changement.
    
    Returns:
        (score, niveau) où score est 0-10 et niveau est Low/Medium/High/Critical
    """
    score = 0
    
    # +3 si contient des données personnelles directes
    if change_data['has_email']:
        score += 3
    
    # +2 si contient des identifiants uniques
    if change_data['has_uuid'] or change_data['has_user_id']:
        score += 2
    
    # +2 si contient des timestamps (tracking temporel)
    if change_data['has_timestamp']:
        score += 2
    
    # +1 si contient des IDs longs (tracking potentiel)
    if change_data['has_long_id']:
        score += 1
    
    # +1 si contient des session IDs
    if change_data['has_session_id']:
        score += 1
    
    # +1 si contient des IPs
    if change_data['has_ip']:
        score += 1
    
    # Niveau de risque
    if score >= 7:
        level = 'Critical'
    elif score >= 5:
        level = 'High'
    elif score >= 3:
        level = 'Medium'
    else:
        level = 'Low'
    
    return score, level


def analyze_critical_changes(base_dir: Path, storage_type: str, 
                            auth_status: str, user: str, policy: str) -> Dict:
    """
    Analyse complète des changements critiques RGPD.
    """
    added_dir = base_dir / 'user' / auth_status / user / policy / storage_type / 'added'
    modified_dir = base_dir / 'user' / auth_status / user / policy / storage_type / 'modified'
    
    if not added_dir.exists() or not modified_dir.exists():
        return None
    
    print(f"\n{'='*70}")
    print(f"Analyse: {user} / {auth_status} / {policy} / {storage_type.upper()}")
    print(f"{'='*70}\n")
    
    # Charger les items
    added_items = {}
    modified_items = defaultdict(list)
    
    for cat_file in sorted(added_dir.glob('*.json')):
        with open(cat_file, 'r') as f:
            items = json.load(f)
            for item in items:
                key = item.get('key', item.get('name', ''))
                if key:
                    added_items[key] = item
    
    for cat_file in sorted(modified_dir.glob('*.json')):
        with open(cat_file, 'r') as f:
            items = json.load(f)
            for item in items:
                key = item.get('key', item.get('name', ''))
                if key:
                    modified_items[key].append(item)
    
    print(f"Items ajoutés: {len(added_items)}")
    print(f"Items modifiés: {len(modified_items)}")
    
    # Analyser les changements
    changes = []
    pii_category_changes = Counter()
    sensitive_type_counts = Counter()
    risk_distribution = Counter()
    critical_items = []
    
    for key, mod_list in modified_items.items():
        if key in added_items:
            original = added_items[key]
            
            for modified in mod_list:
                # Catégorie PII
                pii_category = modified.get('_primary_category', 'UNKNOWN')
                pii_category_changes[pii_category] += 1
                
                # Analyser les données sensibles
                orig_value = str(original.get('value', ''))
                mod_value = str(modified.get('value', ''))
                
                orig_sensitive = analyze_value_for_sensitive_data(orig_value)
                mod_sensitive = analyze_value_for_sensitive_data(mod_value)
                
                # Compter les types sensibles
                for stype in set(orig_sensitive + mod_sensitive):
                    sensitive_type_counts[stype] += 1
                
                # Changement de taille
                size_change = len(mod_value) - len(orig_value)
                
                # Calculer l'entropie
                orig_entropy = pm.calculate_entropy(orig_value)
                mod_entropy = pm.calculate_entropy(mod_value)
                entropy_change = mod_entropy - orig_entropy
                
                change_data = {
                    'key': key,
                    'pii_category': pii_category,
                    'original_sensitive_types': orig_sensitive,
                    'modified_sensitive_types': mod_sensitive,
                    'all_sensitive_types': list(set(orig_sensitive + mod_sensitive)),
                    'size_change': size_change,
                    'entropy_change': entropy_change,
                    'has_timestamp': 'timestamp' in mod_sensitive or 'iso_datetime' in mod_sensitive,
                    'has_uuid': 'uuid' in mod_sensitive,
                    'has_long_id': 'long_id_token' in mod_sensitive,
                    'has_email': 'email' in mod_sensitive,
                    'has_session_id': 'session_id' in mod_sensitive,
                    'has_user_id': 'user_id' in mod_sensitive,
                    'has_ip': 'ip_address' in mod_sensitive
                }
                
                # Calculer le score de risque RGPD
                risk_score, risk_level = calculate_gdpr_risk_score(change_data)
                change_data['risk_score'] = risk_score
                change_data['risk_level'] = risk_level
                
                risk_distribution[risk_level] += 1
                
                # Items critiques (risque High ou Critical)
                if risk_level in ['High', 'Critical']:
                    critical_items.append(change_data)
                
                changes.append(change_data)
    
    # Trier les items critiques par score de risque
    critical_items.sort(key=lambda x: x['risk_score'], reverse=True)
    
    return {
        'storage_type': storage_type,
        'total_changes': len(changes),
        'pii_category_changes': dict(pii_category_changes),
        'sensitive_type_counts': dict(sensitive_type_counts),
        'risk_distribution': dict(risk_distribution),
        'critical_items': critical_items[:50],  # Top 50
        'all_changes': changes
    }


def generate_gdpr_report(results: Dict, output_path: Path):
    """Génère un rapport RGPD détaillé."""
    
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("RAPPORT D'ANALYSE DES CHANGEMENTS CRITIQUES RGPD")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    report_lines.append(f"Type de stockage: {results['storage_type'].upper()}")
    report_lines.append(f"Total de changements analysés: {results['total_changes']}")
    report_lines.append("")
    
    # 1. Distribution des risques
    report_lines.append("1. DISTRIBUTION DES RISQUES RGPD")
    report_lines.append("-" * 80)
    for level in ['Critical', 'High', 'Medium', 'Low']:
        count = results['risk_distribution'].get(level, 0)
        pct = (count / results['total_changes'] * 100) if results['total_changes'] > 0 else 0
        report_lines.append(f"   {level:12s} : {count:4d} items ({pct:5.1f}%)")
    report_lines.append("")
    
    # 2. Changements par catégorie PII
    report_lines.append("2. CHANGEMENTS PAR CATÉGORIE PII")
    report_lines.append("-" * 80)
    for pii, count in sorted(results['pii_category_changes'].items(), 
                             key=lambda x: x[1], reverse=True):
        report_lines.append(f"   {pii:45s} : {count:4d} changements")
    report_lines.append("")
    
    # 3. Types de données sensibles
    report_lines.append("3. TYPES DE DONNÉES SENSIBLES MODIFIÉES")
    report_lines.append("-" * 80)
    type_labels = {
        'timestamp': 'Timestamps Unix',
        'iso_datetime': 'Dates ISO',
        'uuid': 'UUIDs',
        'long_id_token': 'IDs/Tokens longs',
        'email': 'Emails',
        'ip_address': 'Adresses IP',
        'session_id': 'Session IDs',
        'user_id': 'User IDs'
    }
    for stype, count in sorted(results['sensitive_type_counts'].items(), 
                               key=lambda x: x[1], reverse=True):
        label = type_labels.get(stype, stype)
        report_lines.append(f"   {label:30s} : {count:4d} items")
    report_lines.append("")
    
    # 4. Items critiques
    report_lines.append(f"4. TOP {len(results['critical_items'])} ITEMS CRITIQUES")
    report_lines.append("-" * 80)
    report_lines.append(f"{'Clé':<50s} | {'Catégorie PII':<30s} | Score | Niveau")
    report_lines.append("-" * 80)
    
    for item in results['critical_items'][:20]:
        key_display = item['key'][:48] + '..' if len(item['key']) > 48 else item['key']
        pii_display = item['pii_category'][:28] + '..' if len(item['pii_category']) > 28 else item['pii_category']
        report_lines.append(
            f"{key_display:<50s} | {pii_display:<30s} | {item['risk_score']:5d} | {item['risk_level']}"
        )
    
    if len(results['critical_items']) > 20:
        report_lines.append(f"   ... et {len(results['critical_items']) - 20} autres items critiques")
    report_lines.append("")
    
    # 5. Recommandations
    report_lines.append("5. RECOMMANDATIONS RGPD")
    report_lines.append("-" * 80)
    
    critical_count = results['risk_distribution'].get('Critical', 0)
    high_count = results['risk_distribution'].get('High', 0)
    
    if critical_count > 0:
        report_lines.append(f"    CRITIQUE: {critical_count} items à risque critique détectés")
        report_lines.append("      → Audit RGPD immédiat recommandé")
        report_lines.append("      → Vérifier la base légale du traitement")
        report_lines.append("      → Évaluer la nécessité de ces données")
        report_lines.append("")
    
    if high_count > 0:
        report_lines.append(f"     ÉLEVÉ: {high_count} items à risque élevé")
        report_lines.append("      → Audit RGPD prioritaire")
        report_lines.append("      → Vérifier les durées de conservation")
        report_lines.append("")
    
    if results['sensitive_type_counts'].get('email', 0) > 0:
        report_lines.append(f"    Emails détectés dans les changements")
        report_lines.append("      → Données personnelles directes = consentement requis")
        report_lines.append("      → Vérifier le chiffrement et la sécurité")
        report_lines.append("")
    
    if results['sensitive_type_counts'].get('timestamp', 0) > 0:
        report_lines.append(f"     Timestamps fréquents dans les changements")
        report_lines.append("      → Tracking temporel = profilage potentiel")
        report_lines.append("      → Vérifier la finalité du traitement")
        report_lines.append("")
    
    report_lines.append("=" * 80)
    
    # Sauvegarder le rapport
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report_lines))
    
    # Afficher aussi à l'écran
    print('\n'.join(report_lines))


def main():
    """Script principal"""
    base_dir = Path(__file__).resolve().parent.parent.parent / 'data'
    output_base = Path(__file__).resolve().parent.parent.parent / 'results'
    
    users = ('FR_0417', 'FR_0446','FR_0458')  # Commencer avec FR_0417
    auth_statuses = ('Auth','UnAuth')
    policies = ('ALL','NONE','PARTIAL')
    storage_types = ('localstorage', 'sessionstorage')
    
    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                for storage_type in storage_types:
                    results = analyze_critical_changes(
                        base_dir, storage_type, auth_status, user, policy
                    )
                    
                    if results:
                        # Sauvegarder les résultats JSON
                        output_dir = output_base / auth_status / user / policy / storage_type / 'lifecycle'
                        output_dir.mkdir(parents=True, exist_ok=True)
                        
                        json_path = output_dir / 'critical_changes.json'
                        with open(json_path, 'w', encoding='utf-8') as f:
                            # Sauvegarder sans all_changes pour réduire la taille
                            save_results = {k: v for k, v in results.items() if k != 'all_changes'}
                            json.dump(save_results, f, indent=2, ensure_ascii=False)
                        
                        # Générer le rapport texte
                        report_path = output_dir / 'critical_changes_report.txt'
                        generate_gdpr_report(results, report_path)
                        
                        print(f"\n✅ Résultats sauvegardés:")
                        print(f"   JSON: {json_path}")
                        print(f"   Rapport: {report_path}")


if __name__ == '__main__':
    main()
