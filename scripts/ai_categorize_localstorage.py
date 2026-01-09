#!/usr/bin/env python3
"""
Analyse localStorage avec IA (Llama 3.3 70B via Groq).

Expert RGPD pour détection approfondie de données personnelles.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
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


def load_user_profile(user_info_path: Path) -> Dict:
    """Charge le profil utilisateur depuis user_info.json"""
    with open(user_info_path, 'r', encoding='utf-8') as f:
        return json.load(f)


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


def build_prompt(item: Dict, user_profile: Dict, categories: List[str]) -> str:
    """
    Construit le prompt pour l'analyse IA.
    """
    key = item.get('key', '')
    value = item.get('value', '')
    
    # Limiter taille de la valeur pour le prompt
    if len(value) > 2000:
        value_display = value[:2000] + "... [tronqué]"
    else:
        value_display = value
    
    # Convertir TRACKING_PATTERNS_COMPLETE en format lisible
    patterns_info = "PATTERNS DE DÉTECTION (regex.py) :\n\n"
    for category, patterns_dict in TRACKING_PATTERNS_COMPLETE.items():
        patterns_info += f"{category}:\n"
        for pattern_name, pattern in patterns_dict.items():
            patterns_info += f"  - {pattern_name}: {pattern}\n"
        patterns_info += "\n"
    
    prompt = f"""Vous êtes un expert en conformité RGPD spécialisé dans la détection de données personnelles dans le stockage web (localStorage).

PROFIL UTILISATEUR :
{json.dumps(user_profile, indent=2, ensure_ascii=False)}

{patterns_info}

CATÉGORIES PII DISPONIBLES :
{', '.join(categories)}

ITEM LOCALSTORAGE À ANALYSER :
Clé: {key}
Valeur: {value_display}

TÂCHE :
Analysez cet item localStorage et identifiez TOUTES les données personnelles présentes selon le RGPD.

INSTRUCTIONS SPÉCIFIQUES :
1. Utilisez les PATTERNS ci-dessus pour identifier précisément les trackeurs, données personnelles, et technologies
2. Identifiez les vendors/trackeurs présents (Google, Meta, Criteo, Taboola, etc.)
3. Utilisez ces patterns pour justifier les catégories et vulnérabilités
4. Expliquez comment les trackeurs collectent/partagent les données
5. Évaluez les risques liés aux trackeurs tiers et technologies de tracking
6. Un item peut avoir plusieurs catégories

RÉPONDEZ UNIQUEMENT EN JSON avec cette structure EXACTE :
{{
  "categories": ["liste des catégories détectées"],
  "primary_category": "catégorie principale",
  "confidence": 0.0-1.0,
  "explanation": "explication détaillée incluant les patterns/trackeurs identifiés",
  "pii_detected": [
    {{
      "type": "type de PII",
      "value": "valeur détectée ou 'présent'",
      "location": "où dans l'item",
      "certainty": "low|medium|high",
      "tracker": "nom du trackeur si applicable",
      "pattern_matched": "nom du pattern regex.py si applicable"
    }}
  ],
  "trackers_identified": ["liste des trackeurs/vendors détectés"],
  "technologies_detected": ["fingerprinting, behavioral tracking, etc."],
  "gdpr_violations": [
    {{
      "article": "Article RGPD",
      "violation": "type de violation",
      "severity": "low|medium|high|critical",
      "description": "description incluant le rôle des trackeurs",
      "tracker_involved": "trackeur concerné si applicable"
    }}
  ],
  "vulnerabilities": ["liste des vulnérabilités"],
  "risk_score": 0-10,
  "recommendations": ["liste de recommandations"]
}}

IMPORTANT :
- Soyez exhaustif dans la détection de PII
- Utilisez les PATTERNS pour être précis et justifier vos détections
- Identifiez TOUS les trackeurs et technologies présents
- Utilisez le profil utilisateur pour identifier les données personnelles
- Expliquez comment les trackeurs augmentent les risques RGPD
- Répondez UNIQUEMENT en JSON valide, sans texte avant ou après
"""
    
    return prompt


def analyze_with_ai(item: Dict, user_profile: Dict, categories: List[str], client: Groq, model: str = "llama-3.3-70b-versatile") -> Optional[Dict]:
    """
    Analyse un item avec l'IA Groq.
    """
    try:
        prompt = build_prompt(item, user_profile, categories)
        
        # Appel API Groq
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "Vous êtes un expert RGPD. Répondez UNIQUEMENT en JSON valide."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model=model,
            temperature=0.1,  # Faible pour cohérence
            max_tokens=2000,
            response_format={"type": "json_object"}  # Force JSON
        )
        
        # Parser réponse
        response_text = chat_completion.choices[0].message.content
        ai_analysis = json.loads(response_text)
        
        return ai_analysis
        
    except json.JSONDecodeError as e:
        print(f"  Erreur parsing JSON: {e}")
        return None
    except Exception as e:
        print(f"  Erreur API: {e}")
        return None


def save_progress(enriched_items: List[Dict], output_dir: Path, batch_num: int):
    """Sauvegarde incrémentale des résultats"""
    progress_file = output_dir / f'progress_batch_{batch_num}.json'
    progress_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(progress_file, 'w', encoding='utf-8') as f:
        json.dump(enriched_items, f, indent=2, ensure_ascii=False)
    
    print(f"\n  Sauvegarde batch {batch_num}: {len(enriched_items)} items")


def load_existing_progress(output_dir: Path) -> tuple[List[Dict], int]:
    """
    Charge la progression existante depuis les fichiers batch.
    
    Returns:
        (enriched_items, last_batch_num)
    """
    if not output_dir.exists():
        return [], 0
    
    # Trouver tous les fichiers batch
    batch_files = sorted(output_dir.glob('progress_batch_*.json'))
    
    if not batch_files:
        return [], 0
    
    # Charger le dernier batch
    last_batch_file = batch_files[-1]
    last_batch_num = int(last_batch_file.stem.split('_')[-1])
    
    with open(last_batch_file, 'r', encoding='utf-8') as f:
        enriched_items = json.load(f)
    
    print(f"\n  Reprise depuis batch {last_batch_num}: {len(enriched_items)} items déjà analysés")
    
    return enriched_items, last_batch_num


def categorize_all_with_ai(input_file: Path, output_dir: Path, api_key: str, max_items: Optional[int] = None):
    """
    Catégorise tous les items localStorage avec l'IA.
    """
    print(f"\nAnalyse IA localStorage : {input_file.name}")
    print("=" * 70)
    
    # Initialiser client Groq
    client = Groq(api_key=api_key)
    
    # Charger données
    with open(input_file, 'r', encoding='utf-8') as f:
        items = json.load(f)
    
    # Limiter si demandé (pour tests)
    if max_items:
        items = items[:max_items]
        print(f"Mode test : {max_items} items")
    
    print(f"Total items: {len(items)}")
    
    # Charger contexte
    base_dir = Path(__file__).parent.parent
    user_info_path = base_dir / 'FR_0417' / 'storage_state' / 'user_info.json'
    user_profile = load_user_profile(user_info_path)
    categories = get_pii_categories_list()
    
    print(f"Profil utilisateur chargé")
    print(f"Catégories PII: {len(categories)}")
    
    # Charger progression existante
    enriched_items, batch_num = load_existing_progress(output_dir)
    start_index = len(enriched_items)
    
    if start_index > 0:
        print(f"Reprise de l'analyse à partir de l'item {start_index + 1}")
    
    # Analyser chaque item (en commençant après ceux déjà traités)
    enriched_items = []
    stats = {
        'total': len(items),
        'analyzed': 0,
        'failed': 0,
        'categories_count': Counter(),
        'avg_confidence': 0,
        'avg_risk_score': 0,
        'gdpr_violations_count': 0
    }
    
    print(f"\nAnalyse en cours...")
    
    SAVE_INTERVAL = 30  # Sauvegarder tous les 30 appels
    
    for i, item in enumerate(items, 1):
        # Skip items déjà traités
        if i <= start_index:
            continue
        
        print(f"  [{i}/{len(items)}] {item.get('key', 'unknown')[:50]}...", end=' ')
        
        # Analyser avec IA
        ai_analysis = analyze_with_ai(item, user_profile, categories, client)
        
        if ai_analysis:
            # Enrichir item
            enriched_item = {
                **item,
                '_ai_analysis': ai_analysis
            }
            enriched_items.append(enriched_item)
            
            # Stats
            stats['analyzed'] += 1
            stats['categories_count'][ai_analysis.get('primary_category', 'UNKNOWN')] += 1
            stats['avg_confidence'] += ai_analysis.get('confidence', 0)
            stats['avg_risk_score'] += ai_analysis.get('risk_score', 0)
            stats['gdpr_violations_count'] += len(ai_analysis.get('gdpr_violations', []))
            
            print(f"OK (conf: {ai_analysis.get('confidence', 0):.2f}, risk: {ai_analysis.get('risk_score', 0):.1f})")
        else:
            enriched_items.append(item)
            stats['failed'] += 1
            print("FAILED")
        
        # Sauvegarde incrémentale tous les 30 appels
        if i % SAVE_INTERVAL == 0:
            batch_num += 1
            save_progress(enriched_items, output_dir, batch_num)
        
        # Rate limiting (30 req/min pour Groq gratuit)
        if i < len(items):
            time.sleep(2.1)  # ~28 req/min pour être sûr
    
    # Sauvegarde finale si reste des items
    if len(enriched_items) % SAVE_INTERVAL != 0:
        batch_num += 1
        save_progress(enriched_items, output_dir, batch_num)
    
    # Calculer moyennes
    if stats['analyzed'] > 0:
        stats['avg_confidence'] /= stats['analyzed']
        stats['avg_risk_score'] /= stats['analyzed']
    
    # Sauvegarder par catégorie
    output_dir.mkdir(parents=True, exist_ok=True)
    
    categorized_data = {}
    for item in enriched_items:
        if '_ai_analysis' in item:
            primary_cat = item['_ai_analysis']['primary_category']
        else:
            primary_cat = 'FAILED_ANALYSIS'
        
        if primary_cat not in categorized_data:
            categorized_data[primary_cat] = []
        categorized_data[primary_cat].append(item)
    
    for category, items_list in categorized_data.items():
        output_file = output_dir / f'{category}.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(items_list, f, indent=2, ensure_ascii=False)
        print(f"  {category}: {len(items_list)} items")
    
    # Sauvegarder statistiques
    summary_file = output_dir / 'analysis_summary.json'
    summary = {
        'total_items': stats['total'],
        'analyzed': stats['analyzed'],
        'failed': stats['failed'],
        'avg_confidence': stats['avg_confidence'],
        'avg_risk_score': stats['avg_risk_score'],
        'gdpr_violations_count': stats['gdpr_violations_count'],
        'categories_distribution': dict(stats['categories_count'])
    }
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    # Afficher statistiques
    print(f"\nStatistiques:")
    print(f"  Analysés: {stats['analyzed']}/{stats['total']} ({stats['analyzed']/stats['total']*100:.1f}%)")
    print(f"  Échecs: {stats['failed']}")
    print(f"  Confiance moyenne: {stats['avg_confidence']:.2f}")
    print(f"  Score risque moyen: {stats['avg_risk_score']:.1f}/10")
    print(f"  Violations RGPD: {stats['gdpr_violations_count']}")
    
    print(f"\nTop 10 catégories:")
    for cat, count in stats['categories_count'].most_common(10):
        print(f"  {cat}: {count} ({count/stats['analyzed']*100:.1f}%)")
    
    print("\n" + "=" * 70)
    print(f"Résultats sauvegardés dans: {output_dir}")


def main():
    """Script principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyse localStorage avec IA')
    parser.add_argument('--api-key', help='Groq API key (ou variable GROQ_API_KEY)')
    parser.add_argument('--test', type=int, help='Mode test : nombre d\'items à analyser')
    parser.add_argument('--source', choices=['added', 'modified', 'both'], default='both')
    
    args = parser.parse_args()
    
    # Récupérer API key
    api_key = args.api_key or os.environ.get('GROQ_API_KEY')
    
    if not api_key:
        print("Erreur: API key requise")
        print("Utilisez --api-key ou définissez GROQ_API_KEY")
        sys.exit(1)
    
    base_dir = Path(__file__).parent.parent
    input_dir = base_dir / 'preprocessing' / 'localstorage'
    output_base_dir = base_dir / 'ai_categorized_localstorage'
    
    # Fichiers à traiter
    files_to_process = []
    
    if args.source in ['added', 'both']:
        files_to_process.append(
            ('added', input_dir / 'added_localstorage.json', output_base_dir / 'added')
        )
    
    if args.source in ['modified', 'both']:
        files_to_process.append(
            ('modified', input_dir / 'modified_localstorage.json', output_base_dir / 'modified')
        )
    
    for source_type, input_file, output_dir in files_to_process:
        if input_file.exists():
            categorize_all_with_ai(input_file, output_dir, api_key, max_items=args.test)
        else:
            print(f"\nFichier non trouvé: {input_file}")


if __name__ == '__main__':
    main()
