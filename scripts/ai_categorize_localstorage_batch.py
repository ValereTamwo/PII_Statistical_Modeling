#!/usr/bin/env python3
"""
Analyse localStorage avec IA (Llama 3.3 70B via Groq) - Version Batch Optimisée.

Utilise batch processing pour réduire tokens et accélérer l'analyse.
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


def build_batch_prompt(items_batch: List[Dict], user_profile: Dict, categories: List[str]) -> str:
    """
    Construit le prompt pour analyser un batch d'items.
    """
    # Préparer les items pour le prompt
    items_text = ""
    for i, item in enumerate(items_batch, 1):
        key = item.get('key', '')
        value = item.get('value', '')
        
        # Limiter taille de la valeur
        if len(value) > 500:
            value_display = value[:500] + "... [tronqué]"
        else:
            value_display = value
        
        items_text += f"""
ITEM {i}:
Clé: {key}
Valeur: {value_display}
---
"""
    
    # Résumé condensé des patterns (au lieu de tout regex.py)
    patterns_summary = """
PATTERNS DE DÉTECTION DISPONIBLES (résumé) :

DIRECT_PII: email, phone, name, address, birthdate, gender, blood_type, password
ID_SOLUTIONS: criteo, taboola, outbrain, pubmatic, id5, zeotap, liveramp, rtb_house, the_trade_desk, linkedin, twitter, amazon
IDENTITY_TRACKING: google (_ga, _gid), meta (_fbp, _fbc), fingerprint, device_id, session_id
BEHAVIORAL_DATA: hotjar, clarity, fullstory, mouseflow, scroll/click tracking
NAVIGATION_HISTORY: referrer, utm_campaign, breadcrumb, page_flow
CONSENT_AND_PRIVACY: euconsent-v2, didomi, tcf_v2, gdpr_consent
FINGERPRINTING_ADVANCED: webgl, canvas, audio_context, fonts
SUSPICIOUS_VALUES: base64, jwt, uuid, geo_coordinates, encoded_email
UX_ANALYTICS: contentsquare, chartbeat, piano, permutive
SECURITY: cloudflare, recaptcha, csrf_token, akamai
"""
    
    prompt = f"""Vous êtes un expert en conformité RGPD spécialisé dans la détection de données personnelles dans le stockage web (localStorage).

PROFIL UTILISATEUR :
{json.dumps(user_profile, indent=2, ensure_ascii=False)}

{patterns_summary}

CATÉGORIES PII DISPONIBLES :
{', '.join(categories)}

ITEMS LOCALSTORAGE À ANALYSER ({len(items_batch)} items) :
{items_text}

TÂCHE :
Analysez CHAQUE item localStorage et identifiez TOUTES les données personnelles présentes selon le RGPD.

INSTRUCTIONS :
1. Utilisez les PATTERNS ci-dessus pour identifier trackeurs et technologies
2. Identifiez les vendors/trackeurs (Google, Meta, Criteo, Taboola, etc.)
3. N'HÉSITEZ PAS à identifier d'autres trackeurs/vendors basés sur vos connaissances, même s'ils ne sont pas listés ci-dessus
4. Expliquez comment les trackeurs collectent/partagent les données
5. Évaluez les risques RGPD
6. Un item peut avoir plusieurs catégories

RÉPONDEZ UNIQUEMENT EN JSON avec cette structure EXACTE (un objet par item) :
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
          "type": "type de PII (ex: user agent, email, session_id)",
          "value": "valeur exacte détectée (ex: 140.0.7339.16) ou 'présent' si sensible",
          "location": "où dans l'item (ex: uaFullVersion, field 'email', clé principale)",
          "certainty": "low|medium|high",
          "tracker": "trackeur si applicable (ex: Google, Criteo)"
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

IMPORTANT :
- Analysez TOUS les {len(items_batch)} items
- Pour pii_detected: TOUJOURS inclure type, value, location, certainty
- Utilisez les PATTERNS fournis ET vos propres connaissances des trackeurs/technologies
- Identifiez TOUS les trackeurs, même ceux non listés dans les patterns
- Soyez concis mais précis
- Répondez UNIQUEMENT en JSON valide
"""
    
    return prompt


def analyze_batch_with_ai(items_batch: List[Dict], user_profile: Dict, categories: List[str], client: Groq, model: str = "llama-3.3-70b-versatile") -> Optional[List[Dict]]:
    """
    Analyse un batch d'items avec l'IA Groq.
    """
    try:
        prompt = build_batch_prompt(items_batch, user_profile, categories)
        
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
            max_tokens=4000,  # Plus de tokens pour batch
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


def categorize_all_with_ai_batch(input_file: Path, output_dir: Path, api_key: str, batch_size: int = 10, max_items: Optional[int] = None):
    """
    Catégorise tous les items localStorage avec l'IA en mode batch.
    """
    print(f"\nAnalyse IA localStorage (BATCH MODE) : {input_file.name}")
    print(f"Taille batch: {batch_size} items")
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
    
    # Statistiques
    stats = {
        'total': len(items),
        'analyzed': len(enriched_items),
        'failed': 0,
        'categories_count': Counter(),
        'avg_confidence': 0,
        'avg_risk_score': 0,
        'gdpr_violations_count': 0
    }
    
    print(f"\nAnalyse en cours (batches de {batch_size})...")
    
    SAVE_INTERVAL = 30  # Sauvegarder tous les 30 items
    
    # Traiter par batches
    for batch_start in range(start_index, len(items), batch_size):
        batch_end = min(batch_start + batch_size, len(items))
        items_batch = items[batch_start:batch_end]
        
        print(f"\n  Batch [{batch_start+1}-{batch_end}/{len(items)}]...", end=' ')
        
        # Analyser batch avec IA
        analyses = analyze_batch_with_ai(items_batch, user_profile, categories, client)
        
        if analyses and len(analyses) == len(items_batch):
            # Enrichir items avec analyses
            for i, (item, analysis) in enumerate(zip(items_batch, analyses)):
                enriched_item = {
                    **item,
                    '_ai_analysis': analysis
                }
                enriched_items.append(enriched_item)
                
                # Stats
                stats['analyzed'] += 1
                stats['categories_count'][analysis.get('primary_category', 'UNKNOWN')] += 1
                stats['avg_confidence'] += analysis.get('confidence', 0)
                stats['avg_risk_score'] += analysis.get('risk_score', 0)
                stats['gdpr_violations_count'] += len(analysis.get('gdpr_violations', []))
            
            print(f"OK ({len(analyses)} items)")
        else:
            print(f"FAILED (attendu {len(items_batch)}, reçu {len(analyses) if analyses else 0})")
            stats['failed'] += len(items_batch)
        
        # Sauvegarde incrémentale
        if len(enriched_items) % SAVE_INTERVAL < batch_size:
            batch_num += 1
            save_progress(enriched_items, output_dir, batch_num)
        
        # Rate limiting
        if batch_end < len(items):
            time.sleep(2.5)  # Pause entre batches
    
    # Sauvegarde finale
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
        'categories_distribution': dict(stats['categories_count']),
        'batch_size': batch_size
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
    
    parser = argparse.ArgumentParser(description='Analyse localStorage avec IA (Batch Mode)')
    parser.add_argument('--api-key', help='Groq API key (ou variable GROQ_API_KEY)')
    parser.add_argument('--test', type=int, help='Mode test : nombre d\'items à analyser')
    parser.add_argument('--source', choices=['added', 'modified', 'both'], default='both')
    parser.add_argument('--batch-size', type=int, default=10, help='Taille des batches (défaut: 10)')
    
    args = parser.parse_args()
    
    # Récupérer API key
    api_key = args.api_key or os.environ.get('GROQ_API_KEY')
    
    if not api_key:
        print("Erreur: API key requise")
        print("Utilisez --api-key ou définissez GROQ_API_KEY")
        sys.exit(1)
    
    base_dir = Path(__file__).parent.parent
    input_dir = base_dir / 'preprocessing' / 'localstorage'
    output_base_dir = base_dir / 'ai_categorized_localstorage_batch'
    
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
            categorize_all_with_ai_batch(input_file, output_dir, api_key, batch_size=args.batch_size, max_items=args.test)
        else:
            print(f"\nFichier non trouvé: {input_file}")


if __name__ == '__main__':
    main()
