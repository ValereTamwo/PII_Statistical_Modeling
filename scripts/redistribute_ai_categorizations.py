#!/usr/bin/env python3
"""
AI CATEGORIZATION REDISTRIBUTION FOR INDEXEDDB

Reads ai_categorizations.json and redistributes items
into data/user/.../indexeddb/{CATEGORY}.json
Does NOT modify UNCATEGORIZED.json
"""

import json
import sys
from pathlib import Path
from typing import Dict, List
from collections import defaultdict, Counter

def redistribute_ai_categorizations(
    ai_categorizations_file: Path,
    user_indexeddb_dir: Path
):
    """
    Redistributes AI categorizations into category-specific files.
    Appends items to data/user/.../indexeddb/{CATEGORY}.json without modifying UNCATEGORIZED.json.
    """
    # Load AI-generated categorizations
    if not ai_categorizations_file.exists():
        print(f"  Warning: AI categorizations file not found: {ai_categorizations_file}")
        return None
    
    with open(ai_categorizations_file, "r", encoding="utf-8") as f:
        all_categorizations = json.load(f)
    
    # Load source UNCATEGORIZED items for data enrichment
    uncategorized_file = user_indexeddb_dir / "UNCATEGORIZED.json"
    if not uncategorized_file.exists():
        print(f"  Warning: UNCATEGORIZED.json introuvable")
        return None
        
    with open(uncategorized_file, "r", encoding="utf-8") as f:
        uncategorized_items = json.load(f)
    
    # Create a mapping from field_path to the original item
    field_to_item = {item.get("field_path"): item for item in uncategorized_items}
    
    # Grouper par catégorie (seulement les items recatégorisés, pas UNCATEGORIZED)
    items_by_category = defaultdict(list)
    
    stats = {
        "total_fields_processed": 0,
        "fields_recategorized": 0,
        "fields_still_uncategorized": 0,
        "categories_distribution": Counter()
    }
    
    # Parcourir les catégorisations AI
    for record_cat in all_categorizations:
        record_id = record_cat.get("record_id", "")
        
        for field_analysis in record_cat.get("fields", []):
            field_path = field_analysis.get("field_path", "")
            category_raw = field_analysis.get("category", "UNCATEGORIZED")
            confidence = field_analysis.get("confidence", 0.0)
            explanation = field_analysis.get("explanation", "")
            
            stats["total_fields_processed"] += 1
            
            # Trouver l'item original
            original_item = field_to_item.get(field_path)
            if not original_item:
                continue
            
            # Parser la catégorie (peut être "CATEGORY" ou "CATEGORY.subcategory")
            if "." in category_raw:
                # Format: "SECURITY_AND_BOT_MITIGATION.auth_security"
                main_category, subcategory = category_raw.split(".", 1)
            else:
                # Format: "BEHAVIORAL_DATA"
                main_category = category_raw
                subcategory = "ai_context_aware"
            
            # Si la catégorie est UNCATEGORIZED, on ne fait rien (reste dans UNCATEGORIZED.json)
            if main_category == "UNCATEGORIZED":
                stats["fields_still_uncategorized"] += 1
                continue
            
            # Enrichir l'item pour les catégories non-UNCATEGORIZED
            enriched_item = original_item.copy()
            enriched_item["ai_categorized"] = True
            enriched_item["ai_confidence"] = confidence
            enriched_item["ai_explanation"] = explanation
            enriched_item["record_id"] = record_id
            enriched_item["matched_subcategory"] = subcategory
            enriched_item["match_type"] = "ai_analysis"
            
            items_by_category[main_category].append(enriched_item)
            stats["fields_recategorized"] += 1
            stats["categories_distribution"][main_category] += 1
    
    # Sauvegarder dans les fichiers de catégories de data/user/.../indexeddb/
    for category, new_items in items_by_category.items():
        category_file = user_indexeddb_dir / f"{category}.json"
        
        # Charger items existants si le fichier existe
        existing_items = []
        if category_file.exists():
            try:
                with open(category_file, "r", encoding="utf-8") as f:
                    existing_items = json.load(f)
            except:
                existing_items = []
        
        # Fusionner
        all_items = existing_items + new_items
        
        # Sauvegarder
        with open(category_file, "w", encoding="utf-8") as f:
            json.dump(all_items, f, indent=2, ensure_ascii=False)
        
        print(f"     {category}: +{len(new_items)} items (total: {len(all_items)})")
    
    # NE PAS toucher  UNCATEGORIZED.json - il reste tel quel
    print(f"     UNCATEGORIZED.json: inchangé ({stats['fields_still_uncategorized']} items y restent)")
    
    return stats

# =====================================================================
# MAIN
# =====================================================================

def main():
    """Point d'entrée principal."""
    base_dir = Path(__file__).resolve().parent.parent / "data"
    aggregates_ai_base = base_dir / "aggregates_ai_complete" / "indexeddb"
    user_base = base_dir / "user"
    
    print("=" * 80)
    print("REDISTRIBUTION DES CATÉGORISATIONS AI - INDEXEDDB")
    print("=" * 80)
    
    users = ["FR_0417", "FR_0446", "FR_0458"]
    
    total_stats = {
        "total_fields_processed": 0,
        "fields_recategorized": 0,
        "fields_still_uncategorized": 0,
        "categories_distribution": Counter()
    }
    
    for auth in ["Auth", "UnAuth"]:
        for user in users:
            for policy in ["ALL", "PARTIAL", "NONE"]:
                ai_cat_file = aggregates_ai_base / auth / user / policy / "ai_categorizations.json"
                user_dir = user_base / auth / user / policy / "indexeddb"
                
                if not ai_cat_file.exists():
                    continue
                
                print(f"\n {auth}/{user}/{policy}")
                
                stats = redistribute_ai_categorizations(
                    ai_cat_file,
                    user_dir
                )
                
                if stats:
                    total_stats["total_fields_processed"] += stats["total_fields_processed"]
                    total_stats["fields_recategorized"] += stats["fields_recategorized"]
                    total_stats["fields_still_uncategorized"] += stats["fields_still_uncategorized"]
                    total_stats["categories_distribution"].update(stats["categories_distribution"])
                    
                    print(f"  OK {stats['fields_recategorized']} fields recatégorisés")
                    print(f"  OK {stats['fields_still_uncategorized']} fields restent UNCATEGORIZED")
    
    # Résumé global
    print("\n" + "=" * 80)
    print("RÉSUMÉ GLOBAL")
    print("=" * 80)
    print(f"Total fields traités: {total_stats['total_fields_processed']}")
    print(f"Fields recatégorisés: {total_stats['fields_recategorized']}")
    print(f"Fields UNCATEGORIZED: {total_stats['fields_still_uncategorized']}")
    
    if total_stats['categories_distribution']:
        print(f"\nDistribution des catégories:")
        for cat, count in total_stats['categories_distribution'].most_common():
            print(f"  {cat}: {count}")
    
    print("\n REDISTRIBUTION TERMINÉE")

if __name__ == "__main__":
    main()
