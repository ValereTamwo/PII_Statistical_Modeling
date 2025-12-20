#!/usr/bin/env python3
"""
Script d'extraction IndexedDB
Extrait les données IndexedDB des fichiers JSON pour chaque configuration
"""

import json
from pathlib import Path
import shutil


def extract_indexeddb_for_config(config_dir: Path, output_dir: Path):
    """
    Extrait les fichiers IndexedDB pour une configuration
    
    Args:
        config_dir: Dossier de configuration (ex: data/raw/Auth/FR_0017/ALL)
        output_dir: Dossier de sortie (ex: FR_0017/indexedDB)
    """
    
    # Dossier IndexedDB source
    indexeddb_source = config_dir / "IndexedDB"
    
    if not indexeddb_source.exists():
        print(f"    IndexedDB non trouvé dans {config_dir}")
        return 0
    
    # Créer dossier de sortie
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Copier tous les fichiers JSON
    json_files = list(indexeddb_source.glob("*.json"))
    
    for json_file in json_files:
        dest_file = output_dir / json_file.name
        shutil.copy2(json_file, dest_file)
    
    return len(json_files)


def extract_all_indexeddb():
    """
    Extrait IndexedDB pour toutes les configurations
    """
    
    print("=" * 70)
    print("EXTRACTION INDEXEDDB")
    print("=" * 70)
    
    raw_dir = Path(__file__).resolve().parent.parent / 'data' / 'raw'
    
    if not raw_dir.exists():
        print(f" dossier {raw_dir} non trouvé")
        return
    
    users = ['FR_0017', 'FR_0018', 'FR_0019']
    auth_statuses = ['Auth', 'UnAuth']
    policies = ['ALL', 'PARTIAL', 'NONE']
    
    total_files = 0
    base_dir = Path(__file__).resolve().parent.parent / 'data'
    
    for auth in auth_statuses:
        
        for user in users:
            
            for policy in policies:
                config_dir = raw_dir / auth / user / policy
                
                if not config_dir.exists():
                    continue
                
                # Dossier de sortie
                output_dir = base_dir / 'preprocessing' / auth / user / policy / 'indexeddb'
                
                # Extraire
                count = extract_indexeddb_for_config(config_dir, output_dir)
                
                if count > 0:
                    print(f"     {policy:8s} : {count} fichiers IndexedDB")
                    total_files += count
    


if __name__ == '__main__':
    try:
        extract_all_indexeddb()
        
        print(" EXTRACTION TERMINÉE!")
        
    except Exception as e:
        print(f"\ ERREUR: {e}")
        import traceback
        traceback.print_exc()
