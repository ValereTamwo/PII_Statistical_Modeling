#!/usr/bin/env python3
"""
Script pour extraire les données localStorage des fichiers JSON.
Génre des fichiers JSON pour les entrées ajoutées et modifiées.
"""

import json
from pathlib import Path


def extract_added_localstorage(data, task_id):
    """Extrait les entrées localStorage ajoutées d'un fichier JSON"""
    entries = []
    
    added = data.get('localStorage', {}).get('added', {})
    metadata = data.get('metadata', {})
    
    for key, value in added.items():
        entry_info = {
            'task_id': task_id,
            'key': key,
            'value': value,
            'value_length': len(str(value)),
            'initial_url': metadata.get('initial url', ''),
            'final_url': metadata.get('final_url', ''),
            'timestamp': metadata.get('timestamp', '')
        }
        entries.append(entry_info)
    
    return entries


def extract_modified_localstorage(data, task_id):
    """Extrait les entrées localStorage modifiées d'un fichier JSON"""
    entries = []
    
    modified = data.get('localStorage', {}).get('modified', {})
    metadata = data.get('metadata', {})
    
    for key, change_data in modified.items():
        from_value = change_data.get('from', '') if isinstance(change_data, dict) else ''
        to_value = change_data.get('to', '') if isinstance(change_data, dict) else ''
        
        # Si ce n'est pas un dict avec from/to, c'est peut-être une valeur directe
        if not isinstance(change_data, dict):
            from_value = ''
            to_value = change_data
        
        entry_info = {
            'task_id': task_id,
            'key': key,
            'value': to_value,
            'value_from': from_value,
            'value_to': to_value,
            'value_from_length': len(str(from_value)),
            'value_to_length': len(str(to_value)),
            'value_changed': from_value != to_value,
            'initial_url': metadata.get('initial url', ''),
            'final_url': metadata.get('final_url', ''),
            'timestamp': metadata.get('timestamp', '')
        }
        entries.append(entry_info)
    
    return entries


def extract_removed_localstorage(data, task_id):
    """Extrait les entrées localStorage supprimées d'un fichier JSON"""
    entries = []
    
    removed = data.get('localStorage', {}).get('removed', {})
    metadata = data.get('metadata', {})
    
    for key, value in removed.items():
        entry_info = {
            'task_id': task_id,
            'key': key,
            'value': value,
            'value_length': len(str(value)),
            'initial_url': metadata.get('initial url', ''),
            'final_url': metadata.get('final_url', ''),
            'timestamp': metadata.get('timestamp', '')
        }
        entries.append(entry_info)
    
    return entries


def main():



    base_dir = Path(__file__).resolve().parent.parent / 'data'
    if not base_dir.exists():
        print(f"Dossier {base_dir} non trouvé")
        return
    users  = ('FR_0417', 'FR_0446', 'FR_0458')
    auth_statuses = ('Auth', 'UnAuth')
    
    policies = ('ALL', 'PARTIAL', 'NONE')

    for user in users:
        for auth_status in auth_statuses:
            for policy in policies:
                # Chemin dynamique : NotAUTH si UnAuth, sinon Auth
                storage_state_folder = 'NotAUTH' if auth_status == 'UnAuth' else 'Auth'
                input_dir = base_dir / 'raw' / auth_status / user / policy / 'storage_state' / storage_state_folder / policy.lower()
                if not input_dir.exists():
                    print(f"Le dossier {input_dir} n'existe pas, passage  la configuration suivante.")
                    continue
                output_dir = base_dir / 'preprocessing' / auth_status / user / policy / 'localstorage'
                output_dir.mkdir(parents=True, exist_ok=True)   

                all_added_entries = []
                all_modified_entries = []
                all_removed_entries = []
                
                # Parcourir tous les fichiers JSON
                json_files = sorted(input_dir.glob('*.json'), key=lambda x: int(x.stem))
                
                print(f"=== Extraction du localStorage ===\n")
                print(f"Traitement de {len(json_files)} fichiers JSON...\n")
                
                for json_file in json_files:
                    task_id = json_file.stem
                    
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        # Extraire les entrées ajoutées
                        added = extract_added_localstorage(data, task_id)
                        all_added_entries.extend(added)
                        
                        # Extraire les entrées modifiées
                        modified = extract_modified_localstorage(data, task_id)
                        all_modified_entries.extend(modified)
                        
                        # Extraire les entrées supprimées
                        removed = extract_removed_localstorage(data, task_id)
                        all_removed_entries.extend(removed)
                        
                    except Exception as e:
                        print(f" Erreur lors du traitement de {json_file.name}: {e}")
                
                print(f"{len(json_files)} fichiers traités\n")
                
                # Sauvegarder en JSON
                print("Génération des fichiers JSON...\n")
                
                if all_added_entries:
                    output_file = output_dir / 'added_localstorage.json'
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(all_added_entries, f, ensure_ascii=False, indent=2)
                    
                    print(f" {len(all_added_entries)} entrées localStorage ajoutées  {output_file}")
                else:
                    print(" Aucune entrée localStorage ajoutée")
                
                if all_modified_entries:
                    output_file = output_dir / 'modified_localstorage.json'
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(all_modified_entries, f, ensure_ascii=False, indent=2)
                    
                    print(f" {len(all_modified_entries)} entrées localStorage modifiées  {output_file}")
                else:
                    print(" Aucune entrée localStorage modifiée")
                
                if all_removed_entries:
                    output_file = output_dir / 'removed_localstorage.json'
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(all_removed_entries, f, ensure_ascii=False, indent=2)
                    
                    print(f" {len(all_removed_entries)} entrées localStorage supprimées  {output_file}")
                else:
                    print(" Aucune entrée localStorage supprimée")
                
                print("\n=== Extraction terminée ===")


if __name__ == '__main__':
    main()
