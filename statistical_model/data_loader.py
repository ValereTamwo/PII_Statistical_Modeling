import os
import json
import pandas as pd
import numpy as np

def load_all_data(base_path):
    """
    Traverse the results directory and load data from analysis.json files.
    Structure: base_path/Auth|UnAuth/User/Policy/Storage/added|modified|deleted/consolidated/analysis.json
    """
    data = []
    # Walk through results/Auth and results/UnAuth
    for auth_status in ['Auth', 'UnAuth']:
        auth_path = os.path.join(base_path, auth_status)
        if not os.path.exists(auth_path):
            print(f"Warning: Path not found: {auth_path}")
            continue
            
        for user in os.listdir(auth_path):
            user_path = os.path.join(auth_path, user)
            if not os.path.isdir(user_path):
                continue
                
            for policy in os.listdir(user_path):
                policy_path = os.path.join(user_path, policy)
                if not os.path.isdir(policy_path):
                    continue
                    
                for storage in os.listdir(policy_path):
                    storage_path = os.path.join(policy_path, storage)
                    
                    # Initialize metrics
                    row = {
                        'auth': auth_status,
                        'user': user,
                        'policy': policy,
                        'storage': storage,
                        'l_added': 0,
                        'l_modified': 0,
                        'l_deleted': 0,
                        'pii_count': 0,
                        'critical_risk': 0,
                        'high_risk': 0,
                        'medium_risk': 0,
                        'low_risk': 0
                    }
                    
                    # Strategy depends on storage type
                    if storage == 'cookies':
                        # 1. Cookies: ADDED
                        added_json = os.path.join(storage_path, 'added', 'consolidated', 'analysis.json')
                        if os.path.exists(added_json):
                            try:
                                with open(added_json, 'r') as f:
                                    content = json.load(f)
                                    row['l_added'] = content.get('total_cookies', 0)
                                    row['pii_count'] = content.get('direct_pii_count', 0)
                                    row['critical_risk'] = content.get('risk_levels', {}).get('Critical Risk', 0)
                                    row['high_risk'] = content.get('risk_levels', {}).get('High Risk', 0)
                                    row['medium_risk'] = content.get('risk_levels', {}).get('Medium Risk', 0)
                                    row['low_risk'] = content.get('risk_levels', {}).get('Low Risk', 0)
                            except Exception as e:
                                print(f"Error reading {added_json}: {e}")

                        # 2. Cookies: MODIFIED
                        modified_json = os.path.join(storage_path, 'modified', 'consolidated', 'analysis.json')
                        if os.path.exists(modified_json):
                            try:
                                with open(modified_json, 'r') as f:
                                    content = json.load(f)
                                    row['l_modified'] = content.get('total_cookies', 0)
                            except Exception as e:
                                print(f"Error reading {modified_json}: {e}")

                        # 3. Cookies: REMOVED/DELETED (chercher removed d'abord, puis deleted)
                        removed_json = os.path.join(storage_path, 'removed', 'consolidated', 'analysis.json')
                        deleted_json = os.path.join(storage_path, 'deleted', 'consolidated', 'analysis.json')
                        
                        if os.path.exists(removed_json):
                            try:
                                with open(removed_json, 'r') as f:
                                    content = json.load(f)
                                    row['l_deleted'] = content.get('total_cookies', 0)
                            except Exception as e:
                                print(f"Error reading {removed_json}: {e}")
                        elif os.path.exists(deleted_json):
                            try:
                                with open(deleted_json, 'r') as f:
                                    content = json.load(f)
                                    row['l_deleted'] = content.get('total_cookies', 0)
                            except Exception as e:
                                pass

                    else:
                        # LocalStorage, SessionStorage, IndexedDB
                        # 1. ADDED
                        added_json = os.path.join(storage_path, 'added', 'consolidated', 'analysis.json')
                        if os.path.exists(added_json):
                            try:
                                with open(added_json, 'r') as f:
                                    content = json.load(f)
                                    row['l_added'] = content.get('total_items', 0)
                                    row['pii_count'] = content.get('direct_pii_count', 0)
                                    row['critical_risk'] = content.get('risk_levels', {}).get('Critical Risk', 0)
                                    row['high_risk'] = content.get('risk_levels', {}).get('High Risk', 0)
                                    row['medium_risk'] = content.get('risk_levels', {}).get('Medium Risk', 0)
                                    row['low_risk'] = content.get('risk_levels', {}).get('Low Risk', 0)
                            except Exception as e:
                                print(f"Error reading {added_json}: {e}")
                        
                        # 2. MODIFIED
                        modified_json = os.path.join(storage_path, 'modified', 'consolidated', 'analysis.json')
                        if os.path.exists(modified_json):
                            try:
                                with open(modified_json, 'r') as f:
                                    content = json.load(f)
                                    row['l_modified'] = content.get('total_items', 0)
                            except Exception as e:
                                print(f"Error reading {modified_json}: {e}")
                        
                        # 3. REMOVED/DELETED (chercher removed d'abord, puis deleted)
                        removed_json = os.path.join(storage_path, 'removed', 'consolidated', 'analysis.json')
                        deleted_json = os.path.join(storage_path, 'deleted', 'consolidated', 'analysis.json')
                        
                        if os.path.exists(removed_json):
                            try:
                                with open(removed_json, 'r') as f:
                                    content = json.load(f)
                                    row['l_deleted'] = content.get('total_items', 0)
                            except Exception as e:
                                print(f"Error reading {removed_json}: {e}")
                        elif os.path.exists(deleted_json):
                            try:
                                with open(deleted_json, 'r') as f:
                                    content = json.load(f)
                                    row['l_deleted'] = content.get('total_items', 0)
                            except Exception as e:
                                print(f"Error reading {deleted_json}: {e}")
                        else:
                            # Fallback: lifecycle/lifecycle_data.json (compatibilité ancienne structure)
                            lifecycle_json = os.path.join(storage_path, 'lifecycle', 'lifecycle_data.json')
                            if os.path.exists(lifecycle_json):
                                try:
                                    with open(lifecycle_json, 'r') as f:
                                        content = json.load(f)
                                        metrics = content.get('metrics', {})
                                        # Ne pas écraser l_modified si déj chargé
                                        if row['l_modified'] == 0:
                                            row['l_modified'] = metrics.get('items_modified', 0)
                                        if row['l_deleted'] == 0:
                                            row['l_deleted'] = metrics.get('items_deleted', 0)
                                except Exception as e:
                                    print(f"Error reading {lifecycle_json}: {e}")


                    data.append(row)
                            
    return pd.DataFrame(data)
