import os
import json
import pandas as pd
from collections import defaultdict
from typing import Dict, List, Any, Tuple
import copy


def load_analysis_files(base_path: str) -> List[Dict[str, Any]]:
    """
    Load all analysis.json files with metadata.
    
    Returns:
        List of dicts with keys: auth, user, policy, storage, lifecycle, data
    """
    analysis_files = []
    
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
                    
                    if storage == 'cookies':
                        for lifecycle in ['added', 'modified', 'removed', 'deleted']:
                            analysis_json = os.path.join(storage_path, lifecycle, 'consolidated', 'analysis.json')
                            if os.path.exists(analysis_json):
                                try:
                                    with open(analysis_json, 'r') as f:
                                        data = json.load(f)
                                        analysis_files.append({
                                            'auth': auth_status,
                                            'user': user,
                                            'policy': policy,
                                            'storage': storage,
                                            'lifecycle': lifecycle,
                                            'data': data
                                        })
                                except Exception as e:
                                    print(f"Error reading {analysis_json}: {e}")
                        for lifecycle in ['added', 'modified', 'removed', 'deleted']:
                            analysis_json = os.path.join(storage_path, lifecycle, 'consolidated', 'analysis.json')
                            if os.path.exists(analysis_json):
                                try:
                                    with open(analysis_json, 'r') as f:
                                        data = json.load(f)
                                        analysis_files.append({
                                            'auth': auth_status,
                                            'user': user,
                                            'policy': policy,
                                            'storage': storage,
                                            'lifecycle': lifecycle,
                                            'data': data
                                        })
                                except Exception as e:
                                    print(f"Error reading {analysis_json}: {e}")
    
    return analysis_files


def merge_pii_distributions(distributions: List[Dict[str, Dict[str, int]]]) -> Dict[str, Dict[str, int]]:
    """
    Merge multiple PII-classified distributions.
    
    Args:
        distributions: List of dicts like {pii_class: {attribute: count}}
    
    Returns:
        Merged distribution
    """
    merged = defaultdict(lambda: defaultdict(int))
    
    for dist in distributions:
        for pii_class, attrs in dist.items():
            for attr, count in attrs.items():
                merged[pii_class][attr] += count
    
    return {k: dict(v) for k, v in merged.items()}


def merge_simple_distributions(distributions: List[Dict[str, int]]) -> Dict[str, int]:
    """
    Merge multiple simple distributions.
    
    Args:
        distributions: List of dicts like {attribute: count}
    
    Returns:
        Merged distribution
    """
    merged = defaultdict(int)
    
    for dist in distributions:
        for attr, count in dist.items():
            merged[attr] += count
    
    return dict(merged)


def aggregate_cookie_data(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate cookie-specific data from multiple analysis files.
    
    Args:
        files: List of analysis file dicts (filtered for cookies only)
    
    Returns:
        Aggregated cookie data
    """
    # Initialize aggregated structure
    aggregated = {
        'total_cookies': 0,
        'direct_pii_count': 0,
        'other_count': 0,
        'lifetime_distribution': defaultdict(int),
        'lifetime_by_pii': [],
        'httponly_distribution': defaultdict(int),
        'httponly_by_pii': [],
        'secure_distribution': defaultdict(int),
        'secure_by_pii': [],
        'samesite_distribution': defaultdict(int),
        'samesite_by_pii': [],
        'security_matrix': defaultdict(int),
        'security_by_pii': [],
        'thirdparty_distribution': defaultdict(int),
        'thirdparty_by_pii': [],
        'thirdparty_httponly': defaultdict(int),
        'thirdparty_secure': defaultdict(int),
        'risk_levels': defaultdict(int),
        'risk_by_pii': [],
        'keywords': defaultdict(int),
        'content_hierarchy': [],
        'content_types': defaultdict(int),
        'vendor_counts': defaultdict(int)
    }
    
    # Aggregate each file
    for file_info in files:
        data = file_info['data']
        
        # Simple counts
        aggregated['total_cookies'] += data.get('total_cookies', 0)
        aggregated['direct_pii_count'] += data.get('direct_pii_count', 0)
        aggregated['other_count'] += data.get('other_count', 0)
        
        # Simple distributions
        for key in ['lifetime_distribution', 'httponly_distribution', 'secure_distribution',
                    'samesite_distribution', 'security_matrix', 'thirdparty_distribution',
                    'thirdparty_httponly', 'thirdparty_secure', 'risk_levels',
                    'keywords', 'content_types', 'vendor_counts']:
            if key in data:
                for attr, count in data[key].items():
                    aggregated[key][attr] += count
        
        # PII-classified distributions
        for key in ['lifetime_by_pii', 'httponly_by_pii', 'secure_by_pii', 'samesite_by_pii',
                    'security_by_pii', 'thirdparty_by_pii', 'risk_by_pii', 'content_hierarchy']:
            if key in data:
                aggregated[key].append(data[key])
    
    # Merge PII-classified distributions
    for key in ['lifetime_by_pii', 'httponly_by_pii', 'secure_by_pii', 'samesite_by_pii',
                'security_by_pii', 'thirdparty_by_pii', 'risk_by_pii', 'content_hierarchy']:
        if aggregated[key]:
            aggregated[key] = merge_pii_distributions(aggregated[key])
    
    # Convert defaultdicts to regular dicts
    return {k: dict(v) if isinstance(v, defaultdict) else v for k, v in aggregated.items()}


def aggregate_storage_data(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate data for non-cookie storage types (localStorage, sessionStorage, IndexedDB).
    
    Args:
        files: List of analysis file dicts
    
    Returns:
        Aggregated storage data
    """
    aggregated = {
        'total_items': 0,
        'direct_pii_count': 0,
        'other_count': 0,
        'risk_levels': defaultdict(int),
        'risk_by_pii': [],
        'content_hierarchy': [],
        'content_types': defaultdict(int),
        'vendor_counts': defaultdict(int)
    }
    
    for file_info in files:
        data = file_info['data']
        
        aggregated['total_items'] += data.get('total_items', 0)
        aggregated['direct_pii_count'] += data.get('direct_pii_count', 0)
        aggregated['other_count'] += data.get('other_count', 0)
        
        for key in ['risk_levels', 'content_types', 'vendor_counts']:
            if key in data:
                for attr, count in data[key].items():
                    aggregated[key][attr] += count
        
        for key in ['risk_by_pii', 'content_hierarchy']:
            if key in data:
                aggregated[key].append(data[key])
    
    # Merge PII-classified distributions
    for key in ['risk_by_pii', 'content_hierarchy']:
        if aggregated[key]:
            aggregated[key] = merge_pii_distributions(aggregated[key])
    
    return {k: dict(v) if isinstance(v, defaultdict) else v for k, v in aggregated.items()}


def aggregate_by_dimension(files: List[Dict[str, Any]], 
                          group_by: List[str],
                          storage_type: str = None) -> Dict[Tuple, Dict[str, Any]]:
    """
    Generic aggregation function that groups by specified dimensions.
    
    Args:
        files: List of analysis file dicts
        group_by: List of dimension names to group by (e.g., ['auth', 'policy'])
        storage_type: Optional storage type filter ('cookies', 'localstorage', etc.)
    
    Returns:
        Dict mapping dimension tuples to aggregated data
    """
    # Filter by storage type if specified
    if storage_type:
        files = [f for f in files if f['storage'] == storage_type]
    
    # Group files by dimensions
    grouped = defaultdict(list)
    for file_info in files:
        key = tuple(file_info[dim] for dim in group_by)
        grouped[key].append(file_info)
    
    # Aggregate each group
    aggregated = {}
    for key, group_files in grouped.items():
        # Determine storage type from first file
        storage = group_files[0]['storage']
        
        # For all storage types, only aggregate 'added' lifecycle
        added_files = [f for f in group_files if f['lifecycle'] == 'added']
        
        if not added_files:
            continue
            
        if storage == 'cookies':
            aggregated[key] = aggregate_cookie_data(added_files)
        else:
            aggregated[key] = aggregate_storage_data(added_files)
    
    return aggregated


def aggregate_per_user(files: List[Dict[str, Any]], storage_type: str) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate all metrics for each user individually.
    
    Args:
        files: List of analysis file dicts
        storage_type: Storage type to aggregate
    
    Returns:
        Dict mapping user_auth_policy to aggregated data
    """
    result = aggregate_by_dimension(files, ['user', 'auth', 'policy'], storage_type)
    
    # Convert tuple keys to string keys
    return {f"{k[0]}_{k[1]}_{k[2]}": v for k, v in result.items()}


def aggregate_per_policy(files: List[Dict[str, Any]], storage_type: str) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate across users, grouped by policy and auth mode.
    
    Args:
        files: List of analysis file dicts
        storage_type: Storage type to aggregate
    
    Returns:
        Dict mapping policy_auth to aggregated data
    """
    result = aggregate_by_dimension(files, ['policy', 'auth'], storage_type)
    
    # Convert tuple keys to string keys
    return {f"{k[0]}_{k[1]}": v for k, v in result.items()}


def aggregate_per_mode(files: List[Dict[str, Any]], storage_type: str) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate across policies, grouped by auth mode.
    
    Args:
        files: List of analysis file dicts
        storage_type: Storage type to aggregate
    
    Returns:
        Dict mapping auth mode to aggregated data
    """
    result = aggregate_by_dimension(files, ['auth'], storage_type)
    
    # Convert tuple keys to string keys
    return {k[0]: v for k, v in result.items()}


def aggregate_global(files: List[Dict[str, Any]], storage_type: str) -> Dict[str, Any]:
    """
    Aggregate entire dataset for a storage type.
    
    Args:
        files: List of analysis file dicts
        storage_type: Storage type to aggregate
    
    Returns:
        Aggregated data for entire dataset
    """
    # Filter by storage type
    filtered = [f for f in files if f['storage'] == storage_type]
    
    if storage_type == 'cookies':
        # Only aggregate 'added' lifecycle
        cookie_added = [f for f in filtered if f['lifecycle'] == 'added']
        return aggregate_cookie_data(cookie_added)
    else:
        return aggregate_storage_data(filtered)


def create_aggregations(base_path: str, output_path: str):
    """
    Create all aggregation levels and save to output directory.
    
    Args:
        base_path: Path to results directory
        output_path: Path to save aggregations
    """
    print("Loading analysis files...")
    files = load_analysis_files(base_path)
    print(f"Loaded {len(files)} analysis files")
    
    storage_types = ['cookies', 'localstorage', 'sessionstorage', 'indexeddb']
    
    for storage in storage_types:
        print(f"\nAggregating {storage}...")
        storage_output = os.path.join(output_path, storage)
        
        # Per-user aggregation
        print(f"  - Per-user aggregation")
        per_user = aggregate_per_user(files, storage)
        per_user_path = os.path.join(storage_output, 'per_user')
        os.makedirs(per_user_path, exist_ok=True)
        for key, data in per_user.items():
            with open(os.path.join(per_user_path, f'{key}.json'), 'w') as f:
                json.dump(data, f, indent=2)
        
        # Per-policy aggregation
        print(f"  - Per-policy aggregation")
        per_policy = aggregate_per_policy(files, storage)
        per_policy_path = os.path.join(storage_output, 'per_policy')
        os.makedirs(per_policy_path, exist_ok=True)
        for key, data in per_policy.items():
            with open(os.path.join(per_policy_path, f'{key}.json'), 'w') as f:
                json.dump(data, f, indent=2)
        
        # Per-mode aggregation
        print(f"  - Per-mode aggregation")
        per_mode = aggregate_per_mode(files, storage)
        per_mode_path = os.path.join(storage_output, 'per_mode')
        os.makedirs(per_mode_path, exist_ok=True)
        for key, data in per_mode.items():
            with open(os.path.join(per_mode_path, f'{key}.json'), 'w') as f:
                json.dump(data, f, indent=2)
        
        # Global aggregation
        print(f"  - Global aggregation")
        global_data = aggregate_global(files, storage)
        with open(os.path.join(storage_output, 'global.json'), 'w') as f:
            json.dump(global_data, f, indent=2)
    
    print(f"\nAggregations saved to {output_path}")
    
    # Create summary tables
    print("\nCreating summary tables for paper...")
    create_summary_tables(output_path)
    
    # # Create visualizations
    # print("\nCreating visualizations...")
    # try:
    #     from aggregation_viz import create_aggregation_visualizations
    #     create_aggregation_visualizations(output_path)
    # except Exception as e:
    #     print(f"Warning: Could not create visualizations: {e}")



def create_summary_tables(aggregations_path: str):
    """
    Create CSV summary tables from aggregations for paper inclusion.
    
    Args:
        aggregations_path: Path to aggregations directory
    """
    summary_path = os.path.join(aggregations_path, 'summary_tables')
    os.makedirs(summary_path, exist_ok=True)
    
    # Table 1: Cookie Security Attributes by Policy
    print("  - Cookie security by policy")
    create_cookie_security_by_policy_table(aggregations_path, summary_path)
    
    # Table 2: Cookie Security Attributes by Mode
    print("  - Cookie security by mode")
    create_cookie_security_by_mode_table(aggregations_path, summary_path)
    
    # Table 3: PII Distribution by Storage Type
    print("  - PII distribution by storage")
    create_pii_by_storage_table(aggregations_path, summary_path)
    
    # Table 4: Cookie Security by PII Class (detailed)
    print("  - Cookie security by PII class")
    create_cookie_security_by_pii_table(aggregations_path, summary_path)
    
    # Table 5: Risk Levels by Policy and Mode
    print("  - Risk levels by policy and mode")
    create_risk_by_policy_mode_table(aggregations_path, summary_path)
    
    print(f"Summary tables saved to {summary_path}")


def create_cookie_security_by_policy_table(agg_path: str, output_path: str):
    """Create table of cookie security attributes aggregated by consent policy."""
    policies = ['ALL', 'PARTIAL', 'NONE']
    modes = ['Auth', 'UnAuth']
    
    rows = []
    for policy in policies:
        for mode in modes:
            file_path = os.path.join(agg_path, 'cookies', 'per_policy', f'{policy}_{mode}.json')
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                    total = data.get('total_cookies', 0)
                    httponly_true = data.get('httponly_distribution', {}).get('True', 0)
                    httponly_false = data.get('httponly_distribution', {}).get('False', 0)
                    secure_true = data.get('secure_distribution', {}).get('True', 0)
                    secure_false = data.get('secure_distribution', {}).get('False', 0)
                    samesite_lax = data.get('samesite_distribution', {}).get('Lax', 0)
                    samesite_strict = data.get('samesite_distribution', {}).get('Strict', 0)
                    samesite_none = data.get('samesite_distribution', {}).get('No Restriction', 0)
                    third_party = data.get('thirdparty_distribution', {}).get('Third-Party', 0)
                    first_party = data.get('thirdparty_distribution', {}).get('First-Party', 0)
                    
                    rows.append({
                        'Policy': policy,
                        'Mode': mode,
                        'Total_Cookies': total,
                        # HttpOnly - Conformity
                        'HttpOnly_Count': httponly_true,
                        'HttpOnly_Pct': f"{(httponly_true/total*100):.1f}%" if total > 0 else "0%",
                        # HttpOnly - Non-Conformity
                        'HttpOnly_Missing_Count': httponly_false,
                        'HttpOnly_Missing_Pct': f"{(httponly_false/total*100):.1f}%" if total > 0 else "0%",
                        # Secure - Conformity
                        'Secure_Count': secure_true,
                        'Secure_Pct': f"{(secure_true/total*100):.1f}%" if total > 0 else "0%",
                        # Secure - Non-Conformity
                        'Secure_Missing_Count': secure_false,
                        'Secure_Missing_Pct': f"{(secure_false/total*100):.1f}%" if total > 0 else "0%",
                        # SameSite - Conformity
                        'SameSite_Lax': samesite_lax,
                        'SameSite_Strict': samesite_strict,
                        'SameSite_Protected_Pct': f"{((samesite_lax+samesite_strict)/total*100):.1f}%" if total > 0 else "0%",
                        # SameSite - Non-Conformity
                        'SameSite_Unprotected_Count': samesite_none,
                        'SameSite_Unprotected_Pct': f"{(samesite_none/total*100):.1f}%" if total > 0 else "0%",
                        # Third-Party (risk indicator)
                        'Third_Party_Count': third_party,
                        'Third_Party_Pct': f"{(third_party/total*100):.1f}%" if total > 0 else "0%",
                        # First-Party (safer)
                        'First_Party_Count': first_party,
                        'First_Party_Pct': f"{(first_party/total*100):.1f}%" if total > 0 else "0%"
                    })
    
    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(output_path, 'cookie_security_by_policy.csv'), index=False)


def create_cookie_security_by_mode_table(agg_path: str, output_path: str):
    """Create table of cookie security attributes aggregated by authentication mode."""
    modes = ['Auth', 'UnAuth']
    
    rows = []
    for mode in modes:
        file_path = os.path.join(agg_path, 'cookies', 'per_mode', f'{mode}.json')
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
                
                total = data.get('total_cookies', 0)
                httponly_true = data.get('httponly_distribution', {}).get('True', 0)
                httponly_false = data.get('httponly_distribution', {}).get('False', 0)
                secure_true = data.get('secure_distribution', {}).get('True', 0)
                secure_false = data.get('secure_distribution', {}).get('False', 0)
                samesite_lax = data.get('samesite_distribution', {}).get('Lax', 0)
                samesite_strict = data.get('samesite_distribution', {}).get('Strict', 0)
                samesite_none = data.get('samesite_distribution', {}).get('No Restriction', 0)
                third_party = data.get('thirdparty_distribution', {}).get('Third-Party', 0)
                first_party = data.get('thirdparty_distribution', {}).get('First-Party', 0)
                
                rows.append({
                    'Mode': mode,
                    'Total_Cookies': total,
                    # Conformity
                    'HttpOnly_Count': httponly_true,
                    'HttpOnly_Pct': f"{(httponly_true/total*100):.1f}%" if total > 0 else "0%",
                    'Secure_Count': secure_true,
                    'Secure_Pct': f"{(secure_true/total*100):.1f}%" if total > 0 else "0%",
                    'SameSite_Protected_Pct': f"{((samesite_lax+samesite_strict)/total*100):.1f}%" if total > 0 else "0%",
                    # Non-Conformity
                    'HttpOnly_Missing_Count': httponly_false,
                    'HttpOnly_Missing_Pct': f"{(httponly_false/total*100):.1f}%" if total > 0 else "0%",
                    'Secure_Missing_Count': secure_false,
                    'Secure_Missing_Pct': f"{(secure_false/total*100):.1f}%" if total > 0 else "0%",
                    'SameSite_Unprotected_Pct': f"{(samesite_none/total*100):.1f}%" if total > 0 else "0%",
                    # Party distribution
                    'Third_Party_Count': third_party,
                    'Third_Party_Pct': f"{(third_party/total*100):.1f}%" if total > 0 else "0%",
                    'First_Party_Count': first_party,
                    'First_Party_Pct': f"{(first_party/total*100):.1f}%" if total > 0 else "0%"
                })
    
    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(output_path, 'cookie_security_by_mode.csv'), index=False)


def create_pii_by_storage_table(agg_path: str, output_path: str):
    """Create table showing PII distribution across storage types."""
    storage_types = ['cookies', 'localstorage', 'sessionstorage', 'indexeddb']
    
    rows = []
    for storage in storage_types:
        file_path = os.path.join(agg_path, storage, 'global.json')
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
                
                total_key = 'total_cookies' if storage == 'cookies' else 'total_items'
                total = data.get(total_key, 0)
                pii_count = data.get('direct_pii_count', 0)
                
                # Count PII classes
                risk_by_pii = data.get('risk_by_pii', {})
                num_pii_classes = len(risk_by_pii)
                
                # Risk levels
                risk_levels = data.get('risk_levels', {})
                critical = risk_levels.get('Critical Risk', 0)
                high = risk_levels.get('High Risk', 0)
                medium = risk_levels.get('Medium Risk', 0)
                low = risk_levels.get('Low Risk', 0)
                
                rows.append({
                    'Storage_Type': storage.capitalize(),
                    'Total_Items': total,
                    'Direct_PII_Count': pii_count,
                    'Direct_PII_Pct': f"{(pii_count/total*100):.1f}%" if total > 0 else "0%",
                    'Num_PII_Classes': num_pii_classes,
                    'Critical_Risk': critical,
                    'High_Risk': high,
                    'Medium_Risk': medium,
                    'Low_Risk': low,
                    'High_Critical_Pct': f"{((critical+high)/total*100):.1f}%" if total > 0 else "0%"
                })
    
    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(output_path, 'pii_by_storage.csv'), index=False)


def create_cookie_security_by_pii_table(agg_path: str, output_path: str):
    """Create detailed table of cookie security attributes by PII classification."""
    file_path = os.path.join(agg_path, 'cookies', 'global.json')
    
    if not os.path.exists(file_path):
        print(f"Warning: {file_path} not found")
        return
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    httponly_by_pii = data.get('httponly_by_pii', {})
    secure_by_pii = data.get('secure_by_pii', {})
    samesite_by_pii = data.get('samesite_by_pii', {})
    thirdparty_by_pii = data.get('thirdparty_by_pii', {})
    risk_by_pii = data.get('risk_by_pii', {})
    
    # Get all PII classes
    all_pii_classes = set()
    for dist in [httponly_by_pii, secure_by_pii, samesite_by_pii, thirdparty_by_pii, risk_by_pii]:
        all_pii_classes.update(dist.keys())
    
    rows = []
    for pii_class in sorted(all_pii_classes):
        # Calculate totals for this PII class
        httponly_dist = httponly_by_pii.get(pii_class, {})
        total_cookies = sum(httponly_dist.values())
        
        if total_cookies == 0:
            continue
        
        httponly_true = httponly_dist.get('True', 0)
        httponly_false = httponly_dist.get('False', 0)
        
        secure_dist = secure_by_pii.get(pii_class, {})
        secure_true = secure_dist.get('True', 0)
        secure_false = secure_dist.get('False', 0)
        
        samesite_dist = samesite_by_pii.get(pii_class, {})
        samesite_protected = samesite_dist.get('Lax', 0) + samesite_dist.get('Strict', 0)
        samesite_unprotected = samesite_dist.get('No Restriction', 0)
        
        thirdparty_dist = thirdparty_by_pii.get(pii_class, {})
        third_party = thirdparty_dist.get('Third-Party', 0)
        first_party = thirdparty_dist.get('First-Party', 0)
        
        risk_dist = risk_by_pii.get(pii_class, {})
        critical = risk_dist.get('Critical Risk', 0)
        high = risk_dist.get('High Risk', 0)
        
        rows.append({
            'PII_Class': pii_class,
            'Total_Cookies': total_cookies,
            # Conformity
            'HttpOnly_Pct': f"{(httponly_true/total_cookies*100):.1f}%",
            'Secure_Pct': f"{(secure_true/total_cookies*100):.1f}%",
            'SameSite_Protected_Pct': f"{(samesite_protected/total_cookies*100):.1f}%",
            # Non-Conformity
            'HttpOnly_Missing_Pct': f"{(httponly_false/total_cookies*100):.1f}%",
            'Secure_Missing_Pct': f"{(secure_false/total_cookies*100):.1f}%",
            'SameSite_Unprotected_Pct': f"{(samesite_unprotected/total_cookies*100):.1f}%",
            # Party distribution
            'Third_Party_Pct': f"{(third_party/total_cookies*100):.1f}%",
            'First_Party_Pct': f"{(first_party/total_cookies*100):.1f}%",
            # Risk
            'Critical_Risk': critical,
            'High_Risk': high,
            'High_Critical_Pct': f"{((critical+high)/total_cookies*100):.1f}%"
        })
    
    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(output_path, 'cookie_security_by_pii_class.csv'), index=False)


def create_risk_by_policy_mode_table(agg_path: str, output_path: str):
    """Create table of risk levels by policy and mode."""
    policies = ['ALL', 'PARTIAL', 'NONE']
    modes = ['Auth', 'UnAuth']
    
    rows = []
    for policy in policies:
        for mode in modes:
            file_path = os.path.join(agg_path, 'cookies', 'per_policy', f'{policy}_{mode}.json')
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                    total = data.get('total_cookies', 0)
                    risk_levels = data.get('risk_levels', {})
                    
                    critical = risk_levels.get('Critical Risk', 0)
                    high = risk_levels.get('High Risk', 0)
                    medium = risk_levels.get('Medium Risk', 0)
                    low = risk_levels.get('Low Risk', 0)
                    
                    rows.append({
                        'Policy': policy,
                        'Mode': mode,
                        'Total_Cookies': total,
                        'Critical': critical,
                        'Critical_Pct': f"{(critical/total*100):.1f}%" if total > 0 else "0%",
                        'High': high,
                        'High_Pct': f"{(high/total*100):.1f}%" if total > 0 else "0%",
                        'Medium': medium,
                        'Medium_Pct': f"{(medium/total*100):.1f}%" if total > 0 else "0%",
                        'Low': low,
                        'Low_Pct': f"{(low/total*100):.1f}%" if total > 0 else "0%",
                        'High_Critical_Combined': critical + high,
                        'High_Critical_Pct': f"{((critical+high)/total*100):.1f}%" if total > 0 else "0%"
                    })
    
    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(output_path, 'risk_by_policy_mode.csv'), index=False)



if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python aggregation.py <results_path> <output_path>")
        sys.exit(1)
    
    results_path = sys.argv[1]
    output_path = sys.argv[2]
    
    create_aggregations(results_path, output_path)
