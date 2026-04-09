#!/usr/bin/env python3
"""
Aggregate lifecycle data across users, policies, and modes.
Creates aggregated lifecycle metrics for each storage type.
"""

import os
import json
from pathlib import Path
from collections import defaultdict


def aggregate_lifecycle_data(results_base: str, storage_type: str):
    """
    Aggregate lifecycle data for a specific storage type.
    
    Creates aggregations by:
    - Mode (Auth/UnAuth)
    - Policy (ALL/PARTIAL/NONE)
    - User (FR_0417/FR_0446/FR_0458)
    - Global (all combined)
    """
    
    print(f"\n{'='*80}")
    print(f"Aggregating lifecycle data for: {storage_type}")
    print(f"{'='*80}")
    
    # Storage for aggregations
    aggregations = {
        'by_mode': defaultdict(lambda: {
            'total_items': 0,
            'items_modified': 0,
            'items_deleted': 0,
            'pii_transitions': defaultdict(int),
            'volatility_distribution': defaultdict(int),
            'frequent_changes': [],
            'num_configs': 0
        }),
        'by_policy': defaultdict(lambda: {
            'total_items': 0,
            'items_modified': 0,
            'items_deleted': 0,
            'pii_transitions': defaultdict(int),
            'volatility_distribution': defaultdict(int),
            'frequent_changes': [],
            'num_configs': 0
        }),
        'by_user': defaultdict(lambda: {
            'total_items': 0,
            'items_modified': 0,
            'items_deleted': 0,
            'pii_transitions': defaultdict(int),
            'volatility_distribution': defaultdict(int),
            'frequent_changes': [],
            'num_configs': 0
        }),
        'global': {
            'total_items': 0,
            'items_modified': 0,
            'items_deleted': 0,
            'pii_transitions': defaultdict(int),
            'volatility_distribution': defaultdict(int),
            'frequent_changes': [],
            'num_configs': 0
        }
    }
    
    # Iterate through all configurations
    for auth in ['Auth', 'UnAuth']:
        for user in ['FR_0417', 'FR_0446', 'FR_0458']:
            for policy in ['ALL', 'PARTIAL', 'NONE']:
                lifecycle_path = Path(results_base) / auth / user / policy / storage_type / 'lifecycle' / 'lifecycle_data.json'
                
                if not lifecycle_path.exists():
                    continue
                
                with open(lifecycle_path, 'r') as f:
                    data = json.load(f)
                
                metrics = data.get('metrics', {})
                
                # Aggregate to each dimension
                for agg_type, agg_key in [
                    ('by_mode', auth),
                    ('by_policy', policy),
                    ('by_user', user)
                ]:
                    agg = aggregations[agg_type][agg_key]
                    agg['total_items'] += metrics.get('total_items', 0)
                    agg['items_modified'] += metrics.get('items_modified', 0)
                    agg['items_deleted'] += metrics.get('items_deleted', 0)
                    agg['num_configs'] += 1
                    
                    # Aggregate transitions
                    for trans, count in metrics.get('pii_transitions', {}).items():
                        agg['pii_transitions'][trans] += count
                    
                    # Aggregate volatility
                    for level, count in metrics.get('volatility_distribution', {}).items():
                        agg['volatility_distribution'][level] += count
                    
                    # Aggregate frequent changes
                    for item in metrics.get('frequent_changes', []):
                        agg['frequent_changes'].append({
                            'key': item.get('key'),
                            'num_modifications': item.get('num_modifications', 0),
                            'pii_category': item.get('pii_category'),
                            'config': f"{auth}_{user}_{policy}"
                        })
                
                # Aggregate to global
                glob = aggregations['global']
                glob['total_items'] += metrics.get('total_items', 0)
                glob['items_modified'] += metrics.get('items_modified', 0)
                glob['items_deleted'] += metrics.get('items_deleted', 0)
                glob['num_configs'] += 1
                
                for trans, count in metrics.get('pii_transitions', {}).items():
                    glob['pii_transitions'][trans] += count
                
                for level, count in metrics.get('volatility_distribution', {}).items():
                    glob['volatility_distribution'][level] += count
                
                for item in metrics.get('frequent_changes', []):
                    glob['frequent_changes'].append({
                        'key': item.get('key'),
                        'num_modifications': item.get('num_modifications', 0),
                        'pii_category': item.get('pii_category'),
                        'config': f"{auth}_{user}_{policy}"
                    })
    
    # Convert defaultdicts to regular dicts and sort
    for agg_type in ['by_mode', 'by_policy', 'by_user']:
        for key in aggregations[agg_type]:
            agg = aggregations[agg_type][key]
            agg['pii_transitions'] = dict(sorted(agg['pii_transitions'].items(), 
                                                key=lambda x: x[1], reverse=True))
            agg['volatility_distribution'] = dict(agg['volatility_distribution'])
            
            # Sort frequent changes by num_modifications
            agg['frequent_changes'] = sorted(agg['frequent_changes'], 
                                            key=lambda x: x['num_modifications'], 
                                            reverse=True)[:50]  # Keep top 50
    
    glob = aggregations['global']
    glob['pii_transitions'] = dict(sorted(glob['pii_transitions'].items(), 
                                         key=lambda x: x[1], reverse=True))
    glob['volatility_distribution'] = dict(glob['volatility_distribution'])
    glob['frequent_changes'] = sorted(glob['frequent_changes'], 
                                     key=lambda x: x['num_modifications'], 
                                     reverse=True)[:50]
    
    return aggregations


def save_aggregations(aggregations: dict, storage_type: str, output_base: str):
    """Save aggregated lifecycle data to JSON files."""
    
    output_dir = Path(output_base) / storage_type / 'lifecycle'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save by mode
    for mode, data in aggregations['by_mode'].items():
        output_file = output_dir / f'{mode}.json'
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"   Saved: {output_file}")
    
    # Save by policy
    for policy, data in aggregations['by_policy'].items():
        output_file = output_dir / f'{policy}.json'
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"   Saved: {output_file}")
    
    # Save by user
    for user, data in aggregations['by_user'].items():
        output_file = output_dir / f'{user}.json'
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"   Saved: {output_file}")
    
    # Save global
    output_file = output_dir / 'global.json'
    with open(output_file, 'w') as f:
        json.dump(aggregations['global'], f, indent=2)
    print(f"   Saved: {output_file}")


def main():
    """Main execution."""
    
    results_base = 'results'
    output_base = 'results/aggregated_data'
    
    storage_types = ['cookies', 'localstorage', 'sessionstorage']
    
    print("="*80)
    print("LIFECYCLE DATA AGGREGATION")
    print("="*80)
    
    for storage_type in storage_types:
        aggregations = aggregate_lifecycle_data(results_base, storage_type)
        save_aggregations(aggregations, storage_type, output_base)
        
        # Print summary
        glob = aggregations['global']
        print(f"\n  Summary for {storage_type}:")
        print(f"    Total items: {glob['total_items']:,}")
        print(f"    Items modified: {glob['items_modified']:,}")
        print(f"    Items deleted: {glob['items_deleted']:,}")
        print(f"    Configurations: {glob['num_configs']}")
        print(f"    PII transitions: {len(glob['pii_transitions'])}")
    
    print("\n" + "="*80)
    print("COMPLETED")
    print("="*80)
    print(f"\nAggregated lifecycle data saved to: {output_base}/*/lifecycle/")


if __name__ == '__main__':
    main()
