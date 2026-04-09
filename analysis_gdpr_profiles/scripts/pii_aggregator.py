"""
PII Aggregator - Aggregate and categorize all PII instances across storage types and lifecycles
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent))
from utils import (
    load_all_user_data,
    export_to_json,
    get_pii_categories,
    categorize_pii_sensitivity,
    count_by_category,
    filter_by_category,
    extract_pii_value,
    get_storage_key
)


class PIIAggregator:
    """Aggregate PII across all storage types and lifecycles."""
    
    def __init__(self, base_path: str, output_path: str):
        self.base_path = base_path
        self.output_path = output_path
        self.users = ['FR_0417', 'FR_0446', 'FR_0458']
        self.nav_modes = ['Auth', 'UnAuth']
        self.policies = ['ALL', 'NONE', 'PARTIAL']
        self.storage_types = ['cookies', 'indexeddb', 'localstorage', 'sessionstorage']
        self.lifecycles = ['added', 'modified', 'removed']
    
    def aggregate_for_profile(self, nav_mode: str, user_id: str, policy: str) -> Dict[str, Any]:
        """
        Aggregate all PII for a specific user/mode/policy combination.
        """
        print(f"\nAggregating PII for {nav_mode}/{user_id}/{policy}...")
        
        all_data = load_all_user_data(self.base_path, nav_mode, user_id, policy)
        
        # Data structure for multi-dimensional aggregation
        aggregation = {
            'profile_id': f"{nav_mode}_{user_id}_{policy}",
            'nav_mode': nav_mode,
            'user_id': user_id,
            'policy': policy,
            'summary': {
                'total_items': 0,
                'by_storage_type': {},
                'by_category': {},
                'by_lifecycle': {},
                'by_sensitivity': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            },
            'pii_instances': {
                'DIRECT_PII': [],
                'IDENTITY_TRACKING': [],
                'ID_SOLUTIONS_AND_EXCHANGES': [],
                'NAVIGATION_HISTORY': [],
                'LOCATION_AND_DEMOGRAPHICS': [],
                'BEHAVIORAL_DATA': [],
                'DIRECT_PII_KEYS': [],
                'SENSITIVE_LOCATION_PII': [],
                'other': []
            },
            'persistence_metrics': {
                'by_storage_type': {},
                'by_category': {}
            }
        }
        
        # Multi-storage processing loop
        for storage_type, items in all_data.items():
            if not items:
                continue
            
            storage_count = len(items)
            aggregation['summary']['total_items'] += storage_count
            aggregation['summary']['by_storage_type'][storage_type] = storage_count
            
            category_counts = count_by_category(items)
            for category, count in category_counts.items():
                aggregation['summary']['by_category'][category] = \
                    aggregation['summary']['by_category'].get(category, 0) + count
                
                sensitivity = categorize_pii_sensitivity(category)
                aggregation['summary']['by_sensitivity'][sensitivity] += count
            
            # Count by lifecycle
            for item in items:
                lifecycle = item.get('_metadata', {}).get('lifecycle', 'unknown')
                aggregation['summary']['by_lifecycle'][lifecycle] = \
                    aggregation['summary']['by_lifecycle'].get(lifecycle, 0) + 1
            
            # Collect PII instances by category
            for category in aggregation['pii_instances'].keys():
                category_items = filter_by_category(items, category)
                
                for item in category_items:
                    pii_instance = {
                        'storage_type': storage_type,
                        'lifecycle': item.get('_metadata', {}).get('lifecycle'),
                        'key': get_storage_key(item),
                        'value': extract_pii_value(item),
                        'category': category,
                        'sensitivity': categorize_pii_sensitivity(category)
                    }
                    
                    # Add domain if available
                    if 'domain' in item:
                        pii_instance['domain'] = item['domain']
                    
                    aggregation['pii_instances'][category].append(pii_instance)
            
            # Calculate persistence metrics for this storage type
            aggregation['persistence_metrics']['by_storage_type'][storage_type] = \
                self._calculate_persistence(items)
        
        # Calculate persistence by category
        all_items = []
        for items in all_data.values():
            all_items.extend(items)
        
        for category in get_pii_categories():
            category_items = filter_by_category(all_items, category)
            if category_items:
                aggregation['persistence_metrics']['by_category'][category] = \
                    self._calculate_persistence(category_items)
        
        return aggregation
    
    def _calculate_persistence(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate persistence metrics for a set of items.
        """
        lifecycle_counts = defaultdict(int)
        
        for item in items:
            lifecycle = item.get('_metadata', {}).get('lifecycle', 'unknown')
            lifecycle_counts[lifecycle] += 1
        
        total = len(items)
        
        return {
            'total_items': total,
            'added': lifecycle_counts.get('added', 0),
            'modified': lifecycle_counts.get('modified', 0),
            'removed': lifecycle_counts.get('removed', 0),
            'persistence_ratio': (
                (lifecycle_counts.get('added', 0) + lifecycle_counts.get('modified', 0)) / total
                if total > 0 else 0
            )
        }
    
    def generate_comparative_analysis(self) -> Dict[str, Any]:
        """
        Generate comparative analysis across all profiles.
        """
        print("\n" + "="*80)
        print("Generating Comparative Analysis")
        print("="*80)
        
        comparative = {
            'by_user': {},
            'by_nav_mode': {},
            'by_policy': {},
            'overall_statistics': {
                'total_profiles': 0,
                'total_pii_instances': 0,
                'by_category': {},
                'by_sensitivity': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            }
        }
        
        # Collect all profile aggregations
        all_aggregations = []
        
        for nav_mode in self.nav_modes:
            for user_id in self.users:
                for policy in self.policies:
                    agg = self.aggregate_for_profile(nav_mode, user_id, policy)
                    all_aggregations.append(agg)
                    
                    # Save individual profile aggregation
                    output_file = Path(self.output_path) / nav_mode / user_id / policy / 'pii_aggregation_summary.json'
                    export_to_json(agg, str(output_file))
        
        # Build comparative statistics
        comparative['overall_statistics']['total_profiles'] = len(all_aggregations)
        
        for agg in all_aggregations:
            user_id = agg['user_id']
            nav_mode = agg['nav_mode']
            policy = agg['policy']
            
            # By user
            if user_id not in comparative['by_user']:
                comparative['by_user'][user_id] = {
                    'total_items': 0,
                    'by_policy': {},
                    'by_nav_mode': {}
                }
            
            comparative['by_user'][user_id]['total_items'] += agg['summary']['total_items']
            comparative['by_user'][user_id]['by_policy'][policy] = agg['summary']['total_items']
            comparative['by_user'][user_id]['by_nav_mode'][nav_mode] = \
                comparative['by_user'][user_id]['by_nav_mode'].get(nav_mode, 0) + agg['summary']['total_items']
            
            # By nav mode
            if nav_mode not in comparative['by_nav_mode']:
                comparative['by_nav_mode'][nav_mode] = {
                    'total_items': 0,
                    'by_user': {},
                    'by_policy': {}
                }
            
            comparative['by_nav_mode'][nav_mode]['total_items'] += agg['summary']['total_items']
            comparative['by_nav_mode'][nav_mode]['by_user'][user_id] = \
                comparative['by_nav_mode'][nav_mode]['by_user'].get(user_id, 0) + agg['summary']['total_items']
            comparative['by_nav_mode'][nav_mode]['by_policy'][policy] = \
                comparative['by_nav_mode'][nav_mode]['by_policy'].get(policy, 0) + agg['summary']['total_items']
            
            # By policy
            if policy not in comparative['by_policy']:
                comparative['by_policy'][policy] = {
                    'total_items': 0,
                    'by_user': {},
                    'by_nav_mode': {}
                }
            
            comparative['by_policy'][policy]['total_items'] += agg['summary']['total_items']
            comparative['by_policy'][policy]['by_user'][user_id] = \
                comparative['by_policy'][policy]['by_user'].get(user_id, 0) + agg['summary']['total_items']
            comparative['by_policy'][policy]['by_nav_mode'][nav_mode] = \
                comparative['by_policy'][policy]['by_nav_mode'].get(nav_mode, 0) + agg['summary']['total_items']
            
            # Overall statistics
            comparative['overall_statistics']['total_pii_instances'] += agg['summary']['total_items']
            
            for category, count in agg['summary']['by_category'].items():
                comparative['overall_statistics']['by_category'][category] = \
                    comparative['overall_statistics']['by_category'].get(category, 0) + count
            
            for sensitivity, count in agg['summary']['by_sensitivity'].items():
                comparative['overall_statistics']['by_sensitivity'][sensitivity] += count
        
        return comparative
    
    def run(self):
        """
        Run complete PII aggregation analysis.
        """
        print("="*80)
        print("PII AGGREGATION ANALYSIS")
        print("="*80)
        
        # Generate comparative analysis (which also generates individual profiles)
        comparative = self.generate_comparative_analysis()
        
        # Save comparative analysis
        comparative_file = Path(self.output_path).parent / 'reports' / 'pii_comparative_analysis.json'
        export_to_json(comparative, str(comparative_file))
        
        print("\n" + "="*80)
        print("PII Aggregation Complete!")
        print("="*80)
        print(f"Total profiles analyzed: {comparative['overall_statistics']['total_profiles']}")
        print(f"Total PII instances: {comparative['overall_statistics']['total_pii_instances']}")
        print(f"\nTop 5 PII categories:")
        
        sorted_categories = sorted(
            comparative['overall_statistics']['by_category'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        for category, count in sorted_categories:
            print(f"  - {category}: {count}")
        
        print(f"\nBy sensitivity:")
        for sensitivity, count in comparative['overall_statistics']['by_sensitivity'].items():
            print(f"  - {sensitivity}: {count}")


def main():
    """Main entry point."""
    base_path = Path(__file__).parent.parent.parent / 'data' / 'user'
    output_path = Path(__file__).parent.parent / 'outputs'
    
    aggregator = PIIAggregator(str(base_path), str(output_path))
    aggregator.run()


if __name__ == '__main__':
    main()
