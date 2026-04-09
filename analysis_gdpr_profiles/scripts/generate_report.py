
import json
import os
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime


def load_comparative_analysis(reports_dir):
    """Load comparative analysis results from JSON."""
    path = os.path.join(reports_dir, 'pii_comparative_analysis.json')
    with open(path, 'r') as f:
        return json.load(f)


def load_all_profiles(outputs_dir):
    """Descriptive metadata for all profile configurations."""
    profiles = []
    
    for nav_mode in ['Auth', 'UnAuth']:
        nav_path = os.path.join(outputs_dir, nav_mode)
        if not os.path.exists(nav_path):
            continue
            
        for user_id in os.listdir(nav_path):
            user_path = os.path.join(nav_path, user_id)
            if not os.path.isdir(user_path):
                continue
                
            for policy in os.listdir(user_path):
                policy_path = os.path.join(user_path, policy)
                if not os.path.isdir(policy_path):
                    continue
                
                profile = {
                    'nav_mode': nav_mode,
                    'user_id': user_id,
                    'policy': policy,
                    'profile_id': f"{nav_mode}_{user_id}_{policy}"
                }
                
                # Load all JSON files
                for json_file in ['pii_aggregation_summary.json']:
                    json_path = os.path.join(policy_path, json_file)
                    if os.path.exists(json_path):
                        with open(json_path, 'r') as f:
                            profile[json_file.replace('.json', '')] = json.load(f)
                
                profiles.append(profile)
    
    return profiles


def compute_global_statistics(comparative_data):
    """Calculate high-level metrics across entire dataset."""
    stats = {}
    
    overall = comparative_data.get('overall_statistics', {})
    stats['total_profiles'] = overall.get('total_profiles', 0)
    stats['total_pii_instances'] = overall.get('total_pii_instances', 0)
    stats['avg_pii_per_profile'] = stats['total_pii_instances'] / stats['total_profiles'] if stats['total_profiles'] > 0 else 0
    
    by_category = overall.get('by_category', {})
    stats['category_distribution'] = sorted(by_category.items(), key=lambda x: x[1], reverse=True)
    
    by_sensitivity = overall.get('by_sensitivity', {})
    stats['sensitivity_distribution'] = by_sensitivity
    stats['critical_percentage'] = (by_sensitivity.get('critical', 0) / stats['total_pii_instances'] * 100) if stats['total_pii_instances'] > 0 else 0
    stats['high_percentage'] = (by_sensitivity.get('high', 0) / stats['total_pii_instances'] * 100) if stats['total_pii_instances'] > 0 else 0
    
    return stats


def compute_auth_statistics(comparative_data):
    """Compute statistics by authentication status"""
    by_nav = comparative_data.get('by_nav_mode', {})
    
    auth_stats = {}
    for nav_mode in ['Auth', 'UnAuth']:
        if nav_mode in by_nav:
            data = by_nav[nav_mode]
            auth_stats[nav_mode] = {
                'total_items': data.get('total_items', 0),
                'by_user': data.get('by_user', {}),
                'by_policy': data.get('by_policy', {})
            }
    
    # Compute ratio
    if 'Auth' in auth_stats and 'UnAuth' in auth_stats:
        auth_total = auth_stats['Auth']['total_items']
        unauth_total = auth_stats['UnAuth']['total_items']
        auth_stats['ratio_unauth_vs_auth'] = unauth_total / auth_total if auth_total > 0 else 0
    
    return auth_stats


def compute_policy_statistics(comparative_data):
    """Compute statistics by consent policy"""
    by_policy = comparative_data.get('by_policy', {})
    
    policy_stats = {}
    for policy in ['NONE', 'PARTIAL', 'ALL']:
        if policy in by_policy:
            data = by_policy[policy]
            policy_stats[policy] = {
                'total_items': data.get('total_items', 0),
                'avg_per_profile': data.get('total_items', 0) / 6,  # 6 profiles per policy (3 users  2 nav_modes)
                'by_user': data.get('by_user', {}),
                'by_nav_mode': data.get('by_nav_mode', {})
            }
    
    # Compute ratios
    if 'NONE' in policy_stats and 'ALL' in policy_stats:
        none_total = policy_stats['NONE']['total_items']
        all_total = policy_stats['ALL']['total_items']
        policy_stats['none_vs_all_percentage'] = (none_total / all_total * 100) if all_total > 0 else 0
    
    return policy_stats


def compute_user_statistics(comparative_data):
    """Compute statistics by user"""
    by_user = comparative_data.get('by_user', {})
    
    user_stats = {}
    for user_id in ['FR_0417', 'FR_0446', 'FR_0458']:
        if user_id in by_user:
            data = by_user[user_id]
            user_stats[user_id] = {
                'total_items': data.get('total_items', 0),
                'avg_per_config': data.get('total_items', 0) / 6,  # 6 configs per user (3 policies  2 nav_modes)
                'by_policy': data.get('by_policy', {}),
                'by_nav_mode': data.get('by_nav_mode', {})
            }
    
    return user_stats


def compute_identification_scores(profiles):
    """Aggregate risk scores for profiling."""
    scores = {
        'by_profile': {},
        'averages': {
            'identification': [],
            'personalization': [],
            'tracking': []
        }
    }
    
    for profile in profiles:
        profile_id = profile['profile_id']
        id_profile = profile.get('identification_profile', {})
        
        # Scores are in the 'summary' object
        summary = id_profile.get('summary', {})
        
        # Extract scores
        id_score = summary.get('identification_score', 0)
        pers_score = summary.get('personalization_score', 0)
        track_score = summary.get('tracking_exposure_score', 0)
        
        scores['by_profile'][profile_id] = {
            'identification': id_score,
            'personalization': pers_score,
            'tracking': track_score,
            'overall_risk': (id_score + pers_score + track_score) / 3
        }
        
        scores['averages']['identification'].append(id_score)
        scores['averages']['personalization'].append(pers_score)
        scores['averages']['tracking'].append(track_score)
    
    # Compute averages
    for key in ['identification', 'personalization', 'tracking']:
        values = scores['averages'][key]
        scores['averages'][key] = sum(values) / len(values) if values else 0
    
    return scores


def compute_gdpr_compliance_scores(profiles):
    """Calculate GDPR alignment scores."""
    compliance = {
        'by_profile': {},
        'averages': {
            'lawfulness': [],
            'consent': [],
            'data_minimization': [],
            'purpose_limitation': [],
            'special_categories': [],
            'overall': []
        }
    }
    
    for profile in profiles:
        profile_id = profile['profile_id']
        gdpr_report = profile.get('gdpr_risk_report', {})
        
        # Field is 'gdpr_compliance_scores', not 'compliance_scores'
        compliance_scores = gdpr_report.get('gdpr_compliance_scores', {})
        
        compliance['by_profile'][profile_id] = compliance_scores
        
        # Aggregate for averages (use correct field names)
        for dimension in ['lawfulness', 'consent', 'data_minimization', 'purpose_limitation', 'special_categories']:
            score = compliance_scores.get(dimension, 0)
            compliance['averages'][dimension].append(score)
        
        overall = gdpr_report.get('overall_risk_score', 0)
        compliance['averages']['overall'].append(10 - overall)  # Convert risk to compliance (10 - risk)
    
    # Compute averages
    for key in compliance['averages']:
        values = compliance['averages'][key]
        compliance['averages'][key] = sum(values) / len(values) if values else 0
    
    return compliance


def generate_report(output_file, comparative_data):
    """Generate comprehensive reproducibility report"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        # 
        
        # Section 1: Global Statistics
        f.write("SECTION 1: GLOBAL STATISTICS\n")
        f.write("-" * 80 + "\n")
        global_stats = compute_global_statistics(comparative_data)
        
        f.write(f"Total PII Instances: {global_stats['total_pii_instances']:,}\n")
        f.write(f"Total Profiles: {global_stats['total_profiles']}\n")
        f.write(f"Average PII per Profile: {global_stats['avg_pii_per_profile']:,.1f}\n\n")
        
        f.write("Sensitivity Distribution:\n")
        sens_dist = global_stats['sensitivity_distribution']
        total = global_stats['total_pii_instances']
        f.write(f"  Critical: {sens_dist.get('critical', 0):,} ({sens_dist.get('critical', 0)/total*100:.1f}%)\n")
        f.write(f"  High: {sens_dist.get('high', 0):,} ({sens_dist.get('high', 0)/total*100:.1f}%)\n")
        f.write(f"  Medium: {sens_dist.get('medium', 0):,} ({sens_dist.get('medium', 0)/total*100:.1f}%)\n")
        f.write(f"  Low: {sens_dist.get('low', 0):,} ({sens_dist.get('low', 0)/total*100:.1f}%)\n\n")
        
        f.write("Top 10 PII Categories by Volume:\n")
        for i, (category, count) in enumerate(global_stats['category_distribution'][:10], 1):
            percentage = (count / total * 100) if total > 0 else 0
            f.write(f"  {i:2d}. {category:40s} {count:8,} ({percentage:5.1f}%)\n")
        f.write("\n")
        
        # Section 2: Authentication Impact
        f.write("SECTION 2: AUTHENTICATION STATUS IMPACT\n")
        f.write("-" * 80 + "\n")
        auth_stats = compute_auth_statistics(comparative_data)
        
        auth_total = auth_stats.get('Auth', {}).get('total_items', 0)
        unauth_total = auth_stats.get('UnAuth', {}).get('total_items', 0)
        ratio = auth_stats.get('ratio_unauth_vs_auth', 0)
        
        f.write(f"Authenticated Users:\n")
        f.write(f"  Total Items: {auth_total:,}\n")
        f.write(f"  Average per Profile: {auth_total/9:,.1f}\n\n")
        
        f.write(f"Non-Authenticated Users:\n")
        f.write(f"  Total Items: {unauth_total:,}\n")
        f.write(f"  Average per Profile: {unauth_total/9:,.1f}\n\n")
        
        f.write(f"Ratio UnAuth/Auth: {ratio:.2f} (UnAuth users have {ratio:.1f} more PII)\n\n")
        
        # Section 3: Consent Policy Impact
        f.write("SECTION 3: CONSENT POLICY IMPACT\n")
        f.write("-" * 80 + "\n")
        policy_stats = compute_policy_statistics(comparative_data)
        
        for policy in ['NONE', 'PARTIAL', 'ALL']:
            if policy in policy_stats:
                stats = policy_stats[policy]
                f.write(f"{policy} (Consent Policy):\n")
                f.write(f"  Total Items: {stats['total_items']:,}\n")
                f.write(f"  Average per Profile: {stats['avg_per_profile']:,.1f}\n\n")
        
        none_vs_all = policy_stats.get('none_vs_all_percentage', 0)
        f.write(f"CRITICAL FINDING: NONE mode collects {none_vs_all:.1f}% of ALL mode volume\n")
        f.write(f"  => GDPR Violation: Consent not respected\n\n")
        
        # Section 4: User Variability
        f.write("SECTION 4: INTER-USER VARIABILITY\n")
        f.write("-" * 80 + "\n")
        user_stats = compute_user_statistics(comparative_data)
        
        for user_id in ['FR_0417', 'FR_0446', 'FR_0458']:
            if user_id in user_stats:
                stats = user_stats[user_id]
                f.write(f"{user_id}:\n")
                f.write(f"  Total Items: {stats['total_items']:,}\n")
                f.write(f"  Average per Config: {stats['avg_per_config']:,.1f}\n\n")
        
        # Compute ratio
        totals = [user_stats[u]['total_items'] for u in ['FR_0417', 'FR_0446', 'FR_0458'] if u in user_stats]
        if totals:
            max_total = max(totals)
            min_total = min(totals)
            f.write(f"Variability Ratio (Max/Min): {max_total/min_total:.2f}\n\n")
        



def main():
    """Main execution"""
    base_dir = Path(__file__).parent.parent
    reports_dir = base_dir / 'reports'
    outputs_dir = base_dir / 'outputs'
    
    print("Loading data...")
    comparative_data = load_comparative_analysis(reports_dir)
    profiles = load_all_profiles(outputs_dir)
    
    print(f"Loaded {len(profiles)} profiles")
    
    output_file = reports_dir / 'reproducibility_report.txt'
    print(f"Generating report: {output_file}")

    generate_report(output_file, comparative_data)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
    print(f" Report generated successfully!")
    print(f"  Location: {output_file}")
    print(f"  Profiles analyzed: {len(profiles)}")
    print(f"  Total PII instances: {comparative_data['overall_statistics']['total_pii_instances']:,}")


if __name__ == '__main__':
    main()
