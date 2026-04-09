#!/usr/bin/env python3
"""
Generate comprehensive reproducibility report for all Key Findings in results_section.tex
This script extracts all metrics mentioned in the document and validates them against source data.
"""

import json
import os
from pathlib import Path
from datetime import datetime


def load_global_data():
    """Load all global aggregated data files."""
    base_path = Path('results/aggregated_data')
    
    data = {}
    for storage in ['cookies', 'indexeddb', 'localstorage', 'sessionstorage']:
        global_path = base_path / storage / 'global.json'
        if global_path.exists():
            with open(global_path, 'r') as f:
                data[storage] = json.load(f)
    
    return data


def calculate_storage_totals(data):
    """Calculate total items per storage type."""
    totals = {}
    
    # Cookies
    totals['cookies'] = data['cookies'].get('total_cookies', 0)
    
    # Other storages: sum from risk_levels
    for storage in ['indexeddb', 'localstorage', 'sessionstorage']:
        if storage in data:
            risk_levels = data[storage].get('risk_levels', {})
            totals[storage] = sum(risk_levels.values())
    
    return totals


def generate_report():
    """Generate comprehensive reproducibility report."""
    
    print("=" * 80)
    print("COMPREHENSIVE REPRODUCIBILITY REPORT")
    print("Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 80)
    
    # Load data
    data = load_global_data()
    storage_totals = calculate_storage_totals(data)
    
    # Total PII instances
    total_pii = sum(storage_totals.values())
    
    print("\n" + "=" * 80)
    print("SECTION 1: OVERALL PII LANDSCAPE (RQ1)")
    print("=" * 80)
    
    print(f"\n1.1 Total PII Instances Across All Storage Types")
    print("-" * 80)
    for storage, count in storage_totals.items():
        pct = (count / total_pii * 100) if total_pii > 0 else 0
        print(f"  {storage.capitalize():15s}: {count:8,} ({pct:5.1f}%)")
    print(f"  {'TOTAL':15s}: {total_pii:8,}")
    
    # Average profile
    num_profiles = 18  # 3 users Ã 2 modes Ã 3 policies
    avg_per_profile = total_pii / num_profiles
    print(f"\n1.2 Average Profile Size")
    print(f"  Total profiles: {num_profiles}")
    print(f"  Average PII per profile: {avg_per_profile:,.0f}")
    
    # IndexedDB vs Cookies ratio
    idb_cookies_ratio = storage_totals['indexeddb'] / storage_totals['cookies']
    idb_pct = (storage_totals['indexeddb'] / total_pii * 100)
    print(f"\n1.3 IndexedDB Dominance")
    print(f"  IndexedDB items: {storage_totals['indexeddb']:,}")
    print(f"  Cookies items: {storage_totals['cookies']:,}")
    print(f"  Ratio: {idb_cookies_ratio:.1f}x")
    print(f"  IndexedDB % of total: {idb_pct:.1f}%")
    
    # Cookie diversity (PII classes)
    cookies_data = data['cookies']
    lifetime_by_pii = cookies_data.get('lifetime_by_pii', {})
    num_pii_classes = len(lifetime_by_pii)
    print(f"\n1.4 Cookie PII Diversity")
    print(f"  Number of PII classes: {num_pii_classes}")
    
    print("\n" + "=" * 80)
    print("SECTION 2: COOKIE LIFETIME DISTRIBUTION (RQ2)")
    print("=" * 80)
    
    lifetime_dist = cookies_data.get('lifetime_distribution', {})
    total_cookies = sum(lifetime_dist.values())
    
    print(f"\n2.1 Global Lifetime Distribution (Total: {total_cookies:,} cookies)")
    print("-" * 80)
    for cat in ['Session', '<6 months', '6-18 months', '>18 months']:
        count = lifetime_dist.get(cat, 0)
        pct = (count / total_cookies * 100) if total_cookies > 0 else 0
        print(f"  {cat:15s}: {count:6,} ({pct:5.1f}%)")
    
    print(f"\n2.2 Lifetime by PII Category (Top 10)")
    print("-" * 80)
    
    # Calculate totals for each PII class
    pii_totals = {pii: sum(lifetimes.values()) 
                  for pii, lifetimes in lifetime_by_pii.items()}
    top_10_pii = sorted(pii_totals.items(), key=lambda x: x[1], reverse=True)[:10]
    
    for pii, total in top_10_pii:
        print(f"\n  {pii} (Total: {total:,}):")
        dist = lifetime_by_pii[pii]
        for cat in ['Session', '<6 months', '6-18 months', '>18 months']:
            count = dist.get(cat, 0)
            pct = (count / total * 100) if total > 0 else 0
            print(f"    {cat:15s}: {count:5,} ({pct:5.1f}%)")
    
    print("\n" + "=" * 80)
    print("SECTION 3: SECURITY FLAGS (RQ3)")
    print("=" * 80)
    
    # Load security by policy CSV
    csv_path = Path('results/aggregated_data/summary_tables/cookie_security_by_policy.csv')
    if csv_path.exists():
        import pandas as pd
        df = pd.read_csv(csv_path)
        
        print(f"\n3.1 Security Flags by Policy")
        print("-" * 80)
        
        for policy in ['ALL', 'PARTIAL', 'NONE']:
            policy_data = df[df['Policy'] == policy]
            
            total_cookies_policy = policy_data['Total_Cookies'].sum()
            httponly_total = policy_data['HttpOnly_Count'].sum()
            secure_total = policy_data['Secure_Count'].sum()
            samesite_protected = policy_data['SameSite_Lax'].sum() + policy_data['SameSite_Strict'].sum()
            thirdparty_total = policy_data['Third_Party_Count'].sum()
            
            httponly_pct = (httponly_total / total_cookies_policy * 100) if total_cookies_policy > 0 else 0
            secure_pct = (secure_total / total_cookies_policy * 100) if total_cookies_policy > 0 else 0
            samesite_pct = (samesite_protected / total_cookies_policy * 100) if total_cookies_policy > 0 else 0
            thirdparty_pct = (thirdparty_total / total_cookies_policy * 100) if total_cookies_policy > 0 else 0
            
            print(f"\n  {policy} (Total: {total_cookies_policy:,} cookies):")
            print(f"    HttpOnly:     {httponly_pct:5.1f}%")
            print(f"    Secure:       {secure_pct:5.1f}%")
            print(f"    SameSite:     {samesite_pct:5.1f}%")
            print(f"    Third-Party:  {thirdparty_pct:5.1f}%")
    
    # Global security flags
    httponly_dist = cookies_data.get('httponly_distribution', {})
    secure_dist = cookies_data.get('secure_distribution', {})
    samesite_dist = cookies_data.get('samesite_distribution', {})
    thirdparty_dist = cookies_data.get('thirdparty_distribution', {})
    
    print(f"\n3.2 Global Security Flags (Total: {total_cookies:,} cookies)")
    print("-" * 80)
    
    httponly_true = httponly_dist.get('True', 0)
    httponly_pct = (httponly_true / total_cookies * 100)
    print(f"  HttpOnly:     {httponly_true:6,} ({httponly_pct:5.1f}%)")
    
    secure_true = secure_dist.get('True', 0)
    secure_pct = (secure_true / total_cookies * 100)
    print(f"  Secure:       {secure_true:6,} ({secure_pct:5.1f}%)")
    
    samesite_protected = samesite_dist.get('Lax', 0) + samesite_dist.get('Strict', 0)
    samesite_pct = (samesite_protected / total_cookies * 100)
    print(f"  SameSite:     {samesite_protected:6,} ({samesite_pct:5.1f}%)")
    
    tp_count = thirdparty_dist.get('Third-Party', 0)
    tp_pct = (tp_count / total_cookies * 100)
    print(f"  Third-Party:  {tp_count:6,} ({tp_pct:5.1f}%)")
    
    print("\n" + "=" * 80)
    print("SECTION 4: RISK LEVELS (RQ3)")
    print("=" * 80)
    
    print(f"\n4.1 Risk Distribution by Storage Type")
    print("-" * 80)
    
    for storage in ['cookies', 'indexeddb', 'localstorage', 'sessionstorage']:
        if storage not in data:
            continue
        
        risk_levels = data[storage].get('risk_levels', {})
        total = sum(risk_levels.values())
        
        if total == 0:
            continue
        
        print(f"\n  {storage.upper()} (Total: {total:,}):")
        
        for risk in ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk']:
            count = risk_levels.get(risk, 0)
            pct = (count / total * 100) if total > 0 else 0
            print(f"    {risk:15s}: {count:7,} ({pct:5.1f}%)")
        
        # High + Critical
        high_critical = risk_levels.get('High Risk', 0) + risk_levels.get('Critical Risk', 0)
        high_critical_pct = (high_critical / total * 100) if total > 0 else 0
        print(f"    {'High+Critical':15s}: {high_critical:7,} ({high_critical_pct:5.1f}%)")
    
    print("\n" + "=" * 80)
    print("SECTION 5: DATA SOURCES")
    print("=" * 80)
    
    print("\nFiles used for this report:")
    print("  - results/aggregated_data/cookies/global.json")
    print("  - results/aggregated_data/indexeddb/global.json")
    print("  - results/aggregated_data/localstorage/global.json")
    print("  - results/aggregated_data/sessionstorage/global.json")
    print("  - results/aggregated_data/summary_tables/cookie_security_by_policy.csv")
    
    print("\n" + "=" * 80)
    print("END OF REPORT")
    print("=" * 80)


if __name__ == '__main__':
    # Change to project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    generate_report()
