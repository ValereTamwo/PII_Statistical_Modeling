import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


def create_aggregation_visualizations(aggregations_path: str):
    """
    Create comprehensive visualizations from aggregated data.
    
    Args:
        aggregations_path: Path to aggregations directory
    """
    viz_path = os.path.join(aggregations_path, 'visualizations')
    os.makedirs(viz_path, exist_ok=True)
    
    # Set style
    sns.set_theme(style="whitegrid")
    plt.rcParams['figure.dpi'] = 300
    plt.rcParams['savefig.dpi'] = 300
    plt.rcParams['font.size'] = 10
    
    print("Creating visualizations...")
    
    # 1. Cookie Security Attributes by Policy
    print("  - Cookie security by policy")
    plot_cookie_security_by_policy(aggregations_path, viz_path)
    
    # 2. PII Distribution Across Storage Types
    print("  - PII distribution by storage")
    plot_pii_by_storage(aggregations_path, viz_path)
    
    # 3. Cookie Security by PII Class (Top 10)
    print("  - Cookie security by PII class")
    plot_cookie_security_by_pii(aggregations_path, viz_path)
    
    # 4. Risk Levels Distribution
    print("  - Risk levels distribution")
    plot_risk_distribution(aggregations_path, viz_path)
    
    # 5. Third-Party vs First-Party Comparison
    print("  - Third-party vs first-party")
    plot_party_comparison(aggregations_path, viz_path)
    
    # 6. Security Attributes Heatmap by PII Class
    print("  - Security heatmap by PII class")
    plot_security_heatmap(aggregations_path, viz_path)
    
    # 7. Storage Type Comparison (Multi-metric)
    print("  - Storage type comparison")
    plot_storage_comparison(aggregations_path, viz_path)
    
    # NEW: Non-Conformity Focused Visualizations
    print("  - Security gaps by policy (non-conformity)")
    plot_security_gaps_by_policy(aggregations_path, viz_path)
    
    print("  - Non-conformity heatmap by PII class")
    plot_nonconformity_heatmap(aggregations_path, viz_path)
    
    print("  - Conformity vs non-conformity comparison")
    plot_conformity_comparison(aggregations_path, viz_path)
    
    print(f"\nVisualizations saved to {viz_path}")



def plot_cookie_security_by_policy(agg_path: str, output_path: str):
    """Bar chart comparing cookie security attributes across policies."""
    csv_path = os.path.join(agg_path, 'summary_tables', 'cookie_security_by_policy.csv')
    df = pd.read_csv(csv_path)
    
    # Convert percentages to floats
    for col in ['HttpOnly_Pct', 'Secure_Pct', 'SameSite_Protected_Pct', 'Third_Party_Pct']:
        df[col] = df[col].str.rstrip('%').astype(float)
    
    # Create grouped bar chart
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Cookie Security Attributes by Consent Policy and Authentication Mode', 
                 fontsize=14, fontweight='bold')
    
    attributes = [
        ('HttpOnly_Pct', 'HttpOnly Protection (%)'),
        ('Secure_Pct', 'Secure Flag (%)'),
        ('SameSite_Protected_Pct', 'SameSite Protection (%)'),
        ('Third_Party_Pct', 'Third-Party Cookies (%)')
    ]
    
    for idx, (attr, title) in enumerate(attributes):
        ax = axes[idx // 2, idx % 2]
        
        # Prepare data for grouped bar chart
        df_pivot = df.pivot(index='Policy', columns='Mode', values=attr)
        df_pivot.plot(kind='bar', ax=ax, color=['#3498db', '#e74c3c'], width=0.7)
        
        ax.set_title(title, fontweight='bold')
        ax.set_xlabel('Consent Policy')
        ax.set_ylabel('Percentage (%)')
        ax.set_ylim(0, 100)
        ax.legend(title='Mode', loc='upper right')
        ax.grid(axis='y', alpha=0.3)
        
        # Add value labels on bars manually
        for container in ax.containers:
            for bar in container:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.1f}%', ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'cookie_security_by_policy.png'), bbox_inches='tight')
    plt.close()


def plot_pii_by_storage(agg_path: str, output_path: str):
    """Comparison of PII presence and risk across storage types."""
    csv_path = os.path.join(agg_path, 'summary_tables', 'pii_by_storage.csv')
    df = pd.read_csv(csv_path)
    
    # Convert percentages
    df['High_Critical_Pct'] = df['High_Critical_Pct'].str.rstrip('%').astype(float)
    
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    fig.suptitle('PII Distribution and Risk Across Storage Types', fontsize=14, fontweight='bold')
    
    # 1. Total Items
    ax1 = axes[0]
    bars1 = ax1.bar(df['Storage_Type'], df['Total_Items'], color=['#3498db', '#2ecc71', '#f39c12', '#9b59b6'])
    ax1.set_title('Total Items by Storage Type', fontweight='bold')
    ax1.set_ylabel('Number of Items')
    ax1.set_xlabel('Storage Type')
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height):,}', ha='center', va='bottom')
    
    # 2. Risk Distribution (Stacked)
    ax2 = axes[1]
    risk_data = df[['Critical_Risk', 'High_Risk', 'Medium_Risk', 'Low_Risk']].values.T
    colors = ['#e74c3c', '#e67e22', '#f39c12', '#2ecc71']
    bottom = np.zeros(len(df))
    
    for i, (risk_level, color) in enumerate(zip(['Critical', 'High', 'Medium', 'Low'], colors)):
        ax2.bar(df['Storage_Type'], risk_data[i], bottom=bottom, label=risk_level, color=color)
        bottom += risk_data[i]
    
    ax2.set_title('Risk Level Distribution', fontweight='bold')
    ax2.set_ylabel('Number of Items')
    ax2.set_xlabel('Storage Type')
    ax2.legend(title='Risk Level', loc='upper right')
    ax2.grid(axis='y', alpha=0.3)
    
    # 3. High/Critical Risk Percentage
    ax3 = axes[2]
    bars3 = ax3.bar(df['Storage_Type'], df['High_Critical_Pct'], 
                    color=['#e74c3c', '#e67e22', '#2ecc71', '#3498db'])
    ax3.set_title('High/Critical Risk Percentage', fontweight='bold')
    ax3.set_ylabel('Percentage (%)')
    ax3.set_xlabel('Storage Type')
    ax3.set_ylim(0, 100)
    ax3.axhline(y=50, color='red', linestyle='--', alpha=0.5, label='50% threshold')
    ax3.legend()
    ax3.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bar in bars3:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}%', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'pii_by_storage.png'), bbox_inches='tight')
    plt.close()


def plot_cookie_security_by_pii(agg_path: str, output_path: str):
    """Security attributes for top PII classes - IMPROVED VERSION showing non-conformity."""
    csv_path = os.path.join(agg_path, 'summary_tables', 'cookie_security_by_pii_class.csv')
    df = pd.read_csv(csv_path)
    
    # Convert percentages
    for col in ['HttpOnly_Pct', 'Secure_Pct', 'SameSite_Protected_Pct', 'Third_Party_Pct', 
                'HttpOnly_Missing_Pct', 'Secure_Missing_Pct', 'SameSite_Unprotected_Pct',
                'High_Critical_Pct']:
        df[col] = df[col].str.rstrip('%').astype(float)
    
    # Sort by total cookies and take top 10
    df_top = df.nlargest(10, 'Total_Cookies').copy()
    
    fig, axes = plt.subplots(2, 1, figsize=(16, 11))
    fig.suptitle('Security Analysis by PII Classification (Top 10)', 
                 fontsize=16, fontweight='bold')
    
    # 1. NON-CONFORMITY Attributes (Security Gaps)
    ax1 = axes[0]
    x = np.arange(len(df_top))
    width = 0.2
    
    # Use NON-CONFORMITY percentages (security gaps)
    bars1 = ax1.bar(x - 1.5*width, df_top['HttpOnly_Missing_Pct'], width, 
                    label='Missing HttpOnly', color='#e74c3c', edgecolor='black', linewidth=0.5)
    bars2 = ax1.bar(x - 0.5*width, df_top['Secure_Missing_Pct'], width, 
                    label='Missing Secure', color='#e67e22', edgecolor='black', linewidth=0.5)
    bars3 = ax1.bar(x + 0.5*width, df_top['SameSite_Unprotected_Pct'], width, 
                    label='Missing SameSite', color='#f39c12', edgecolor='black', linewidth=0.5)
    bars4 = ax1.bar(x + 1.5*width, df_top['Third_Party_Pct'], width, 
                    label='Third-Party', color='#c0392b', edgecolor='black', linewidth=0.5)
    
    ax1.set_ylabel('Non-Conformity Percentage (%)', fontsize=12, fontweight='bold')
    ax1.set_title('Security Gaps (Non-Conformity) by PII Class', 
                  fontweight='bold', fontsize=13, color='#c0392b')
    ax1.set_xticks(x)
    ax1.set_xticklabels(df_top['PII_Class'], rotation=45, ha='right', fontsize=10)
    ax1.legend(loc='upper right', fontsize=10)
    ax1.set_ylim(0, 105)
    ax1.grid(axis='y', alpha=0.3)
    ax1.axhline(y=50, color='darkred', linestyle='--', alpha=0.5, linewidth=1.5, label='50% threshold')
    
    # Add value labels on bars - LARGER and BOLD
    for bars in [bars1, bars2, bars3, bars4]:
        for bar in bars:
            height = bar.get_height()
            if height > 5:  # Only show if significant
                ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                        f'{height:.0f}%', ha='center', va='bottom', 
                        fontsize=9, fontweight='bold')
    
    # 2. Cookie Count and Risk Level
    ax2 = axes[1]
    ax2_twin = ax2.twinx()
    
    # Bar chart for cookie count
    bars = ax2.bar(x, df_top['Total_Cookies'], color='#95a5a6', alpha=0.7, 
                   edgecolor='black', linewidth=0.5, label='Total Cookies')
    ax2.set_ylabel('Number of Cookies', color='#34495e', fontsize=12, fontweight='bold')
    ax2.tick_params(axis='y', labelcolor='#34495e')
    
    # Add value labels on cookie bars
    for i, bar in enumerate(bars):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height):,}', ha='center', va='bottom', 
                fontsize=9, fontweight='bold', color='#34495e')
    
    # Line chart for risk percentage
    line = ax2_twin.plot(x, df_top['High_Critical_Pct'], color='#e74c3c', marker='o', 
                         linewidth=3, markersize=10, label='High/Critical Risk %',
                         markeredgecolor='darkred', markeredgewidth=1.5)
    ax2_twin.set_ylabel('High/Critical Risk (%)', color='#e74c3c', fontsize=12, fontweight='bold')
    ax2_twin.tick_params(axis='y', labelcolor='#e74c3c')
    ax2_twin.set_ylim(0, 100)
    
    # Add value labels on risk line - LARGER and BOLD
    for i, (xi, yi) in enumerate(zip(x, df_top['High_Critical_Pct'])):
        ax2_twin.text(xi, yi + 3, f'{yi:.1f}%', ha='center', va='bottom',
                     fontsize=10, fontweight='bold', color='#c0392b',
                     bbox=dict(boxstyle='round,pad=0.3', facecolor='white', 
                              edgecolor='#e74c3c', alpha=0.8))
    
    ax2.set_xlabel('PII Class', fontsize=12, fontweight='bold')
    ax2.set_title('Cookie Volume and Risk Level', fontweight='bold', fontsize=13)
    ax2.set_xticks(x)
    ax2.set_xticklabels(df_top['PII_Class'], rotation=45, ha='right', fontsize=10)
    ax2.grid(axis='y', alpha=0.3)
    
    # Combined legend
    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax2_twin.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'cookie_security_by_pii_class.png'), 
                bbox_inches='tight', dpi=300)
    plt.close()


def plot_risk_distribution(agg_path: str, output_path: str):
    """Risk level distribution across policies and modes."""
    csv_path = os.path.join(agg_path, 'summary_tables', 'risk_by_policy_mode.csv')
    df = pd.read_csv(csv_path)
    
    # Convert percentages
    for col in ['Critical_Pct', 'High_Pct', 'Medium_Pct', 'Low_Pct', 'High_Critical_Pct']:
        df[col] = df[col].str.rstrip('%').astype(float)
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Risk Level Distribution by Policy and Mode', fontsize=14, fontweight='bold')
    
    # 1. Stacked bar by policy
    ax1 = axes[0]
    df_auth = df[df['Mode'] == 'Auth']
    
    risk_data = df_auth[['Critical', 'High', 'Medium', 'Low']].values.T
    colors = ['#e74c3c', '#e67e22', '#f39c12', '#2ecc71']
    bottom = np.zeros(len(df_auth))
    
    for i, (risk_level, color) in enumerate(zip(['Critical', 'High', 'Medium', 'Low'], colors)):
        ax1.bar(df_auth['Policy'], risk_data[i], bottom=bottom, label=risk_level, color=color)
        bottom += risk_data[i]
    
    ax1.set_title('Risk Distribution (Authenticated Mode)', fontweight='bold')
    ax1.set_ylabel('Number of Cookies')
    ax1.set_xlabel('Consent Policy')
    ax1.legend(title='Risk Level', loc='upper right')
    ax1.grid(axis='y', alpha=0.3)
    
    # 2. High/Critical percentage comparison - use simple bar chart instead of pivot
    ax2 = axes[1]
    
    # Create grouped bar chart manually
    policies = df['Policy'].unique()
    x = np.arange(len(policies))
    width = 0.35
    
    auth_values = df[df['Mode'] == 'Auth']['High_Critical_Pct'].values
    unauth_values = df[df['Mode'] == 'UnAuth']['High_Critical_Pct'].values
    
    bars1 = ax2.bar(x - width/2, auth_values, width, label='Auth', color='#3498db')
    bars2 = ax2.bar(x + width/2, unauth_values, width, label='UnAuth', color='#e74c3c')
    
    ax2.set_title('High/Critical Risk Percentage', fontweight='bold')
    ax2.set_ylabel('Percentage (%)')
    ax2.set_xlabel('Consent Policy')
    ax2.set_xticks(x)
    ax2.set_xticklabels(policies)
    ax2.set_ylim(0, 100)
    ax2.legend(title='Mode', loc='upper right')
    ax2.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}%', ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'risk_distribution.png'), bbox_inches='tight')
    plt.close()


def plot_party_comparison(agg_path: str, output_path: str):
    """First-party vs third-party cookie comparison."""
    global_path = os.path.join(agg_path, 'cookies', 'global.json')
    
    with open(global_path, 'r') as f:
        data = json.load(f)
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('First-Party vs Third-Party Cookie Analysis', fontsize=14, fontweight='bold')
    
    # 1. Overall distribution
    ax1 = axes[0]
    party_dist = data.get('thirdparty_distribution', {})
    
    if not party_dist:
        print("Warning: No third-party distribution data found")
        plt.close()
        return
    
    colors = ['#3498db', '#e74c3c']
    wedges, texts, autotexts = ax1.pie(party_dist.values(), labels=party_dist.keys(), 
                                        autopct='%1.1f%%', colors=colors, startangle=90)
    ax1.set_title('Cookie Distribution by Party Type', fontweight='bold')
    
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    
    # 2. Security attributes by party type
    ax2 = axes[1]
    
    # Extract httponly and secure by party
    httponly_data = data.get('thirdparty_httponly', {})
    secure_data = data.get('thirdparty_secure', {})
    
    # Calculate percentages
    first_party_total = party_dist.get('First-Party', 0)
    third_party_total = party_dist.get('Third-Party', 0)
    
    if first_party_total == 0 and third_party_total == 0:
        print("Warning: No party data available")
        plt.close()
        return
    
    first_httponly = httponly_data.get('First-Party_True', 0) / first_party_total * 100 if first_party_total > 0 else 0
    third_httponly = httponly_data.get('Third-Party_True', 0) / third_party_total * 100 if third_party_total > 0 else 0
    first_secure = secure_data.get('First-Party_True', 0) / first_party_total * 100 if first_party_total > 0 else 0
    third_secure = secure_data.get('Third-Party_True', 0) / third_party_total * 100 if third_party_total > 0 else 0
    
    x = np.arange(2)
    width = 0.35
    
    bars1 = ax2.bar(x - width/2, [first_httponly, first_secure], width, label='First-Party', color='#3498db')
    bars2 = ax2.bar(x + width/2, [third_httponly, third_secure], width, label='Third-Party', color='#e74c3c')
    
    ax2.set_ylabel('Percentage (%)')
    ax2.set_title('Security Attributes by Party Type', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(['HttpOnly', 'Secure'])
    ax2.legend()
    ax2.set_ylim(0, 100)
    ax2.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}%', ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'party_comparison.png'), bbox_inches='tight')
    plt.close()


def plot_security_heatmap(agg_path: str, output_path: str):
    """Heatmap of security attributes by PII class."""
    csv_path = os.path.join(agg_path, 'summary_tables', 'cookie_security_by_pii_class.csv')
    df = pd.read_csv(csv_path)
    
    # Convert percentages
    for col in ['HttpOnly_Pct', 'Secure_Pct', 'SameSite_Protected_Pct', 'Third_Party_Pct']:
        df[col] = df[col].str.rstrip('%').astype(float)
    
    # Select top 12 by cookie count
    df_top = df.nlargest(12, 'Total_Cookies').copy()
    
    # Prepare data for heatmap
    heatmap_data = df_top[['HttpOnly_Pct', 'Secure_Pct', 'SameSite_Protected_Pct', 'Third_Party_Pct']].values
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    im = ax.imshow(heatmap_data, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
    
    # Set ticks
    ax.set_xticks(np.arange(4))
    ax.set_yticks(np.arange(len(df_top)))
    ax.set_xticklabels(['HttpOnly', 'Secure', 'SameSite', 'Third-Party'])
    ax.set_yticklabels(df_top['PII_Class'])
    
    # Rotate x labels
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Percentage (%)', rotation=270, labelpad=20)
    
    # Add text annotations
    for i in range(len(df_top)):
        for j in range(4):
            text = ax.text(j, i, f'{heatmap_data[i, j]:.1f}%',
                          ha="center", va="center", color="black", fontsize=8)
    
    ax.set_title('Security Attributes Heatmap by PII Classification', fontweight='bold', pad=20)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'security_heatmap.png'), bbox_inches='tight')
    plt.close()


def plot_storage_comparison(agg_path: str, output_path: str):
    """Multi-metric comparison across storage types."""
    storage_types = ['cookies', 'localstorage', 'sessionstorage', 'indexeddb']
    
    metrics = {
        'Total Items': [],
        'PII Classes': [],
        'High/Critical %': []
    }
    
    for storage in storage_types:
        global_path = os.path.join(agg_path, storage, 'global.json')
        with open(global_path, 'r') as f:
            data = json.load(f)
        
        total_key = 'total_cookies' if storage == 'cookies' else 'total_items'
        total = data.get(total_key, 0)
        num_pii = len(data.get('risk_by_pii', {}))
        
        risk_levels = data.get('risk_levels', {})
        critical = risk_levels.get('Critical Risk', 0)
        high = risk_levels.get('High Risk', 0)
        high_critical_pct = ((critical + high) / total * 100) if total > 0 else 0
        
        metrics['Total Items'].append(total)
        metrics['PII Classes'].append(num_pii)
        metrics['High/Critical %'].append(high_critical_pct)
    
    # Create radar chart
    fig = plt.figure(figsize=(12, 6))
    
    # Normalize metrics for radar chart
    normalized_metrics = {
        'Total Items': [x / max(metrics['Total Items']) * 100 for x in metrics['Total Items']],
        'PII Classes': [x / max(metrics['PII Classes']) * 100 for x in metrics['PII Classes']],
        'High/Critical %': metrics['High/Critical %']
    }
    
    # Create subplots
    ax1 = plt.subplot(121, projection='polar')
    ax2 = plt.subplot(122)
    
    # Radar chart
    categories = list(normalized_metrics.keys())
    N = len(categories)
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]
    
    colors = ['#3498db', '#2ecc71', '#f39c12', '#9b59b6']
    
    for idx, storage in enumerate(storage_types):
        values = [normalized_metrics[cat][idx] for cat in categories]
        values += values[:1]
        ax1.plot(angles, values, 'o-', linewidth=2, label=storage.capitalize(), color=colors[idx])
        ax1.fill(angles, values, alpha=0.15, color=colors[idx])
    
    ax1.set_xticks(angles[:-1])
    ax1.set_xticklabels(categories)
    ax1.set_ylim(0, 100)
    ax1.set_title('Storage Type Comparison (Normalized)', fontweight='bold', pad=20)
    ax1.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
    ax1.grid(True)
    
    # Bar chart for actual values
    x = np.arange(len(storage_types))
    width = 0.25
    
    ax2.bar(x - width, [m/1000 for m in metrics['Total Items']], width, label='Total Items (k)', color='#3498db')
    ax2.bar(x, metrics['PII Classes'], width, label='PII Classes', color='#2ecc71')
    ax2.bar(x + width, metrics['High/Critical %'], width, label='High/Critical %', color='#e74c3c')
    
    ax2.set_xlabel('Storage Type')
    ax2.set_title('Storage Metrics (Actual Values)', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels([s.capitalize() for s in storage_types])
    ax2.legend()
    ax2.grid(axis='y', alpha=0.3)
    
    plt.suptitle('Comprehensive Storage Type Comparison', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'storage_comparison.png'), bbox_inches='tight')
    plt.close()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python aggregation_viz.py <aggregations_path>")
        sys.exit(1)
    
    aggregations_path = sys.argv[1]
    create_aggregation_visualizations(aggregations_path)


def plot_security_gaps_by_policy(agg_path: str, output_path: str):
    """Bar chart showing security GAPS (non-conformity) across policies."""
    csv_path = os.path.join(agg_path, 'summary_tables', 'cookie_security_by_policy.csv')
    df = pd.read_csv(csv_path)
    
    # Convert percentages to floats
    for col in ['HttpOnly_Missing_Pct', 'Secure_Missing_Pct', 'SameSite_Unprotected_Pct', 'Third_Party_Pct']:
        df[col] = df[col].str.rstrip('%').astype(float)
    
    # Create grouped bar chart
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Security Gaps (Non-Conformity) by Consent Policy and Authentication Mode', 
                 fontsize=14, fontweight='bold', color='#c0392b')
    
    attributes = [
        ('HttpOnly_Missing_Pct', 'Missing HttpOnly Protection (%)'),
        ('Secure_Missing_Pct', 'Missing Secure Flag (%)'),
        ('SameSite_Unprotected_Pct', 'Missing SameSite Protection (%)'),
        ('Third_Party_Pct', 'Third-Party Cookies (%)')
    ]
    
    colors_danger = ['#e74c3c', '#c0392b']  # Red shades for danger
    
    for idx, (attr, title) in enumerate(attributes):
        ax = axes[idx // 2, idx % 2]
        
        # Prepare data for grouped bar chart
        df_pivot = df.pivot(index='Policy', columns='Mode', values=attr)
        df_pivot.plot(kind='bar', ax=ax, color=colors_danger, width=0.7)
        
        ax.set_title(title, fontweight='bold', color='#c0392b')
        ax.set_xlabel('Consent Policy')
        ax.set_ylabel('Percentage (%)')
        ax.set_ylim(0, 100)
        ax.legend(title='Mode', loc='upper right')
        ax.grid(axis='y', alpha=0.3)
        
        # Add danger threshold line at 50%
        ax.axhline(y=50, color='darkred', linestyle='--', alpha=0.5, linewidth=1)
        
        # Add value labels on bars
        for container in ax.containers:
            for bar in container:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.1f}%', ha='center', va='bottom', fontsize=8, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'security_gaps_by_policy.png'), bbox_inches='tight')
    plt.close()


def plot_nonconformity_heatmap(agg_path: str, output_path: str):
    """Heatmap showing NON-CONFORMITY percentages by PII class."""
    csv_path = os.path.join(agg_path, 'summary_tables', 'cookie_security_by_pii_class.csv')
    df = pd.read_csv(csv_path)
    
    # Convert percentages
    for col in ['HttpOnly_Missing_Pct', 'Secure_Missing_Pct', 'SameSite_Unprotected_Pct', 'Third_Party_Pct']:
        df[col] = df[col].str.rstrip('%').astype(float)
    
    # Select top 12 by cookie count
    df_top = df.nlargest(12, 'Total_Cookies').copy()
    
    # Prepare data for heatmap (NON-CONFORMITY)
    heatmap_data = df_top[['HttpOnly_Missing_Pct', 'Secure_Missing_Pct', 
                            'SameSite_Unprotected_Pct', 'Third_Party_Pct']].values
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Use reversed RdYlGn (red=bad, green=good) - reversed because we show non-conformity
    im = ax.imshow(heatmap_data, cmap='RdYlGn_r', aspect='auto', vmin=0, vmax=100)
    
    # Set ticks
    ax.set_xticks(np.arange(4))
    ax.set_yticks(np.arange(len(df_top)))
    ax.set_xticklabels(['Missing\nHttpOnly', 'Missing\nSecure', 'Missing\nSameSite', 'Third-Party'])
    ax.set_yticklabels(df_top['PII_Class'])
    
    # Rotate x labels
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center")
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Non-Conformity (%)', rotation=270, labelpad=20)
    
    # Add text annotations
    for i in range(len(df_top)):
        for j in range(4):
            value = heatmap_data[i, j]
            # Use white text for dark backgrounds, black for light
            text_color = "white" if value > 50 else "black"
            text = ax.text(j, i, f'{value:.1f}%',
                          ha="center", va="center", color=text_color, 
                          fontsize=8, fontweight='bold')
    
    ax.set_title('Security Non-Conformity Heatmap by PII Classification\n(Red = High Non-Conformity = Bad)', 
                 fontweight='bold', pad=20, color='#c0392b')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'nonconformity_heatmap.png'), bbox_inches='tight')
    plt.close()


def plot_conformity_comparison(agg_path: str, output_path: str):
    """Side-by-side comparison of conformity vs non-conformity for top PII classes."""
    csv_path = os.path.join(agg_path, 'summary_tables', 'cookie_security_by_pii_class.csv')
    df = pd.read_csv(csv_path)
    
    # Convert percentages
    for col in ['HttpOnly_Pct', 'HttpOnly_Missing_Pct', 'Secure_Pct', 'Secure_Missing_Pct',
                'SameSite_Protected_Pct', 'SameSite_Unprotected_Pct']:
        df[col] = df[col].str.rstrip('%').astype(float)
    
    # Select top 8 by cookie count for readability
    df_top = df.nlargest(8, 'Total_Cookies').copy()
    
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle('Security Conformity vs Non-Conformity Comparison (Top 8 PII Classes)', 
                 fontsize=14, fontweight='bold')
    
    x = np.arange(len(df_top))
    width = 0.35
    
    attributes = [
        ('HttpOnly', 'HttpOnly_Pct', 'HttpOnly_Missing_Pct'),
        ('Secure', 'Secure_Pct', 'Secure_Missing_Pct'),
        ('SameSite', 'SameSite_Protected_Pct', 'SameSite_Unprotected_Pct')
    ]
    
    for idx, (name, conf_col, nonconf_col) in enumerate(attributes):
        ax = axes[idx]
        
        # Stacked bar chart
        bars1 = ax.bar(x, df_top[conf_col], width, label='Conforme', color='#2ecc71', alpha=0.8)
        bars2 = ax.bar(x, df_top[nonconf_col], width, bottom=df_top[conf_col], 
                      label='Non-Conforme', color='#e74c3c', alpha=0.8)
        
        ax.set_ylabel('Percentage (%)')
        ax.set_title(f'{name} Protection', fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(df_top['PII_Class'], rotation=45, ha='right')
        ax.set_ylim(0, 100)
        ax.legend(loc='upper right')
        ax.grid(axis='y', alpha=0.3)
        
        # Add 50% threshold line
        ax.axhline(y=50, color='orange', linestyle='--', alpha=0.5, linewidth=1)
        
        # Add percentage labels for non-conformity
        for i, bar in enumerate(bars2):
            height = bar.get_height()
            if height > 10:  # Only show if significant
                ax.text(bar.get_x() + bar.get_width()/2., 
                       df_top[conf_col].iloc[i] + height/2,
                       f'{height:.0f}%', ha='center', va='center', 
                       color='white', fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'conformity_comparison.png'), bbox_inches='tight')
    plt.close()
