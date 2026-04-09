import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import defaultdict


def create_aggregated_lifecycle_heatmap(results_base: str, output_path: str):
    """
    Create aggregated lifecycle activity heatmap across all users/policies/modes.
    Shows:
    1. Top modified cookies (most volatile)
    2. PII transition matrix (aggregated)
    3. Volatility distribution
    """
    
    # Data collection across experimental dimensions (Auth/UnAuth, User, Policy)
    all_lifecycle_data = []
    all_transitions = defaultdict(int)
    all_modified_keys = defaultdict(int)
    volatility_totals = defaultdict(int)
    
    for auth in ['Auth', 'UnAuth']:
        for user in ['FR_0417', 'FR_0446', 'FR_0458']:
            for policy in ['ALL', 'PARTIAL', 'NONE']:
                lifecycle_path = os.path.join(results_base, auth, user, policy, 
                                             'cookies', 'lifecycle', 'lifecycle_data.json')
                
                if os.path.exists(lifecycle_path):
                    with open(lifecycle_path, 'r') as f:
                        data = json.load(f)
                    
                    all_lifecycle_data.append(data)
                    
                    # Transition and volatility aggregation
                    transitions = data.get('metrics', {}).get('pii_transitions', {})
                    for trans, count in transitions.items():
                        all_transitions[trans] += count
                    
                    top_keys = data.get('top_modified_keys', [])
                    for key in top_keys:
                        all_modified_keys[key] += 1
                    
                    volatility = data.get('metrics', {}).get('volatility_distribution', {})
                    for level, count in volatility.items():
                        volatility_totals[level] += count
    
    fig = plt.figure(figsize=(20, 12))
    
    # 1. Top Modified Cookies (most volatile)
    ax1 = plt.subplot(3, 2, (1, 2))
    
    # Rank-ordered distribution of cookie volatility
    top_modified = sorted(all_modified_keys.items(), key=lambda x: x[1], reverse=True)[:20]
    
    if top_modified:
        keys = [k[0].split('|')[0][:30] for k in top_modified]  # Cookie name only, truncated
        counts = [k[1] for k in top_modified]
        
        bars = ax1.barh(keys, counts, color='#e74c3c', edgecolor='black', linewidth=0.5)
        ax1.set_xlabel('Frequency Across All Users/Policies', fontweight='bold', fontsize=11)
        ax1.set_title('Top 20 Most Modified Cookies (Highest Volatility)', 
                     fontweight='bold', fontsize=13, color='#c0392b')
        ax1.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax1.text(width + 0.1, bar.get_y() + bar.get_height()/2.,
                    f'{int(width)}', ha='left', va='center', fontsize=9, fontweight='bold')
    
    # 2. Volatility Distribution
    ax2 = plt.subplot(3, 2, 3)
    
    if volatility_totals:
        levels = list(volatility_totals.keys())
        values = list(volatility_totals.values())
        colors_vol = {'stable': '#2ecc71', 'moderate': '#f39c12', 'high': '#e74c3c'}
        bar_colors = [colors_vol.get(l, '#95a5a6') for l in levels]
        
        bars2 = ax2.bar(levels, values, color=bar_colors, edgecolor='black', linewidth=1.5)
        ax2.set_ylabel('Number of Cookies', fontweight='bold')
        ax2.set_title('Cookie Volatility Distribution', fontweight='bold', fontsize=13)
        ax2.grid(axis='y', alpha=0.3)
        
        # Add value labels
        for bar in bars2:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height):,}', ha='center', va='bottom', fontweight='bold')
    
    # 3. PII Transition Matrix (Top transitions)
    ax3 = plt.subplot(3, 2, (4, 6))
    
    # Get top 30 transitions
    top_transitions = sorted(all_transitions.items(), key=lambda x: x[1], reverse=True)[:30]
    
    if top_transitions:
        # Parse transitions into source -> target
        transition_data = []
        for trans, count in top_transitions:
            parts = trans.split('  ')
            if len(parts) == 2:
                source_full = parts[0]
                target_full = parts[1]
                
                # Extract PII class (before ::)
                source = source_full.split('::')[0] if '::' in source_full else source_full
                target = target_full.split('::')[0] if '::' in target_full else target_full
                
                transition_data.append({
                    'source': source,
                    'target': target,
                    'count': count,
                    'full_transition': trans
                })
        
        df_trans = pd.DataFrame(transition_data)
        
        # Create transition matrix
        all_classes = sorted(set(df_trans['source'].tolist() + df_trans['target'].tolist()))
        matrix = np.zeros((len(all_classes), len(all_classes)))
        
        for _, row in df_trans.iterrows():
            i = all_classes.index(row['source'])
            j = all_classes.index(row['target'])
            matrix[i, j] += row['count']
        
        # Plot heatmap
        im = ax3.imshow(matrix, cmap='YlOrRd', aspect='auto')
        
        ax3.set_xticks(np.arange(len(all_classes)))
        ax3.set_yticks(np.arange(len(all_classes)))
        ax3.set_xticklabels(all_classes, rotation=45, ha='right', fontsize=9)
        ax3.set_yticklabels(all_classes, fontsize=9)
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax3)
        cbar.set_label('Transition Count', rotation=270, labelpad=20, fontweight='bold')
        
        # Add text annotations for significant transitions
        for i in range(len(all_classes)):
            for j in range(len(all_classes)):
                value = matrix[i, j]
                if value > 0:
                    text_color = "white" if value > matrix.max() * 0.5 else "black"
                    ax3.text(j, i, f'{int(value)}',
                            ha="center", va="center", color=text_color, 
                            fontsize=7, fontweight='bold')
        
        ax3.set_title('PII Class Transition Matrix\n(Aggregated Across All Users/Policies)', 
                     fontweight='bold', fontsize=13)
        ax3.set_xlabel('Target PII Class', fontweight='bold')
        ax3.set_ylabel('Source PII Class', fontweight='bold')
        
        # Add grid
        ax3.set_xticks(np.arange(len(all_classes))-.5, minor=True)
        ax3.set_yticks(np.arange(len(all_classes))-.5, minor=True)
        ax3.grid(which="minor", color="white", linestyle='-', linewidth=2)
    
    # 4. Modification Statistics
    ax4 = plt.subplot(3, 2, 5)
    
    # Aggregate modification stats
    total_cookies = sum(d.get('metrics', {}).get('total_cookies', 0) for d in all_lifecycle_data)
    total_modified = sum(d.get('metrics', {}).get('cookies_modified', 0) for d in all_lifecycle_data)
    duration_inc = sum(d.get('metrics', {}).get('duration_increases', 0) for d in all_lifecycle_data)
    duration_dec = sum(d.get('metrics', {}).get('duration_decreases', 0) for d in all_lifecycle_data)
    
    stats_data = {
        'Total Cookies': total_cookies,
        'Modified': total_modified,
        'Duration ': duration_inc,
        'Duration ': duration_dec
    }
    
    bars4 = ax4.bar(stats_data.keys(), stats_data.values(), 
                    color=['#3498db', '#e74c3c', '#2ecc71', '#f39c12'],
                    edgecolor='black', linewidth=1.5)
    ax4.set_ylabel('Count', fontweight='bold')
    ax4.set_title('Lifecycle Modification Statistics', fontweight='bold', fontsize=13)
    ax4.grid(axis='y', alpha=0.3)
    plt.setp(ax4.xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    # Add value labels
    for bar in bars4:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height):,}', ha='center', va='bottom', fontweight='bold', fontsize=9)
    
    plt.suptitle('Aggregated Cookie Lifecycle Activity Analysis\n(All Users, Policies, and Modes)', 
                 fontsize=16, fontweight='bold', y=0.98)
    
    # Add summary text
    modification_rate = (total_modified / total_cookies * 100) if total_cookies > 0 else 0
    fig.text(0.5, 0.02, 
             f'Summary: {total_modified:,} out of {total_cookies:,} cookies were modified ({modification_rate:.1f}%)\n' +
             f'Volatility: {volatility_totals.get("stable", 0):,} stable, {volatility_totals.get("moderate", 0):,} moderate, {volatility_totals.get("high", 0):,} high',
             ha='center', fontsize=11, style='italic',
             bbox=dict(boxstyle='round,pad=0.8', facecolor='#e8f4f8', edgecolor='#3498db', linewidth=2))
    
    plt.tight_layout(rect=[0, 0.05, 1, 0.96])
    plt.savefig(os.path.join(output_path, 'aggregated_lifecycle_activity.png'), 
                bbox_inches='tight', dpi=300)
    plt.close()
    
    print("  - Aggregated lifecycle activity heatmap created")
    
    # Create summary table
    create_lifecycle_activity_table(top_modified, top_transitions, output_path)


def create_lifecycle_activity_table(top_modified, top_transitions, output_path):
    """Create CSV summary of lifecycle activity."""
    summary_path = os.path.join(output_path, '..', 'summary_tables')
    os.makedirs(summary_path, exist_ok=True)
    
    # Top modified cookies table
    df_modified = pd.DataFrame(top_modified, columns=['Cookie_Key', 'Modification_Frequency'])
    df_modified.to_csv(os.path.join(summary_path, 'top_modified_cookies.csv'), index=False)
    
    # Top transitions table
    df_transitions = pd.DataFrame(top_transitions, columns=['Transition', 'Count'])
    df_transitions.to_csv(os.path.join(summary_path, 'top_pii_transitions.csv'), index=False)
    
    print("  - Lifecycle activity tables created")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python create_aggregated_lifecycle_activity.py <aggregations_path>")
        sys.exit(1)
    
    agg_path = sys.argv[1]
    viz_path = os.path.join(agg_path, 'visualizations')
    os.makedirs(viz_path, exist_ok=True)
    
    # Get results base path
    results_base = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(agg_path))), 'results')
    
    create_aggregated_lifecycle_heatmap(results_base, viz_path)
    print("Aggregated lifecycle activity visualization created!")
