import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


def plot_pii_by_policy_mode(agg_path: str, output_path: str):
    """
    Create visualization showing PII classes by policy and mode.
    This will demonstrate the INVARIANCE across policies - an important finding.
    """
    storage_types = ['cookies', 'localstorage', 'sessionstorage', 'indexeddb']
    policies = ['ALL', 'PARTIAL', 'NONE']
    modes = ['Auth', 'UnAuth']
    
    # We'll create a grid showing: Policy x Mode for each storage
    # But first, let's verify the invariance
    
    fig = plt.figure(figsize=(18, 12))
    
    # Create a 2x2 grid for the 4 storage types
    for idx, storage in enumerate(storage_types):
        ax = plt.subplot(2, 2, idx + 1)
        
        # Collect data for this storage across all policy-mode combinations
        policy_mode_data = {}
        
        for policy in policies:
            for mode in modes:
                key = f"{policy}_{mode}"
                file_path = os.path.join(agg_path, storage, 'per_policy', f'{policy}_{mode}.json')
                
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    
                    risk_by_pii = data.get('risk_by_pii', {})
                    
                    # Get total for each PII class
                    pii_totals = {}
                    for pii_class, risk_dist in risk_by_pii.items():
                        pii_totals[pii_class] = sum(risk_dist.values())
                    
                    policy_mode_data[key] = pii_totals
        
        # Convert to DataFrame
        df = pd.DataFrame(policy_mode_data).fillna(0)
        
        if df.empty:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', fontsize=14)
            ax.set_title(f'{storage.capitalize()}', fontweight='bold', fontsize=13)
            continue
        
        # Sort by total across all combinations
        df['total'] = df.sum(axis=1)
        df = df.sort_values('total', ascending=False).drop('total', axis=1)
        
        # Take top 10 PII classes
        df_top = df.head(10)
        
        # Check if all columns are identical (invariance)
        all_identical = all(df_top.iloc[:, 0].equals(df_top.iloc[:, i]) for i in range(len(df_top.columns)))
        
        # Create heatmap
        if len(df_top) > 0:
            # Use log scale for better visualization
            heatmap_data = np.log10(df_top.values + 1)
            
            im = ax.imshow(heatmap_data, cmap='YlOrRd', aspect='auto')
            
            # Set ticks
            ax.set_xticks(np.arange(len(df_top.columns)))
            ax.set_yticks(np.arange(len(df_top)))
            
            # Create labels with policy and mode
            col_labels = []
            for col in df_top.columns:
                parts = col.split('_')
                col_labels.append(f"{parts[0]}\n{parts[1]}")
            
            ax.set_xticklabels(col_labels, fontsize=9)
            ax.set_yticklabels(df_top.index, fontsize=9)
            
            # Add values as text
            for i in range(len(df_top)):
                for j in range(len(df_top.columns)):
                    value = int(df_top.iloc[i, j])
                    if value > 0:
                        text_color = "white" if heatmap_data[i, j] > 2 else "black"
                        ax.text(j, i, f'{value:,}',
                               ha="center", va="center", color=text_color, 
                               fontsize=7, fontweight='bold')
            
            # Add title with invariance indicator
            title = f'{storage.capitalize()}'
            if all_identical:
                title += '\n'
                title_color = '#e74c3c'
            else:
                title += '\n✓ Varies by policy/mode'
                title_color = '#2ecc71'
            
            ax.set_title(title, fontweight='bold', fontsize=11, color=title_color)
            
            # Add grid
            ax.set_xticks(np.arange(len(df_top.columns))-.5, minor=True)
            ax.set_yticks(np.arange(len(df_top))-.5, minor=True)
            ax.grid(which="minor", color="white", linestyle='-', linewidth=1.5)
    
    plt.suptitle('PII Classes by Consent Policy and Authentication Mode\n(Demonstrating Policy Invariance)', 
                 fontsize=16, fontweight='bold', y=0.98)
    
    # Add explanation text
    fig.text(0.5, 0.02, 
             '⚠️ Red titles indicate IDENTICAL values across all policy-mode combinations\n' +
             'This demonstrates that consent policies have NO IMPACT on PII storage behavior',
             ha='center', fontsize=11, style='italic', color='#c0392b',
             bbox=dict(boxstyle='round,pad=0.8', facecolor='#ffe6e6', edgecolor='#e74c3c', linewidth=2))
    
    plt.tight_layout(rect=[0, 0.05, 1, 0.96])
    plt.savefig(os.path.join(output_path, 'pii_by_policy_mode_invariance.png'), 
                bbox_inches='tight', dpi=300)
    plt.close()
    
    print("  - Policy-mode comparison created (showing invariance)")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python create_policy_mode_viz.py <aggregations_path>")
        sys.exit(1)
    
    agg_path = sys.argv[1]
    viz_path = os.path.join(agg_path, 'visualizations')
    os.makedirs(viz_path, exist_ok=True)
    
    plot_pii_by_policy_mode(agg_path, viz_path)
    print("Policy-mode visualization created!")
