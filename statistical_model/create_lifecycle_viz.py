import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


def create_lifecycle_visualization(agg_path: str, output_path: str):
    """
    Create comprehensive lifecycle visualization showing:
    1. PII volume across lifecycle states (added, modified, deleted)
    2. Which PII classes change the most
    3. Persistence patterns
    """
    
    # We'll use the global aggregation which combines all users/policies/modes
    storage_path = os.path.join(agg_path, 'cookies')
    
    # Collect lifecycle data
    lifecycle_data = {}
    lifecycle_states = []
    
    # Check what lifecycle files exist
    for state in ['added', 'modified', 'deleted']:
        state_path = os.path.join(storage_path, 'per_mode', f'Auth.json')  # Use Auth mode as reference
        
        # Actually, we need to look at the original results structure
        # Let's use a different approach - aggregate from the results directly
        pass
    
    # Alternative: Create visualization from user-level data
    results_base = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(agg_path))), 'results')
    
    # Collect data from one representative user-policy-mode combination
    sample_path = os.path.join(results_base, 'Auth', 'FR_0017', 'ALL', 'cookies')
    
    lifecycle_pii = {'added': {}, 'modified': {}, 'deleted': {}}
    lifecycle_totals = {'added': 0, 'modified': 0, 'deleted': 0}
    
    for state in ['added', 'modified']:  # deleted might not have analysis.json
        analysis_path = os.path.join(sample_path, state, 'consolidated', 'analysis.json')
        
        if os.path.exists(analysis_path):
            with open(analysis_path, 'r') as f:
                data = json.load(f)
            
            lifecycle_totals[state] = data.get('total_cookies', 0)
            risk_by_pii = data.get('risk_by_pii', {})
            
            for pii_class, risk_dist in risk_by_pii.items():
                total = sum(risk_dist.values())
                lifecycle_pii[state][pii_class] = total
    
    # Check for deleted (might be in lifecycle folder)
    lifecycle_path = os.path.join(sample_path, 'lifecycle')
    if os.path.exists(lifecycle_path):
        # Look for lifecycle_data.json or similar
        for file in os.listdir(lifecycle_path):
            if 'deleted' in file.lower() and file.endswith('.json'):
                with open(os.path.join(lifecycle_path, file), 'r') as f:
                    try:
                        data = json.load(f)
                        # Extract deleted count if available
                        if 'deleted' in data:
                            lifecycle_totals['deleted'] = len(data['deleted'])
                    except:
                        pass
    
    # Create visualization
    fig = plt.figure(figsize=(18, 10))
    
    # 1. Overall lifecycle distribution (top left)
    ax1 = plt.subplot(2, 3, 1)
    states = [s for s in ['added', 'modified', 'deleted'] if lifecycle_totals[s] > 0]
    values = [lifecycle_totals[s] for s in states]
    colors = ['#2ecc71', '#f39c12', '#e74c3c'][:len(states)]
    
    bars = ax1.bar(states, values, color=colors, edgecolor='black', linewidth=1.5)
    ax1.set_title('Cookie Lifecycle Distribution', fontweight='bold', fontsize=13)
    ax1.set_ylabel('Number of Cookies', fontweight='bold')
    ax1.set_xlabel('Lifecycle State', fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height):,}', ha='center', va='bottom', fontweight='bold')
    
    # 2. PII classes comparison: Added vs Modified (top middle & right)
    # Get all PII classes
    all_pii = set(lifecycle_pii['added'].keys()) | set(lifecycle_pii['modified'].keys())
    
    # Create DataFrame for comparison
    df_lifecycle = pd.DataFrame({
        'PII_Class': list(all_pii),
        'Added': [lifecycle_pii['added'].get(pii, 0) for pii in all_pii],
        'Modified': [lifecycle_pii['modified'].get(pii, 0) for pii in all_pii]
    })
    
    # Calculate change rate
    df_lifecycle['Total'] = df_lifecycle['Added'] + df_lifecycle['Modified']
    df_lifecycle['Modification_Rate'] = (df_lifecycle['Modified'] / df_lifecycle['Total'] * 100).fillna(0)
    df_lifecycle = df_lifecycle.sort_values('Total', ascending=False).head(12)
    
    # 2a. Stacked bar: Added + Modified
    ax2 = plt.subplot(2, 3, 2)
    x = np.arange(len(df_lifecycle))
    width = 0.6
    
    ax2.bar(x, df_lifecycle['Added'], width, label='Added', color='#2ecc71', edgecolor='black', linewidth=0.5)
    ax2.bar(x, df_lifecycle['Modified'], width, bottom=df_lifecycle['Added'], 
            label='Modified', color='#f39c12', edgecolor='black', linewidth=0.5)
    
    ax2.set_title('PII Classes: Added vs Modified (Top 12)', fontweight='bold', fontsize=13)
    ax2.set_ylabel('Number of Cookies', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(df_lifecycle['PII_Class'], rotation=45, ha='right', fontsize=9)
    ax2.legend(loc='upper right')
    ax2.grid(axis='y', alpha=0.3)
    
    # 2b. Modification rate
    ax3 = plt.subplot(2, 3, 3)
    bars3 = ax3.barh(df_lifecycle['PII_Class'], df_lifecycle['Modification_Rate'], 
                     color='#3498db', edgecolor='black', linewidth=0.5)
    ax3.set_title('Modification Rate by PII Class', fontweight='bold', fontsize=13)
    ax3.set_xlabel('Modification Rate (%)', fontweight='bold')
    ax3.set_xlim(0, 100)
    ax3.axvline(x=50, color='red', linestyle='--', alpha=0.5, linewidth=1.5)
    ax3.grid(axis='x', alpha=0.3)
    
    # Add value labels
    for i, bar in enumerate(bars3):
        width = bar.get_width()
        if width > 5:
            ax3.text(width + 2, bar.get_y() + bar.get_height()/2.,
                    f'{width:.1f}%', ha='left', va='center', fontsize=8, fontweight='bold')
    
    # 3. Lifetime distribution (bottom row)
    # Load lifetime data from added cookies
    analysis_path = os.path.join(sample_path, 'added', 'consolidated', 'analysis.json')
    if os.path.exists(analysis_path):
        with open(analysis_path, 'r') as f:
            data = json.load(f)
        
        lifetime_by_pii = data.get('lifetime_by_pii', {})
        
        # Get top PII classes
        top_pii = df_lifecycle['PII_Class'].head(8).tolist()
        
        # 3a. Lifetime heatmap
        ax4 = plt.subplot(2, 3, (4, 6))
        
        lifetime_categories = ['Session', '<6 months', '6-18 months', '>18 months']
        heatmap_data = []
        pii_labels = []
        
        for pii in top_pii:
            if pii in lifetime_by_pii:
                row = []
                pii_data = lifetime_by_pii[pii]
                total = sum(pii_data.values())
                
                for cat in lifetime_categories:
                    count = pii_data.get(cat, 0)
                    percentage = (count / total * 100) if total > 0 else 0
                    row.append(percentage)
                
                heatmap_data.append(row)
                pii_labels.append(pii)
        
        if heatmap_data:
            heatmap_array = np.array(heatmap_data)
            
            im = ax4.imshow(heatmap_array, cmap='YlOrRd', aspect='auto', vmin=0, vmax=100)
            
            ax4.set_xticks(np.arange(len(lifetime_categories)))
            ax4.set_yticks(np.arange(len(pii_labels)))
            ax4.set_xticklabels(lifetime_categories, fontsize=11)
            ax4.set_yticklabels(pii_labels, fontsize=10)
            
            # Add colorbar
            cbar = plt.colorbar(im, ax=ax4)
            cbar.set_label('Percentage (%)', rotation=270, labelpad=20, fontweight='bold')
            
            # Add text annotations
            for i in range(len(pii_labels)):
                for j in range(len(lifetime_categories)):
                    value = heatmap_array[i, j]
                    if value > 0:
                        text_color = "white" if value > 50 else "black"
                        ax4.text(j, i, f'{value:.0f}%',
                                ha="center", va="center", color=text_color, 
                                fontsize=9, fontweight='bold')
            
            ax4.set_title('Cookie Lifetime Distribution by PII Class\n(Persistence Patterns)', 
                         fontweight='bold', fontsize=13)
            ax4.set_xlabel('Lifetime Category', fontweight='bold')
            ax4.set_ylabel('PII Classification', fontweight='bold')
            
            # Add grid
            ax4.set_xticks(np.arange(len(lifetime_categories))-.5, minor=True)
            ax4.set_yticks(np.arange(len(pii_labels))-.5, minor=True)
            ax4.grid(which="minor", color="white", linestyle='-', linewidth=2)
    
    plt.suptitle('PII Lifecycle Analysis: Persistence and Changes\n(Quantifying PII Dynamics)', 
                 fontsize=16, fontweight='bold', y=0.98)
    
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(os.path.join(output_path, 'pii_lifecycle_analysis.png'), 
                bbox_inches='tight', dpi=300)
    plt.close()
    
    print("  - Lifecycle analysis visualization created")
    
    # Also create a summary table
    create_lifecycle_summary_table(df_lifecycle, output_path)


def create_lifecycle_summary_table(df_lifecycle, output_path):
    """Create CSV summary of lifecycle data."""
    summary_path = os.path.join(output_path, '..', 'summary_tables')
    os.makedirs(summary_path, exist_ok=True)
    
    df_lifecycle.to_csv(os.path.join(summary_path, 'pii_lifecycle_summary.csv'), index=False)
    print("  - Lifecycle summary table created")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python create_lifecycle_viz.py <aggregations_path>")
        sys.exit(1)
    
    agg_path = sys.argv[1]
    viz_path = os.path.join(agg_path, 'visualizations')
    os.makedirs(viz_path, exist_ok=True)
    
    create_lifecycle_visualization(agg_path, viz_path)
    print("Lifecycle visualization created!")
