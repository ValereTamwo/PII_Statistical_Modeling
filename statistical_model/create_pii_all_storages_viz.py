import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


def plot_pii_classes_all_storages(agg_path: str, output_path: str):
    """
    Heatmap showing PII classes across ALL storage types.
    Demonstrates that PII exists in localStorage, sessionStorage, and IndexedDB, not just cookies.
    """
    storage_types = ['cookies', 'localstorage', 'sessionstorage', 'indexeddb']
    storage_labels = ['Cookies', 'localStorage', 'sessionStorage', 'IndexedDB']
    
    # Collect PII data from all storages
    all_pii_data = {}
    
    for storage in storage_types:
        global_path = os.path.join(agg_path, storage, 'global.json')
        if os.path.exists(global_path):
            with open(global_path, 'r') as f:
                data = json.load(f)
            
            # Get risk_by_pii which contains all PII classes
            risk_by_pii = data.get('risk_by_pii', {})
            
            for pii_class, risk_dist in risk_by_pii.items():
                if pii_class not in all_pii_data:
                    all_pii_data[pii_class] = {}
                
                # Total items for this PII class in this storage
                total = sum(risk_dist.values())
                all_pii_data[pii_class][storage] = total
    
    # Create DataFrame
    df = pd.DataFrame(all_pii_data).T.fillna(0)
    df = df[storage_types]  # Ensure column order
    
    # Sort by total across all storages
    df['total'] = df.sum(axis=1)
    df = df.sort_values('total', ascending=False).drop('total', axis=1)
    
    # Take top 15 PII classes for readability
    df_top = df.head(15)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 10))
    
    # Create heatmap with log scale for better visualization
    # Add 1 to avoid log(0)
    heatmap_data = np.log10(df_top.values + 1)
    
    # Use custom colormap - green to red
    im = ax.imshow(heatmap_data, cmap='YlOrRd', aspect='auto')
    
    # Set ticks
    ax.set_xticks(np.arange(len(storage_labels)))
    ax.set_yticks(np.arange(len(df_top)))
    ax.set_xticklabels(storage_labels, fontsize=12, fontweight='bold')
    ax.set_yticklabels(df_top.index, fontsize=11)
    
    # Rotate x labels
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center")
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Number of Items (log scale)', rotation=270, labelpad=20, fontsize=11)
    
    # Add text annotations with actual values
    for i in range(len(df_top)):
        for j in range(len(storage_labels)):
            value = int(df_top.iloc[i, j])
            if value > 0:
                # Use white text for dark backgrounds, black for light
                text_color = "white" if heatmap_data[i, j] > 2 else "black"
                text = ax.text(j, i, f'{value:,}',
                              ha="center", va="center", color=text_color, 
                              fontsize=9, fontweight='bold')
    
    ax.set_title('PII Classes Across All Web Storage Types\n(Demonstrating PII Presence Beyond Cookies)', 
                 fontweight='bold', pad=20, fontsize=14)
    ax.set_xlabel('Storage Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('PII Classification', fontsize=12, fontweight='bold')
    
    # Add grid
    ax.set_xticks(np.arange(len(storage_labels))-.5, minor=True)
    ax.set_yticks(np.arange(len(df_top))-.5, minor=True)
    ax.grid(which="minor", color="white", linestyle='-', linewidth=2)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_path, 'pii_classes_all_storages.png'), 
                bbox_inches='tight', dpi=300)
    plt.close()
    
    # Also create a summary table
    create_pii_summary_table(df, output_path)


def create_pii_summary_table(df, output_path):
    """Create summary table showing PII presence across storages."""
    # Add totals and presence indicators
    summary = df.copy()
    summary['Total_Items'] = summary.sum(axis=1)
    summary['Present_In_Storages'] = (summary[['cookies', 'localstorage', 'sessionstorage', 'indexeddb']] > 0).sum(axis=1)
    
    # Sort by total
    summary = summary.sort_values('Total_Items', ascending=False)
    
    # Rename columns for clarity
    summary.columns = ['Cookies', 'localStorage', 'sessionStorage', 'IndexedDB', 'Total_Items', 'Present_In_N_Storages']
    
    # Save to CSV
    summary.to_csv(os.path.join(output_path, '..', 'summary_tables', 'pii_classes_all_storages.csv'))
    
    print(f"  - PII summary table created")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python create_pii_all_storages_viz.py <aggregations_path>")
        sys.exit(1)
    
    agg_path = sys.argv[1]
    viz_path = os.path.join(agg_path, 'visualizations')
    os.makedirs(viz_path, exist_ok=True)
    
    plot_pii_classes_all_storages(agg_path, viz_path)
    print("PII classes visualization created!")
