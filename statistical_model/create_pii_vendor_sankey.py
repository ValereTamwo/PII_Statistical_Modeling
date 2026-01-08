import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict


def create_pii_vendor_sankey(agg_path: str, output_path: str):
    """
    Create Sankey diagram showing PII class → Vendor flows.
    Shows where sensitive PII data is being sent to third-party vendors.
    """
    
    # Aggregate category_vendor_flows from all users/policies/modes
    results_base = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(agg_path))), 'results')
    
    all_flows = defaultdict(int)
    
    for auth in ['Auth', 'UnAuth']:
        for user in ['FR_0017', 'FR_0018', 'FR_0019']:
            for policy in ['ALL', 'PARTIAL', 'NONE']:
                for lifecycle in ['added', 'modified', 'removed']:
                    analysis_path = os.path.join(results_base, auth, user, policy, 
                                                'cookies', lifecycle, 'consolidated', 'analysis.json')
                    
                    if os.path.exists(analysis_path):
                        with open(analysis_path, 'r') as f:
                            data = json.load(f)
                        
                        category_vendor_flows = data.get('category_vendor_flows', [])
                        
                        for flow in category_vendor_flows:
                            if len(flow) == 3:
                                pii_class, vendor, count = flow
                                key = (pii_class, vendor)
                                all_flows[key] += count
    
    if not all_flows:
        print("Warning: No category_vendor_flows data found")
        return
    
    # Convert to DataFrame
    df_flows = pd.DataFrame([
        {'PII_Class': k[0], 'Vendor': k[1], 'Count': v}
        for k, v in all_flows.items()
    ])
    
    # Filter for significant flows (top vendors and PII classes)
    # Get top 15 PII classes by total volume
    top_pii = df_flows.groupby('PII_Class')['Count'].sum().nlargest(15).index.tolist()
    
    # Get top 30 vendors by total volume
    top_vendors = df_flows.groupby('Vendor')['Count'].sum().nlargest(30).index.tolist()
    
    # Filter flows
    df_filtered = df_flows[
        (df_flows['PII_Class'].isin(top_pii)) & 
        (df_flows['Vendor'].isin(top_vendors))
    ]
    
    # Group small flows into "Others"
    min_flow_threshold = df_filtered['Count'].quantile(0.7)  # Keep top 30% of flows
    
    # Create Sankey-style visualization using matplotlib
    # Since plotly might not be available, we'll create a custom flow diagram
    
    fig, ax = plt.subplots(figsize=(20, 14))
    
    # Prepare data for visualization
    pii_classes = sorted(df_filtered['PII_Class'].unique())
    vendors = sorted(df_filtered['Vendor'].unique())
    
    # Create positions
    pii_y_positions = {pii: i for i, pii in enumerate(pii_classes)}
    vendor_y_positions = {vendor: i for i, vendor in enumerate(vendors)}
    
    # Normalize positions
    pii_y_max = len(pii_classes) - 1
    vendor_y_max = len(vendors) - 1
    
    # Draw flows
    for _, row in df_filtered.iterrows():
        pii = row['PII_Class']
        vendor = row['Vendor']
        count = row['Count']
        
        if count < min_flow_threshold:
            continue
        
        # Normalize y positions to match
        pii_y = pii_y_positions[pii] / pii_y_max if pii_y_max > 0 else 0.5
        vendor_y = vendor_y_positions[vendor] / vendor_y_max if vendor_y_max > 0 else 0.5
        
        # Scale y to plot coordinates
        pii_y_plot = pii_y * 0.8 + 0.1
        vendor_y_plot = vendor_y * 0.8 + 0.1
        
        # Line width proportional to count
        linewidth = np.log1p(count) * 2
        
        # Color based on PII class risk
        if 'IDENTITY' in pii or 'ID_SOLUTIONS' in pii:
            color = '#e74c3c'
            alpha = 0.3
        elif 'CONSENT' in pii or 'PRIVACY' in pii:
            color = '#3498db'
            alpha = 0.3
        elif 'SUSPICIOUS' in pii or 'UNCATEGORIZED' in pii:
            color = '#95a5a6'
            alpha = 0.2
        else:
            color = '#2ecc71'
            alpha = 0.3
        
        # Draw curved line
        x = np.linspace(0.2, 0.8, 100)
        y = pii_y_plot + (vendor_y_plot - pii_y_plot) * (1 - np.cos(np.pi * (x - 0.2) / 0.6)) / 2
        
        ax.plot(x, y, color=color, linewidth=linewidth, alpha=alpha, solid_capstyle='round')
    
    # Draw PII class nodes (left)
    for pii, y_idx in pii_y_positions.items():
        y = (y_idx / pii_y_max if pii_y_max > 0 else 0.5) * 0.8 + 0.1
        
        # Node size based on total flow
        total_flow = df_filtered[df_filtered['PII_Class'] == pii]['Count'].sum()
        node_size = np.log1p(total_flow) * 100
        
        # Color based on category
        if 'IDENTITY' in pii or 'ID_SOLUTIONS' in pii:
            node_color = '#e74c3c'
        elif 'CONSENT' in pii or 'PRIVACY' in pii:
            node_color = '#3498db'
        elif 'SUSPICIOUS' in pii or 'UNCATEGORIZED' in pii:
            node_color = '#95a5a6'
        else:
            node_color = '#2ecc71'
        
        ax.scatter(0.2, y, s=node_size, color=node_color, edgecolor='black', 
                  linewidth=2, zorder=10, alpha=0.8)
        
        # Label
        label = pii.replace('_', ' ')
        if len(label) > 25:
            label = label[:22] + '...'
        ax.text(0.15, y, label, ha='right', va='center', fontsize=9, fontweight='bold')
    
    # Draw Vendor nodes (right)
    for vendor, y_idx in vendor_y_positions.items():
        y = (y_idx / vendor_y_max if vendor_y_max > 0 else 0.5) * 0.8 + 0.1
        
        # Node size based on total flow
        total_flow = df_filtered[df_filtered['Vendor'] == vendor]['Count'].sum()
        node_size = np.log1p(total_flow) * 100
        
        # Color based on vendor type
        if any(x in vendor.lower() for x in ['google', 'facebook', 'meta', 'microsoft']):
            node_color = '#9b59b6'  # Big tech
        elif any(x in vendor.lower() for x in ['criteo', 'taboola', 'outbrain', 'adnxs', 'adsrvr']):
            node_color = '#e67e22'  # Adtech
        elif '.fr' in vendor or 'france' in vendor.lower():
            node_color = '#3498db'  # French sites
        else:
            node_color = '#34495e'  # Others
        
        ax.scatter(0.8, y, s=node_size, color=node_color, edgecolor='black', 
                  linewidth=2, zorder=10, alpha=0.8)
        
        # Label
        label = vendor
        if len(label) > 20:
            label = label[:17] + '...'
        ax.text(0.85, y, label, ha='left', va='center', fontsize=8, fontweight='bold')
    
    # Add titles
    ax.text(0.2, 0.95, 'PII Classes', ha='center', va='bottom', 
           fontsize=14, fontweight='bold', color='#2c3e50')
    ax.text(0.8, 0.95, 'Third-Party Vendors', ha='center', va='bottom', 
           fontsize=14, fontweight='bold', color='#2c3e50')
    
    # Add legend
    legend_elements = [
        plt.Line2D([0], [0], color='#e74c3c', linewidth=4, alpha=0.5, label='Identity/Tracking PII'),
        plt.Line2D([0], [0], color='#3498db', linewidth=4, alpha=0.5, label='Consent/Privacy PII'),
        plt.Line2D([0], [0], color='#2ecc71', linewidth=4, alpha=0.5, label='Other PII'),
        plt.Line2D([0], [0], color='#95a5a6', linewidth=4, alpha=0.5, label='Suspicious/Uncategorized')
    ]
    ax.legend(handles=legend_elements, loc='upper center', bbox_to_anchor=(0.5, -0.02),
             ncol=4, frameon=True, fontsize=10)
    
    # Styling
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    
    plt.suptitle('PII Data Flows to Third-Party Vendors\n(Sankey-Style Flow Diagram)', 
                 fontsize=16, fontweight='bold', y=0.98)
    
    # Add summary text
    total_flows = df_filtered['Count'].sum()
    num_pii_classes = len(pii_classes)
    num_vendors = len(vendors)
    
    fig.text(0.5, 0.02, 
             f'Showing {num_pii_classes} PII classes flowing to {num_vendors} vendors ({total_flows:,} total cookies)\n' +
             f'Line thickness represents volume of data flow',
             ha='center', fontsize=10, style='italic',
             bbox=dict(boxstyle='round,pad=0.8', facecolor='#fff3cd', edgecolor='#856404', linewidth=2))
    
    plt.tight_layout(rect=[0, 0.05, 1, 0.96])
    plt.savefig(os.path.join(output_path, 'pii_vendor_sankey.png'), 
                bbox_inches='tight', dpi=300)
    plt.close()
    
    print("  - PII to Vendor Sankey diagram created")
    
    # Create summary table
    create_pii_vendor_table(df_filtered, output_path)


def create_pii_vendor_table(df_flows, output_path):
    """Create CSV summary of PII-Vendor flows."""
    summary_path = os.path.join(output_path, '..', 'summary_tables')
    os.makedirs(summary_path, exist_ok=True)
    
    # Top flows
    df_top_flows = df_flows.nlargest(50, 'Count')
    df_top_flows.to_csv(os.path.join(summary_path, 'top_pii_vendor_flows.csv'), index=False)
    
    # Summary by PII class
    pii_summary = df_flows.groupby('PII_Class').agg({
        'Count': 'sum',
        'Vendor': 'count'
    }).rename(columns={'Vendor': 'Num_Vendors'}).sort_values('Count', ascending=False)
    pii_summary.to_csv(os.path.join(summary_path, 'pii_vendor_summary_by_class.csv'))
    
    # Summary by Vendor
    vendor_summary = df_flows.groupby('Vendor').agg({
        'Count': 'sum',
        'PII_Class': 'count'
    }).rename(columns={'PII_Class': 'Num_PII_Classes'}).sort_values('Count', ascending=False)
    vendor_summary.to_csv(os.path.join(summary_path, 'pii_vendor_summary_by_vendor.csv'))
    
    print("  - PII-Vendor flow tables created")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python create_pii_vendor_sankey.py <aggregations_path>")
        sys.exit(1)
    
    agg_path = sys.argv[1]
    viz_path = os.path.join(agg_path, 'visualizations')
    os.makedirs(viz_path, exist_ok=True)
    
    create_pii_vendor_sankey(agg_path, viz_path)
    print("PII-Vendor Sankey diagram created!")
