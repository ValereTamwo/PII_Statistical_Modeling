import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict


def create_pii_vendor_by_policy_mode(agg_path: str, output_path: str):
    """
    Create comparative Sankey diagrams showing PII → Vendor flows
    by Auth status and Policy to demonstrate invariance.
    """
    
    results_base = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(agg_path))), 'results')
    
    # Collect flows separately for each policy-mode combination
    flows_by_config = {}
    
    for auth in ['Auth', 'UnAuth']:
        for policy in ['ALL', 'PARTIAL', 'NONE']:
            key = f"{policy}_{auth}"
            flows_by_config[key] = defaultdict(int)
            
            for user in ['FR_0017', 'FR_0018', 'FR_0019']:
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
                                flow_key = (pii_class, vendor)
                                flows_by_config[key][flow_key] += count
    
    # Create 2x3 grid (2 auth modes × 3 policies)
    fig, axes = plt.subplots(2, 3, figsize=(24, 14))
    fig.suptitle('PII → Vendor Flows by Consent Policy and Authentication Mode\n', 
                 fontsize=16, fontweight='bold', y=0.98)
    
    configs = [
        ('ALL', 'Auth'), ('PARTIAL', 'Auth'), ('NONE', 'Auth'),
        ('ALL', 'UnAuth'), ('PARTIAL', 'UnAuth'), ('NONE', 'UnAuth')
    ]
    
    # Check if all are identical
    all_identical = True
    first_flows = None
    
    for policy, auth in configs:
        key = f"{policy}_{auth}"
        if first_flows is None:
            first_flows = flows_by_config[key]
        elif flows_by_config[key] != first_flows:
            all_identical = False
            break
    
    # Plot each configuration
    for idx, (policy, auth) in enumerate(configs):
        ax = axes[idx // 3, idx % 3]
        key = f"{policy}_{auth}"
        
        flows = flows_by_config[key]
        
        if not flows:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', fontsize=14)
            ax.set_title(f'{policy} - {auth}', fontweight='bold', fontsize=12)
            ax.axis('off')
            continue
        
        # Convert to DataFrame
        df_flows = pd.DataFrame([
            {'PII_Class': k[0], 'Vendor': k[1], 'Count': v}
            for k, v in flows.items()
        ])
        
        # Get top 8 PII classes and top 15 vendors for this config
        top_pii = df_flows.groupby('PII_Class')['Count'].sum().nlargest(8).index.tolist()
        top_vendors = df_flows.groupby('Vendor')['Count'].sum().nlargest(15).index.tolist()
        
        df_filtered = df_flows[
            (df_flows['PII_Class'].isin(top_pii)) & 
            (df_flows['Vendor'].isin(top_vendors))
        ]
        
        # Create simplified flow diagram
        pii_classes = sorted(df_filtered['PII_Class'].unique())
        vendors = sorted(df_filtered['Vendor'].unique())
        
        pii_y_positions = {pii: i for i, pii in enumerate(pii_classes)}
        vendor_y_positions = {vendor: i for i, vendor in enumerate(vendors)}
        
        pii_y_max = len(pii_classes) - 1 if len(pii_classes) > 1 else 1
        vendor_y_max = len(vendors) - 1 if len(vendors) > 1 else 1
        
        # Draw flows
        for _, row in df_filtered.iterrows():
            pii = row['PII_Class']
            vendor = row['Vendor']
            count = row['Count']
            
            pii_y = pii_y_positions[pii] / pii_y_max if pii_y_max > 0 else 0.5
            vendor_y = vendor_y_positions[vendor] / vendor_y_max if vendor_y_max > 0 else 0.5
            
            pii_y_plot = pii_y * 0.7 + 0.15
            vendor_y_plot = vendor_y * 0.7 + 0.15
            
            linewidth = np.log1p(count) * 1.5
            
            # Color based on PII class
            if 'IDENTITY' in pii or 'ID_SOLUTIONS' in pii:
                color = '#e74c3c'
                alpha = 0.3
            elif 'CONSENT' in pii:
                color = '#3498db'
                alpha = 0.3
            else:
                color = '#95a5a6'
                alpha = 0.2
            
            # Draw curved line
            x = np.linspace(0.25, 0.75, 50)
            y = pii_y_plot + (vendor_y_plot - pii_y_plot) * (1 - np.cos(np.pi * (x - 0.25) / 0.5)) / 2
            
            ax.plot(x, y, color=color, linewidth=linewidth, alpha=alpha, solid_capstyle='round')
        
        # Draw PII nodes (left)
        for pii, y_idx in pii_y_positions.items():
            y = (y_idx / pii_y_max if pii_y_max > 0 else 0.5) * 0.7 + 0.15
            total_flow = df_filtered[df_filtered['PII_Class'] == pii]['Count'].sum()
            node_size = np.log1p(total_flow) * 50
            
            if 'IDENTITY' in pii or 'ID_SOLUTIONS' in pii:
                node_color = '#e74c3c'
            elif 'CONSENT' in pii:
                node_color = '#3498db'
            else:
                node_color = '#95a5a6'
            
            ax.scatter(0.25, y, s=node_size, color=node_color, edgecolor='black', 
                      linewidth=1, zorder=10, alpha=0.8)
            
            label = pii.replace('_', ' ')[:15]
            ax.text(0.20, y, label, ha='right', va='center', fontsize=7)
        
        # Draw Vendor nodes (right)
        for vendor, y_idx in vendor_y_positions.items():
            y = (y_idx / vendor_y_max if vendor_y_max > 0 else 0.5) * 0.7 + 0.15
            total_flow = df_filtered[df_filtered['Vendor'] == vendor]['Count'].sum()
            node_size = np.log1p(total_flow) * 50
            
            if any(x in vendor.lower() for x in ['google', 'facebook', 'microsoft']):
                node_color = '#9b59b6'
            elif any(x in vendor.lower() for x in ['criteo', 'taboola', 'adnxs']):
                node_color = '#e67e22'
            else:
                node_color = '#34495e'
            
            ax.scatter(0.75, y, s=node_size, color=node_color, edgecolor='black', 
                      linewidth=1, zorder=10, alpha=0.8)
            
            label = vendor[:12]
            ax.text(0.80, y, label, ha='left', va='center', fontsize=6)
        
        # Title with invariance indicator
        total_flows = df_filtered['Count'].sum()
        title = f'{policy} - {auth}\n({total_flows:,} cookies)'
        
        if all_identical:
            title_color = '#e74c3c'
            ax.text(0.5, 0.05, '⚠️ IDENTICAL', ha='center', va='center',
                   fontsize=10, fontweight='bold', color='#c0392b',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='#ffe6e6', edgecolor='#e74c3c'))
        else:
            title_color = '#2c3e50'
        
        ax.set_title(title, fontweight='bold', fontsize=11, color=title_color)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
    
    # Add summary text
    if all_identical:
        summary_text = ('⚠️ CRITICAL FINDING: All policy-mode combinations show IDENTICAL PII-Vendor flows\n' +
                       'Consent policies (ALL, PARTIAL, NONE) have NO IMPACT on data sharing with third parties')
        bg_color = '#ffe6e6'
        edge_color = '#e74c3c'
    else:
        summary_text = 'PII-Vendor flows vary by consent policy and authentication mode'
        bg_color = '#e8f4f8'
        edge_color = '#3498db'
    
    fig.text(0.5, 0.02, summary_text,
             ha='center', fontsize=11, style='italic', fontweight='bold',
             bbox=dict(boxstyle='round,pad=0.8', facecolor=bg_color, 
                      edgecolor=edge_color, linewidth=2))
    
    plt.tight_layout(rect=[0, 0.05, 1, 0.96])
    plt.savefig(os.path.join(output_path, 'pii_vendor_by_policy_mode.png'), 
                bbox_inches='tight', dpi=300)
    plt.close()
    
    print("  - PII-Vendor by policy-mode diagram created")
    
    # Create comparison table
    create_policy_mode_comparison_table(flows_by_config, output_path)


def create_policy_mode_comparison_table(flows_by_config, output_path):
    """Create table comparing flows across configurations."""
    summary_path = os.path.join(output_path, '..', 'summary_tables')
    os.makedirs(summary_path, exist_ok=True)
    
    # Summary stats for each configuration
    summary_data = []
    for config, flows in flows_by_config.items():
        policy, auth = config.split('_')
        total_flows = sum(flows.values())
        num_pii_classes = len(set(k[0] for k in flows.keys()))
        num_vendors = len(set(k[1] for k in flows.keys()))
        
        summary_data.append({
            'Policy': policy,
            'Auth_Mode': auth,
            'Total_Cookies': total_flows,
            'Num_PII_Classes': num_pii_classes,
            'Num_Vendors': num_vendors
        })
    
    df_summary = pd.DataFrame(summary_data)
    df_summary.to_csv(os.path.join(summary_path, 'pii_vendor_by_policy_mode_summary.csv'), index=False)
    
    print("  - Policy-mode comparison table created")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python create_pii_vendor_by_policy_mode.py <aggregations_path>")
        sys.exit(1)
    
    agg_path = sys.argv[1]
    viz_path = os.path.join(agg_path, 'visualizations')
    os.makedirs(viz_path, exist_ok=True)
    
    create_pii_vendor_by_policy_mode(agg_path, viz_path)
    print("PII-Vendor by policy-mode diagram created!")
