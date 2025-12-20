#!/usr/bin/env python3
"""
Module de visualisations avancées pour l'analyse vie privée.
Utilise Plotly pour les graphiques interactifs et Matplotlib pour les scatter plots.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
from pathlib import Path

# Configuration
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)


def plot_content_sunburst(content_hierarchy: Dict, output_path: Path):
    """
    Graphique 17: Sunburst - Hiérarchie des types de contenu décodé.
    
    Args:
        content_hierarchy: {data_type: {subcategory: count}}
        output_path: Chemin de sortie
    """
    # Préparer les données pour Plotly Sunburst
    labels = ['All Cookies']
    parents = ['']
    values = [0]
    colors = []
    
    # Couleurs par type de données
    color_map = {
        'uuid': '#e74c3c',  # Rouge - Identifiant unique
        'uuid_compact': '#e74c3c',
        'token_id': '#e67e22',  # Orange - Token
        'email': '#c0392b',  # Rouge foncé - Email
        'ip_address': '#d35400',  # Orange foncé
        'json_structured': '#f39c12',  # Jaune - Données structurées
        'timestamp': '#3498db',  # Bleu - Technique
        'boolean': '#2ecc71',  # Vert - Simple
        'number': '#27ae60',
        'language_code': '#16a085',
        'short_text': '#1abc9c',
        'complex_string': '#95a5a6',  # Gris
        'empty': '#ecf0f1'
    }
    
    total = 0
    for data_type, subcats in content_hierarchy.items():
        type_total = sum(subcats.values())
        total += type_total
        
        # Ajouter le type de données
        labels.append(data_type)
        parents.append('All Cookies')
        values.append(type_total)
        colors.append(color_map.get(data_type, '#95a5a6'))
        
        # Ajouter les sous-catégories
        for subcat, count in subcats.items():
            labels.append(f"{subcat}")
            parents.append(data_type)
            values.append(count)
            colors.append(color_map.get(data_type, '#95a5a6'))
    
    values[0] = total  # Total pour la racine
    
    # Créer le Sunburst
    fig = go.Figure(go.Sunburst(
        labels=labels,
        parents=parents,
        values=values,
        marker=dict(colors=colors),
        branchvalues="total",
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br><extra></extra>'
    ))
    
    fig.update_layout(
        title='Content Type Hierarchy (Decoded Values)',
        font=dict(size=12, family='Arial'),
        width=900,
        height=900
    )
    
    # Sauvegarder en HTML (pas besoin de kaleido)
    fig.write_html(str(output_path).replace('.png', '.html'))
    
    # Aussi sauvegarder en PNG si possible
    try:
        fig.write_image(str(output_path), width=900, height=900, scale=2)
    except:
        pass  # Ignorer si kaleido ne fonctionne pas


def plot_content_types_distribution(content_types: Dict[str, int], output_path: Path):
    """
    Graphique 18: Distribution des types de données détectées.
    
    Args:
        content_types: {data_type: count}
        output_path: Chemin de sortie
    """
    # Trier par count décroissant
    sorted_types = sorted(content_types.items(), key=lambda x: x[1], reverse=True)
    types = [item[0] for item in sorted_types]
    counts = [item[1] for item in sorted_types]
    
    # Couleurs selon le risque
    risk_colors = {
        'uuid': '#e74c3c',
        'uuid_compact': '#e74c3c',
        'token_id': '#e67e22',
        'email': '#c0392b',
        'ip_address': '#d35400',
        'json_structured': '#f39c12',
        'timestamp': '#3498db',
        'boolean': '#2ecc71',
        'number': '#27ae60',
        'language_code': '#16a085',
        'short_text': '#1abc9c',
        'complex_string': '#95a5a6',
        'empty': '#ecf0f1'
    }
    
    colors = [risk_colors.get(t, '#95a5a6') for t in types]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    bars = ax.barh(types, counts, color=colors, edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bar in bars:
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f'{int(width)}', ha='left', va='center', fontweight='bold', fontsize=10)
    
    ax.set_xlabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_ylabel('Data Type (Decoded)', fontsize=12, fontweight='bold')
    ax.set_title('Distribution of Detected Data Types', fontsize=14, fontweight='bold', pad=20)
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_vendor_sankey(category_vendor_flows: List[Tuple[str, str, int]], output_path: Path):
    """
    Graphique 19: Sankey - Flux de données Catégorie → Vendor.
    Version améliorée : limite aux top 15 vendors + regroupe les autres.
    
    Args:
        category_vendor_flows: [(category, vendor, count), ...]
        output_path: Chemin de sortie
    """
    # Calculer le total par vendor
    vendor_totals = defaultdict(int)
    for cat, vendor, count in category_vendor_flows:
        vendor_totals[vendor] += count
    
    # Sélectionner les top 15 vendors
    top_vendors = sorted(vendor_totals.items(), key=lambda x: x[1], reverse=True)[:15]
    top_vendor_names = {vendor for vendor, _ in top_vendors}
    
    # Regrouper les flux
    categories = set()
    aggregated_flows = defaultdict(int)
    
    for cat, vendor, count in category_vendor_flows:
        categories.add(cat)
        
        # Si vendor dans le top 15, garder tel quel
        if vendor in top_vendor_names:
            aggregated_flows[(cat, vendor)] += count
        else:
            # Sinon, regrouper dans "Autres"
            aggregated_flows[(cat, 'Autres vendors')] += count
    
    # Créer les listes de nœuds
    vendors = list(top_vendor_names) + ['Autres vendors']
    all_nodes = list(categories) + vendors
    node_dict = {node: idx for idx, node in enumerate(all_nodes)}
    
    # Créer les liens
    sources = []
    targets = []
    values = []
    
    for (cat, vendor), count in aggregated_flows.items():
        sources.append(node_dict[cat])
        targets.append(node_dict[vendor])
        values.append(count)
    
    # Couleurs
    node_colors = ['#3498db'] * len(categories) + ['#e74c3c'] * (len(vendors) - 1) + ['#95a5a6']  # Gris pour "Autres"
    
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=20,
            thickness=25,
            line=dict(color="black", width=0.5),
            label=all_nodes,
            color=node_colors
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values,
            color='rgba(231, 76, 60, 0.2)'
        )
    )])
    
    fig.update_layout(
        title='Data Flow: PII Category → Third-Party Vendor (Top 15 + Autres)',
        font=dict(size=13, family='Arial'),
        width=1400,
        height=900
    )
    
    # Sauvegarder en HTML
    fig.write_html(str(output_path).replace('.png', '.html'))
    
    # Aussi sauvegarder en PNG si possible
    try:
        fig.write_image(str(output_path), width=1400, height=900, scale=2)
    except:
        pass


def plot_top_vendors(vendor_counts: Dict[str, int], output_path: Path, top_n: int = 15):
    """
    Graphique 20: Top vendors recevant des PII.
    
    Args:
        vendor_counts: {vendor: count}
        output_path: Chemin de sortie
        top_n: Nombre de vendors à afficher
    """
    # Trier et prendre le top N
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    vendors = [item[0] for item in sorted_vendors]
    counts = [item[1] for item in sorted_vendors]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    colors = plt.cm.Reds(np.linspace(0.4, 0.9, len(vendors)))
    bars = ax.barh(vendors, counts, color=colors, edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bar in bars:
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f'{int(width)}', ha='left', va='center', fontweight='bold', fontsize=10)
    
    ax.set_xlabel('Number of PII Cookies', fontsize=12, fontweight='bold')
    ax.set_ylabel('Third-Party Vendor', fontsize=12, fontweight='bold')
    ax.set_title(f'Top {top_n} Vendors Receiving PII Data', fontsize=14, fontweight='bold', pad=20)
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_entropy_scatter(entropy_lifetime_data: List[Tuple[float, float, str]], output_path: Path):
    """
    Graphique 21: Scatter plot - Entropie × Durée de vie.
    
    Args:
        entropy_lifetime_data: [(entropy, lifetime_days, data_type), ...]
        output_path: Chemin de sortie
    """
    entropies = [item[0] for item in entropy_lifetime_data]
    lifetimes = [item[1] for item in entropy_lifetime_data]
    data_types = [item[2] for item in entropy_lifetime_data]
    
    # Couleurs par type de données
    type_colors = {
        'uuid': '#e74c3c',
        'uuid_compact': '#e74c3c',
        'token_id': '#e67e22',
        'email': '#c0392b',
        'ip_address': '#d35400',
        'json_structured': '#f39c12',
        'timestamp': '#3498db',
        'boolean': '#2ecc71',
        'number': '#27ae60',
        'language_code': '#16a085',
        'short_text': '#1abc9c',
        'complex_string': '#95a5a6'
    }
    
    colors = [type_colors.get(dt, '#95a5a6') for dt in data_types]
    
    fig, ax = plt.subplots(figsize=(14, 10))
    scatter = ax.scatter(lifetimes, entropies, c=colors, alpha=0.6, s=50, edgecolors='black', linewidth=0.5)
    
    # Zone critique (coin haut-droit)
    ax.axhline(y=4.0, color='red', linestyle='--', alpha=0.3, linewidth=2, label='High Entropy Threshold')
    ax.axvline(x=365, color='red', linestyle='--', alpha=0.3, linewidth=2, label='1 Year Threshold')
    
    # Annoter la zone critique
    ax.text(400, 6.5, 'CRITICAL ZONE\n(Super Trackers)', 
            bbox=dict(boxstyle='round', facecolor='red', alpha=0.2),
            fontsize=12, fontweight='bold', color='darkred')
    
    ax.set_xlabel('Cookie Lifetime (days)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Entropy (bits)', fontsize=12, fontweight='bold')
    ax.set_title('Tracking Potential: Entropy × Lifetime\n(High Entropy + Long Lifetime = Super Tracker)', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='upper left')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_entropy_distribution(entropy_by_subcat: Dict[str, List[float]], output_path: Path):
    """
    Graphique 22: Distribution de l'entropie par sous-catégorie PII.
    
    Args:
        entropy_by_subcat: {subcategory: [entropies]}
        output_path: Chemin de sortie
    """
    # Calculer la moyenne d'entropie par sous-catégorie
    avg_entropies = {}
    for subcat, entropies in entropy_by_subcat.items():
        if entropies:
            avg_entropies[subcat] = np.mean(entropies)
    
    # Trier par entropie moyenne décroissante
    sorted_subcats = sorted(avg_entropies.items(), key=lambda x: x[1], reverse=True)[:15]
    subcats = [item[0] for item in sorted_subcats]
    avgs = [item[1] for item in sorted_subcats]
    
    # Couleurs selon le niveau d'entropie
    colors = ['#c0392b' if e > 5.5 else '#e74c3c' if e > 4.0 else '#f39c12' if e > 2.5 else '#2ecc71' 
              for e in avgs]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    bars = ax.barh(subcats, avgs, color=colors, edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bar in bars:
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f'{width:.2f}', ha='left', va='center', fontweight='bold', fontsize=9)
    
    # Lignes de seuil
    ax.axvline(x=4.0, color='red', linestyle='--', alpha=0.5, linewidth=1.5, label='High Entropy (4.0)')
    ax.axvline(x=2.5, color='orange', linestyle='--', alpha=0.5, linewidth=1.5, label='Medium Entropy (2.5)')
    
    ax.set_xlabel('Average Entropy (bits)', fontsize=12, fontweight='bold')
    ax.set_ylabel('PII Subcategory', fontsize=12, fontweight='bold')
    ax.set_title('Average Entropy by PII Type\n(Higher = More Unique/Trackable)', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='lower right')
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
