#!/usr/bin/env python3
"""
Module de visualisations pour l'analyse des stockages web (localStorage, sessionStorage, IndexedDB).

Adapté des visualisations des cookies, mais sans les graphiques liés aux attributs de sécurité
(HttpOnly, Secure, SameSite) qui n'existent pas pour les autres types de stockage.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
from collections import Counter
import matplotlib.patches as mpatches

# Configuration matplotlib
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10
sns.set_palette("husl")


def plot_pii_distribution(pii_dist: Dict[str, int], output_path: Path, storage_type: str = ""):
    """
    Graphique de distribution des types de PII.
    
    Args:
        pii_dist: Distribution des types de PII
        output_path: Chemin de sortie
        storage_type: Type de stockage (pour le titre)
    """
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Trier par valeur décroissante
    sorted_items = sorted(pii_dist.items(), key=lambda x: x[1], reverse=True)
    labels = [item[0] for item in sorted_items]
    values = [item[1] for item in sorted_items]
    
    # Créer le graphique en barres
    bars = ax.barh(labels, values, color=sns.color_palette("viridis", len(labels)))
    
    # Ajouter les valeurs sur les barres
    for i, (bar, value) in enumerate(zip(bars, values)):
        ax.text(value + max(values) * 0.01, i, f'{value}', 
                va='center', fontweight='bold')
    
    title = f'Distribution des Types de PII'
    if storage_type:
        title += f' - {storage_type.upper()}'
    
    ax.set_xlabel('Nombre d\'items', fontweight='bold')
    ax.set_ylabel('Type de PII', fontweight='bold')
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_pii_by_category(pii_by_cat: Dict[str, Dict[str, int]], output_path: Path, storage_type: str = ""):
    """
    Graphique empilé des PII par catégorie principale.
    """
    fig, ax = plt.subplots(figsize=(14, 10))
    
    # Préparer les données
    categories = list(pii_by_cat.keys())
    all_pii_types = set()
    for cat_data in pii_by_cat.values():
        all_pii_types.update(cat_data.keys())
    
    pii_types = sorted(all_pii_types)
    
    # Créer la matrice de données
    data_matrix = []
    for pii_type in pii_types:
        row = [pii_by_cat[cat].get(pii_type, 0) for cat in categories]
        data_matrix.append(row)
    
    # Créer le graphique empilé
    x = np.arange(len(categories))
    bottom = np.zeros(len(categories))
    
    colors = sns.color_palette("tab20", len(pii_types))
    
    for i, (pii_type, row) in enumerate(zip(pii_types, data_matrix)):
        ax.bar(x, row, bottom=bottom, label=pii_type, color=colors[i])
        bottom += row
    
    ax.set_xlabel('Catégorie', fontweight='bold')
    ax.set_ylabel('Nombre d\'items', fontweight='bold')
    
    title = f'Distribution des PII par Catégorie'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=45, ha='right')
    ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=8)
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_persistence_distribution(persistence_dist: Dict[str, int], output_path: Path, storage_type: str = ""):
    """
    Graphique de distribution de la persistance.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    
    labels = list(persistence_dist.keys())
    values = list(persistence_dist.values())
    colors = ['#2ecc71', '#e74c3c']  # Vert pour session, rouge pour persistent
    
    wedges, texts, autotexts = ax.pie(values, labels=labels, autopct='%1.1f%%',
                                        colors=colors, startangle=90,
                                        textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    # Ajouter les valeurs absolues
    for i, (autotext, value) in enumerate(zip(autotexts, values)):
        autotext.set_text(f'{value}\n({autotext.get_text()})')
    
    title = f'Distribution de la Persistance'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_persistence_by_pii(persistence_by_pii: Dict[str, Dict[str, int]], output_path: Path, storage_type: str = ""):
    """
    Graphique de persistance par type de PII.
    """
    fig, ax = plt.subplots(figsize=(14, 10))
    
    pii_types = list(persistence_by_pii.keys())
    persistence_types = ['Session', 'Persistent']
    
    # Préparer les données
    data_matrix = []
    for persistence_type in persistence_types:
        row = [persistence_by_pii[pii].get(persistence_type, 0) for pii in pii_types]
        data_matrix.append(row)
    
    # Créer le graphique groupé
    x = np.arange(len(pii_types))
    width = 0.35
    
    colors = ['#2ecc71', '#e74c3c']
    
    for i, (persistence_type, row) in enumerate(zip(persistence_types, data_matrix)):
        offset = width * (i - 0.5)
        ax.bar(x + offset, row, width, label=persistence_type, color=colors[i])
    
    ax.set_xlabel('Type de PII', fontweight='bold')
    ax.set_ylabel('Nombre d\'items', fontweight='bold')
    
    title = f'Persistance par Type de PII'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    ax.set_xticks(x)
    ax.set_xticklabels(pii_types, rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_size_by_pii(size_by_pii: Dict[str, Dict], output_path: Path, storage_type: str = ""):
    """
    Graphique de la taille moyenne par type de PII.
    """
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Extraire les données
    pii_types = []
    avg_sizes = []
    counts = []
    
    for pii_type, data in sorted(size_by_pii.items(), key=lambda x: x[1]['average'], reverse=True):
        pii_types.append(pii_type)
        avg_sizes.append(data['average'])
        counts.append(data['count'])
    
    # Créer le graphique
    bars = ax.barh(pii_types, avg_sizes, color=sns.color_palette("rocket", len(pii_types)))
    
    # Ajouter les valeurs
    for i, (bar, avg_size, count) in enumerate(zip(bars, avg_sizes, counts)):
        ax.text(avg_size + max(avg_sizes) * 0.01, i, 
                f'{avg_size:.0f} bytes (n={count})', 
                va='center', fontsize=9)
    
    ax.set_xlabel('Taille moyenne (bytes)', fontweight='bold')
    ax.set_ylabel('Type de PII', fontweight='bold')
    
    title = f'Taille Moyenne par Type de PII'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_content_types_distribution(content_types: Dict[str, int], output_path: Path, storage_type: str = ""):
    """
    Graphique de distribution des types de contenu.
    """
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Trier par valeur
    sorted_items = sorted(content_types.items(), key=lambda x: x[1], reverse=True)
    labels = [item[0] for item in sorted_items]
    values = [item[1] for item in sorted_items]
    
    # Créer le graphique
    bars = ax.barh(labels, values, color=sns.color_palette("mako", len(labels)))
    
    # Ajouter les valeurs
    for i, (bar, value) in enumerate(zip(bars, values)):
        ax.text(value + max(values) * 0.01, i, f'{value}', 
                va='center', fontweight='bold')
    
    ax.set_xlabel('Nombre d\'items', fontweight='bold')
    ax.set_ylabel('Type de contenu', fontweight='bold')
    
    title = f'Distribution des Types de Contenu'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_top_vendors(vendor_counts: Dict[str, int], output_path: Path, storage_type: str = "", top_n: int = 15):
    """
    Graphique des principaux vendors.
    """
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Prendre les top N
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    labels = [item[0] for item in sorted_vendors]
    values = [item[1] for item in sorted_vendors]
    
    # Créer le graphique
    bars = ax.barh(labels, values, color=sns.color_palette("coolwarm", len(labels)))
    
    # Ajouter les valeurs
    for i, (bar, value) in enumerate(zip(bars, values)):
        ax.text(value + max(values) * 0.01, i, f'{value}', 
                va='center', fontweight='bold')
    
    ax.set_xlabel('Nombre d\'items', fontweight='bold')
    ax.set_ylabel('Vendor', fontweight='bold')
    
    title = f'Top {top_n} Vendors'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_entropy_distribution(entropy_by_pii: Dict[str, List[float]], output_path: Path, storage_type: str = ""):
    """
    Graphique de distribution de l'entropie par type de PII.
    """
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Préparer les données pour le boxplot
    pii_types = []
    entropy_data = []
    
    for pii_type, entropies in sorted(entropy_by_pii.items(), 
                                      key=lambda x: np.median(x[1]) if x[1] else 0, 
                                      reverse=True):
        if entropies:
            pii_types.append(pii_type)
            entropy_data.append(entropies)
    
    # Créer le boxplot
    bp = ax.boxplot(entropy_data, labels=pii_types, patch_artist=True,
                    showmeans=True, meanline=True)
    
    # Colorier les boîtes
    colors = sns.color_palette("viridis", len(pii_types))
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    ax.set_xlabel('Type de PII', fontweight='bold')
    ax.set_ylabel('Entropie (bits)', fontweight='bold')
    
    title = f'Distribution de l\'Entropie par Type de PII'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    plt.xticks(rotation=45, ha='right')
    ax.grid(axis='y', alpha=0.3)
    
    # Ajouter une ligne de référence pour haute entropie
    ax.axhline(y=4.0, color='r', linestyle='--', alpha=0.5, label='Seuil haute entropie')
    ax.legend()
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_risk_matrix(risk_levels: Dict[str, int], risk_by_pii: Dict[str, Dict[str, int]], 
                     output_path: Path, storage_type: str = ""):
    """
    Matrice de risques RGPD.
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Graphique 1: Distribution globale des risques
    risk_order = ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk']
    risk_colors = ['#2ecc71', '#f39c12', '#e67e22', '#e74c3c']
    
    values = [risk_levels.get(risk, 0) for risk in risk_order]
    
    wedges, texts, autotexts = ax1.pie(values, labels=risk_order, autopct='%1.1f%%',
                                         colors=risk_colors, startangle=90,
                                         textprops={'fontsize': 10, 'fontweight': 'bold'})
    
    for autotext, value in zip(autotexts, values):
        autotext.set_text(f'{value}\n({autotext.get_text()})')
    
    title1 = f'Distribution des Niveaux de Risque RGPD'
    if storage_type:
        title1 += f'\n{storage_type.upper()}'
    ax1.set_title(title1, fontsize=12, fontweight='bold', pad=20)
    
    # Graphique 2: Risques par type de PII (heatmap)
    pii_types = list(risk_by_pii.keys())
    
    # Créer la matrice
    matrix = []
    for pii_type in pii_types:
        row = [risk_by_pii[pii_type].get(risk, 0) for risk in risk_order]
        matrix.append(row)
    
    im = ax2.imshow(matrix, cmap='YlOrRd', aspect='auto')
    
    # Configurer les axes
    ax2.set_xticks(np.arange(len(risk_order)))
    ax2.set_yticks(np.arange(len(pii_types)))
    ax2.set_xticklabels(risk_order, rotation=45, ha='right')
    ax2.set_yticklabels(pii_types)
    
    # Ajouter les valeurs dans les cellules
    for i in range(len(pii_types)):
        for j in range(len(risk_order)):
            text = ax2.text(j, i, matrix[i][j],
                           ha="center", va="center", color="black", fontsize=8)
    
    ax2.set_title('Risques par Type de PII', fontsize=12, fontweight='bold', pad=20)
    
    # Colorbar
    cbar = plt.colorbar(im, ax=ax2)
    cbar.set_label('Nombre d\'items', rotation=270, labelpad=20)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def generate_all_visualizations(analysis_results: Dict, output_dir: Path, storage_type: str = ""):
    """
    Génère tous les graphiques pour l'analyse des stockages.
    
    Args:
        analysis_results: Résultats de l'analyse
        output_dir: Répertoire de sortie
        storage_type: Type de stockage (pour les titres)
    """
    graphs_dir = output_dir / 'consolidated' / 'graphs'
    graphs_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"📊 Génération des graphiques pour {storage_type.upper()}...\n")
    
    # 1. Distribution des PII
    plot_pii_distribution(
        analysis_results['pii_distribution'],
        graphs_dir / '01_pii_distribution.png',
        storage_type
    )
    
    # 2. PII par catégorie
    plot_pii_by_category(
        analysis_results['pii_by_category'],
        graphs_dir / '02_pii_by_category.png',
        storage_type
    )
    
    # 3. Distribution de la persistance
    plot_persistence_distribution(
        analysis_results['persistence_distribution'],
        graphs_dir / '03_persistence_distribution.png',
        storage_type
    )
    
    # 4. Persistance par PII
    plot_persistence_by_pii(
        analysis_results['persistence_by_pii'],
        graphs_dir / '04_persistence_by_pii.png',
        storage_type
    )
    
    # 5. Taille par PII
    plot_size_by_pii(
        analysis_results['size_by_pii'],
        graphs_dir / '05_size_by_pii.png',
        storage_type
    )
    
    # 6. Types de contenu
    plot_content_types_distribution(
        analysis_results['content_types'],
        graphs_dir / '06_content_types.png',
        storage_type
    )
    
    # 7. Top vendors
    plot_top_vendors(
        analysis_results['vendor_counts'],
        graphs_dir / '07_top_vendors.png',
        storage_type
    )
    
    # 8. Distribution de l'entropie
    plot_entropy_distribution(
        analysis_results['entropy_by_pii'],
        graphs_dir / '08_entropy_distribution.png',
        storage_type
    )
    
    # 9. Matrice de risques
    plot_risk_matrix(
        analysis_results['risk_levels'],
        analysis_results['risk_by_pii'],
        graphs_dir / '09_risk_matrix.png',
        storage_type
    )
    
    print(f"✅ 9 graphiques générés dans {graphs_dir}\n")
