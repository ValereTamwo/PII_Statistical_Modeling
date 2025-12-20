#!/usr/bin/env python3
"""
Module de visualisations pour l'analyse de cycle de vie des stockages web.

Adapté des visualisations de cycle de vie des cookies, sans les métriques de sécurité.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from typing import Dict, List
from collections import Counter
import matplotlib.patches as mpatches

# Configuration matplotlib
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10
sns.set_palette("husl")


def plot_lifecycle_overview(timelines: Dict, output_path: Path, storage_type: str = ""):
    """
    Vue d'ensemble du cycle de vie des items.
    """
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    
    # 1. Distribution des événements
    event_counts = Counter()
    for timeline in timelines.values():
        for event in timeline['events']:
            event_counts[event['type']] += 1
    
    event_types = list(event_counts.keys())
    event_values = list(event_counts.values())
    colors = {'added': '#2ecc71', 'modified': '#f39c12', 'deleted': '#e74c3c'}
    event_colors = [colors.get(et, '#95a5a6') for et in event_types]
    
    ax1.bar(event_types, event_values, color=event_colors)
    ax1.set_ylabel('Nombre d\'événements', fontweight='bold')
    ax1.set_title('Distribution des Événements', fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    
    for i, (et, ev) in enumerate(zip(event_types, event_values)):
        ax1.text(i, ev + max(event_values) * 0.01, f'{ev}', 
                ha='center', fontweight='bold')
    
    # 2. Distribution des modifications
    mod_counts = [t['num_modifications'] for t in timelines.values()]
    ax2.hist(mod_counts, bins=20, color='#3498db', edgecolor='black')
    ax2.set_xlabel('Nombre de modifications', fontweight='bold')
    ax2.set_ylabel('Nombre d\'items', fontweight='bold')
    ax2.set_title('Distribution des Modifications', fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    
    # 3. Volatilité
    volatility = Counter()
    for timeline in timelines.values():
        num_changes = timeline['num_modifications'] + timeline['num_deletions']
        if num_changes == 0:
            volatility['Stable'] += 1
        elif num_changes <= 2:
            volatility['Modéré'] += 1
        else:
            volatility['Élevé'] += 1
    
    vol_labels = list(volatility.keys())
    vol_values = list(volatility.values())
    vol_colors = ['#2ecc71', '#f39c12', '#e74c3c']
    
    wedges, texts, autotexts = ax3.pie(vol_values, labels=vol_labels, autopct='%1.1f%%',
                                         colors=vol_colors, startangle=90,
                                         textprops={'fontsize': 10, 'fontweight': 'bold'})
    
    for autotext, value in zip(autotexts, vol_values):
        autotext.set_text(f'{value}\n({autotext.get_text()})')
    
    ax3.set_title('Volatilité des Items', fontweight='bold')
    
    # 4. Évolution de l'entropie
    entropy_changes = []
    for timeline in timelines.values():
        if len(timeline['entropy_evolution']) > 1:
            change = timeline['entropy_evolution'][-1] - timeline['entropy_evolution'][0]
            entropy_changes.append(change)
    
    if entropy_changes:
        ax4.hist(entropy_changes, bins=30, color='#9b59b6', edgecolor='black')
        ax4.axvline(x=0, color='red', linestyle='--', linewidth=2, label='Aucun changement')
        ax4.set_xlabel('Changement d\'entropie (bits)', fontweight='bold')
        ax4.set_ylabel('Nombre d\'items', fontweight='bold')
        ax4.set_title('Distribution des Changements d\'Entropie', fontweight='bold')
        ax4.legend()
        ax4.grid(axis='y', alpha=0.3)
    
    title = f'Vue d\'Ensemble du Cycle de Vie'
    if storage_type:
        title += f' - {storage_type.upper()}'
    fig.suptitle(title, fontsize=16, fontweight='bold', y=0.995)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_entropy_evolution(timelines: Dict, output_path: Path, storage_type: str = "", top_n: int = 20):
    """
    Évolution de l'entropie pour les items les plus modifiés.
    """
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Sélectionner les top N items par nombre de modifications
    sorted_timelines = sorted(
        timelines.values(),
        key=lambda x: x['num_modifications'],
        reverse=True
    )[:top_n]
    
    # Tracer l'évolution
    colors = sns.color_palette("viridis", len(sorted_timelines))
    
    for i, timeline in enumerate(sorted_timelines):
        if len(timeline['entropy_evolution']) > 1:
            x = list(range(len(timeline['entropy_evolution'])))
            y = timeline['entropy_evolution']
            
            # Simplifier la clé pour l'affichage
            key_parts = timeline['key'].split('|')
            label = key_parts[0][:30] if len(key_parts[0]) > 30 else key_parts[0]
            
            ax.plot(x, y, marker='o', label=label, color=colors[i], linewidth=2)
    
    ax.set_xlabel('Événement', fontweight='bold')
    ax.set_ylabel('Entropie (bits)', fontweight='bold')
    
    title = f'Évolution de l\'Entropie (Top {top_n} Items Modifiés)'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    ax.axhline(y=4.0, color='r', linestyle='--', alpha=0.5, label='Seuil haute entropie')
    ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=8)
    ax.grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_size_evolution(timelines: Dict, output_path: Path, storage_type: str = "", top_n: int = 20):
    """
    Évolution de la taille pour les items les plus modifiés.
    """
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Sélectionner les top N items par nombre de modifications
    sorted_timelines = sorted(
        timelines.values(),
        key=lambda x: x['num_modifications'],
        reverse=True
    )[:top_n]
    
    # Tracer l'évolution
    colors = sns.color_palette("rocket", len(sorted_timelines))
    
    for i, timeline in enumerate(sorted_timelines):
        if len(timeline['size_evolution']) > 1:
            x = list(range(len(timeline['size_evolution'])))
            y = timeline['size_evolution']
            
            # Simplifier la clé
            key_parts = timeline['key'].split('|')
            label = key_parts[0][:30] if len(key_parts[0]) > 30 else key_parts[0]
            
            ax.plot(x, y, marker='s', label=label, color=colors[i], linewidth=2)
    
    ax.set_xlabel('Événement', fontweight='bold')
    ax.set_ylabel('Taille (bytes)', fontweight='bold')
    
    title = f'Évolution de la Taille (Top {top_n} Items Modifiés)'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=8)
    ax.grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_pii_transition_matrix(timelines: Dict, output_path: Path, storage_type: str = ""):
    """
    Matrice des transitions entre catégories PII.
    """
    # Collecter les transitions
    transitions = Counter()
    all_categories = set()
    
    for timeline in timelines.values():
        if len(timeline['pii_categories']) > 1:
            initial = timeline['pii_categories'][0]
            final = timeline['pii_categories'][-1]
            
            # Simplifier les noms de catégories
            initial_short = initial.split('::')[0] if '::' in initial else initial
            final_short = final.split('::')[0] if '::' in final else final
            
            all_categories.add(initial_short)
            all_categories.add(final_short)
            
            if initial_short != final_short:
                transitions[(initial_short, final_short)] += 1
    
    if not transitions:
        # Pas de transitions, créer un graphique vide avec message
        fig, ax = plt.subplots(figsize=(10, 8))
        ax.text(0.5, 0.5, 'Aucune transition PII détectée', 
                ha='center', va='center', fontsize=14)
        ax.axis('off')
        
        title = f'Matrice de Transition PII'
        if storage_type:
            title += f' - {storage_type.upper()}'
        ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        return
    
    # Créer la matrice
    categories = sorted(all_categories)
    matrix = np.zeros((len(categories), len(categories)))
    
    for (from_cat, to_cat), count in transitions.items():
        i = categories.index(from_cat)
        j = categories.index(to_cat)
        matrix[i][j] = count
    
    # Créer le graphique
    fig, ax = plt.subplots(figsize=(12, 10))
    
    im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto')
    
    # Configurer les axes
    ax.set_xticks(np.arange(len(categories)))
    ax.set_yticks(np.arange(len(categories)))
    ax.set_xticklabels(categories, rotation=45, ha='right')
    ax.set_yticklabels(categories)
    
    # Ajouter les valeurs
    for i in range(len(categories)):
        for j in range(len(categories)):
            if matrix[i][j] > 0:
                text = ax.text(j, i, int(matrix[i][j]),
                             ha="center", va="center", color="black", fontsize=10)
    
    ax.set_xlabel('Catégorie Finale', fontweight='bold')
    ax.set_ylabel('Catégorie Initiale', fontweight='bold')
    
    title = f'Matrice de Transition PII'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    # Colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Nombre de transitions', rotation=270, labelpad=20)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_activity_heatmap(timelines: Dict, output_path: Path, storage_type: str = "", top_n: int = 30):
    """
    Heatmap de l'activité des items.
    """
    # Sélectionner les top N items par activité totale
    sorted_timelines = sorted(
        timelines.values(),
        key=lambda x: len(x['events']),
        reverse=True
    )[:top_n]
    
    if not sorted_timelines:
        fig, ax = plt.subplots(figsize=(10, 8))
        ax.text(0.5, 0.5, 'Aucune activité détectée', 
                ha='center', va='center', fontsize=14)
        ax.axis('off')
        
        title = f'Heatmap d\'Activité'
        if storage_type:
            title += f' - {storage_type.upper()}'
        ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        return
    
    # Créer la matrice d'activité
    max_events = max(len(t['events']) for t in sorted_timelines)
    matrix = np.zeros((len(sorted_timelines), max_events))
    
    labels = []
    for i, timeline in enumerate(sorted_timelines):
        # Simplifier la clé
        key_parts = timeline['key'].split('|')
        label = key_parts[0][:40] if len(key_parts[0]) > 40 else key_parts[0]
        labels.append(label)
        
        # Remplir la matrice (1 = événement)
        for j in range(len(timeline['events'])):
            event_type = timeline['events'][j]['type']
            if event_type == 'added':
                matrix[i][j] = 1
            elif event_type == 'modified':
                matrix[i][j] = 2
            elif event_type == 'deleted':
                matrix[i][j] = 3
    
    # Créer le graphique
    fig, ax = plt.subplots(figsize=(14, max(8, len(sorted_timelines) * 0.3)))
    
    # Colormap personnalisée
    from matplotlib.colors import ListedColormap
    colors = ['white', '#2ecc71', '#f39c12', '#e74c3c']  # 0=vide, 1=added, 2=modified, 3=deleted
    cmap = ListedColormap(colors)
    
    im = ax.imshow(matrix, cmap=cmap, aspect='auto', vmin=0, vmax=3)
    
    # Configurer les axes
    ax.set_yticks(np.arange(len(labels)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel('Événement #', fontweight='bold')
    ax.set_ylabel('Item', fontweight='bold')
    
    title = f'Heatmap d\'Activité (Top {top_n} Items)'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    # Légende
    legend_elements = [
        mpatches.Patch(color='#2ecc71', label='Added'),
        mpatches.Patch(color='#f39c12', label='Modified'),
        mpatches.Patch(color='#e74c3c', label='Deleted')
    ]
    ax.legend(handles=legend_elements, loc='upper right')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def generate_lifecycle_visualizations(results: Dict, output_dir: Path, storage_type: str = ""):
    """
    Génère tous les graphiques de cycle de vie.
    """
    print(f"📊 Génération des graphiques de cycle de vie...\n")
    
    timelines = results['timelines']
    
    # 1. Vue d'ensemble
    plot_lifecycle_overview(
        timelines,
        output_dir / '01_lifecycle_overview.png',
        storage_type
    )
    print("    Graphique 1: Vue d'ensemble")
    
    # 2. Évolution de l'entropie
    plot_entropy_evolution(
        timelines,
        output_dir / '02_entropy_evolution.png',
        storage_type
    )
    print("    Graphique 2: Évolution de l'entropie")
    
    # 3. Évolution de la taille
    plot_size_evolution(
        timelines,
        output_dir / '03_size_evolution.png',
        storage_type
    )
    print("    Graphique 3: Évolution de la taille")
    
    # 4. Matrice de transition PII
    plot_pii_transition_matrix(
        timelines,
        output_dir / '04_pii_transition_matrix.png',
        storage_type
    )
    print("   Graphique 4: Matrice de transition PII")
    
    # 5. Heatmap d'activité (version originale)
    plot_activity_heatmap(
        timelines,
        output_dir / '05_activity_heatmap.png',
        storage_type
    )
    print("    Graphique 5: Heatmap d'activité")
    
    # 6. Heatmap temporelle (NOUVEAU - avec task_ids)
    try:
        from analysis.storage_analysis import temporal_heatmap as th
        th.plot_temporal_activity_heatmap(
            timelines,
            output_dir / '06_temporal_activity_heatmap.png',
            storage_type
        )
        print("    Graphique 6: Heatmap temporelle (task_ids)")
        
        th.plot_temporal_activity_detailed(
            timelines,
            output_dir / '07_temporal_timeline_detailed.png',
            storage_type
        )
        print("    Graphique 7: Timeline détaillée")
        
        print(f"\n✅ 7 graphiques de cycle de vie générés dans {output_dir}\n")
    except Exception as e:
        print(f"   ⚠️  Heatmap temporelle non générée: {e}")
        print(f"\n 5 graphiques de cycle de vie générés dans {output_dir}\n")
