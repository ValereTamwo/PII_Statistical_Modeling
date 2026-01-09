#!/usr/bin/env python3
"""
Visualisation temporelle enrichie de la heatmap d'activité.
Utilise les task_ids pour montrer l'évolution chronologique réelle.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from typing import Dict
import matplotlib.patches as mpatches
from matplotlib.colors import ListedColormap

plt.rcParams['figure.figsize'] = (16, 10)
plt.rcParams['font.size'] = 10


def plot_temporal_activity_heatmap(timelines: Dict, output_path: Path, 
                                   storage_type: str = "", top_n: int = 30):
    """
    Heatmap d'activité avec task_ids réels sur l'axe X.
    
    Montre QUAND (task_id) chaque item a été modifié, permettant de voir:
    - Les items qui changent fréquemment
    - Les périodes d'activité intense
    - Les patterns de modification cross-site
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
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        return
    
    # Trouver la plage de task_ids
    all_task_ids = []
    for timeline in sorted_timelines:
        all_task_ids.extend(timeline.get('task_ids', []))
    
    if not all_task_ids:
        print("⚠️  Aucun task_id trouvé, utilisation de la version simple")
        return
    
    min_task_id = min(all_task_ids)
    max_task_id = max(all_task_ids)
    task_id_range = max_task_id - min_task_id + 1
    
    # Créer la matrice d'activité (items x task_ids)
    matrix = np.zeros((len(sorted_timelines), task_id_range))
    
    labels = []
    pii_categories = []
    
    for i, timeline in enumerate(sorted_timelines):
        # Simplifier la clé
        key_parts = timeline['key'].split('|')
        label = key_parts[0][:40] if len(key_parts[0]) > 40 else key_parts[0]
        labels.append(label)
        
        # Catégorie PII (pour annotation)
        pii_cat = timeline['pii_categories'][-1] if timeline['pii_categories'] else 'unknown'
        pii_categories.append(pii_cat.split('::')[0])  # Simplifier
        
        # Remplir la matrice selon les task_ids
        for event in timeline['events']:
            task_id = event.get('task_id', 0)
            if task_id > 0:
                col_idx = task_id - min_task_id
                event_type = event['type']
                
                if event_type == 'added':
                    matrix[i][col_idx] = 1
                elif event_type == 'modified':
                    matrix[i][col_idx] = 2
                elif event_type == 'deleted':
                    matrix[i][col_idx] = 3
    
    # Créer le graphique
    fig, ax = plt.subplots(figsize=(18, max(10, len(sorted_timelines) * 0.4)))
    
    # Colormap personnalisée
    colors = ['white', '#2ecc71', '#f39c12', '#e74c3c']  # 0=vide, 1=added, 2=modified, 3=deleted
    cmap = ListedColormap(colors)
    
    im = ax.imshow(matrix, cmap=cmap, aspect='auto', vmin=0, vmax=3, interpolation='nearest')
    
    # Configurer l'axe Y (items)
    ax.set_yticks(np.arange(len(labels)))
    
    # Créer des labels avec catégorie PII
    y_labels = [f"{label} ({pii})" for label, pii in zip(labels, pii_categories)]
    ax.set_yticklabels(y_labels, fontsize=9)
    
    # Configurer l'axe X (task_ids)
    # Afficher seulement quelques task_ids pour lisibilité
    num_ticks = min(20, task_id_range)
    tick_positions = np.linspace(0, task_id_range - 1, num_ticks, dtype=int)
    tick_labels = [str(min_task_id + pos) for pos in tick_positions]
    
    ax.set_xticks(tick_positions)
    ax.set_xticklabels(tick_labels, rotation=45, ha='right')
    ax.set_xlabel('Task ID (Événement de Navigation)', fontweight='bold', fontsize=12)
    ax.set_ylabel('Item (Catégorie PII)', fontweight='bold', fontsize=12)
    
    # Titre
    title = f'Heatmap d\\Activité Temporelle (Top {top_n} Items)\\n'
    title += f'Task IDs: {min_task_id} → {max_task_id} ({task_id_range} événements)'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    # Légende
    legend_elements = [
        mpatches.Patch(color='#2ecc71', label='Added'),
        mpatches.Patch(color='#f39c12', label='Modified'),
        mpatches.Patch(color='#e74c3c', label='Deleted')
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=10)
    
    # Grille pour meilleure lisibilité
    ax.set_xticks(np.arange(task_id_range) - 0.5, minor=True)
    ax.set_yticks(np.arange(len(labels)) - 0.5, minor=True)
    ax.grid(which='minor', color='gray', linestyle='-', linewidth=0.1, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Heatmap temporelle générée: {output_path}")
    print(f"   Plage task_id: {min_task_id} → {max_task_id}")
    print(f"   Items affichés: {len(sorted_timelines)}")


def plot_temporal_activity_detailed(timelines: Dict, output_path: Path, 
                                    storage_type: str = "", top_n: int = 15):
    """
    Version détaillée avec annotations des URLs et catégories PII.
    """
    # Sélectionner les top N items
    sorted_timelines = sorted(
        timelines.values(),
        key=lambda x: x['num_modifications'],
        reverse=True
    )[:top_n]
    
    if not sorted_timelines:
        return
    
    fig, ax = plt.subplots(figsize=(20, max(8, top_n * 0.6)))
    
    # Trouver la plage de task_ids
    all_task_ids = []
    for timeline in sorted_timelines:
        all_task_ids.extend(timeline.get('task_ids', []))
    
    if not all_task_ids:
        return
    
    min_task_id = min(all_task_ids)
    max_task_id = max(all_task_ids)
    
    # Tracer chaque item
    colors = {'added': '#2ecc71', 'modified': '#f39c12', 'deleted': '#e74c3c'}
    
    for i, timeline in enumerate(sorted_timelines):
        key_parts = timeline['key'].split('|')
        label = key_parts[0][:35] if len(key_parts[0]) > 35 else key_parts[0]
        
        # Tracer les événements
        for event in timeline['events']:
            task_id = event.get('task_id', 0)
            if task_id > 0:
                event_type = event['type']
                color = colors.get(event_type, 'gray')
                
                # Marker différent selon le type
                marker = 'o' if event_type == 'added' else ('s' if event_type == 'modified' else 'x')
                size = 100 if event_type == 'modified' else 60
                
                ax.scatter(task_id, i, c=color, marker=marker, s=size, 
                          alpha=0.7, edgecolors='black', linewidths=0.5)
        
        # Label avec catégorie PII
        pii_cat = timeline['pii_categories'][-1] if timeline['pii_categories'] else 'unknown'
        pii_short = pii_cat.split('::')[0]
        ax.text(min_task_id - (max_task_id - min_task_id) * 0.02, i, 
               f"{label} ({pii_short})", 
               ha='right', va='center', fontsize=9)
    
    ax.set_xlim(min_task_id - (max_task_id - min_task_id) * 0.15, max_task_id + 10)
    ax.set_ylim(-0.5, len(sorted_timelines) - 0.5)
    
    ax.set_xlabel('Task ID (Événement de Navigation)', fontweight='bold', fontsize=12)
    ax.set_ylabel('Item', fontweight='bold', fontsize=12)
    ax.set_yticks([])
    
    title = f'Timeline Détaillée des Modifications (Top {top_n})\\n'
    title += f'Task IDs: {min_task_id} → {max_task_id}'
    if storage_type:
        title += f' - {storage_type.upper()}'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    
    # Légende
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#2ecc71', 
                   markersize=10, label='Added', markeredgecolor='black'),
        plt.Line2D([0], [0], marker='s', color='w', markerfacecolor='#f39c12', 
                   markersize=10, label='Modified', markeredgecolor='black'),
        plt.Line2D([0], [0], marker='x', color='w', markerfacecolor='#e74c3c', 
                   markersize=10, label='Deleted', markeredgecolor='black')
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=10)
    
    ax.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Timeline détaillée générée: {output_path}")


if __name__ == '__main__':
    # Test avec les données existantes
    import json
    from pathlib import Path
    
    lifecycle_file = Path('/home/franck/Documents/PII_Statistical_Modeling/results/Auth/FR_0417/ALL/localstorage/lifecycle/lifecycle_data.json')
    
    if lifecycle_file.exists():
        print("Chargement des données de test...")
        # Note: Le fichier JSON ne contient pas les timelines complètes
        # Il faudrait relancer l'analyse pour avoir les données complètes
        print("⚠️  Pour tester, relancez l'analyse lifecycle")
