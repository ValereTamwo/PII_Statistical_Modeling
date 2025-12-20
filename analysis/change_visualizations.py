#!/usr/bin/env python3
"""
Module de visualisations des changements pour cookies modified.
Génère 6 graphiques spécifiques à l'analyse des modifications.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import Counter
from typing import Dict, List, Tuple
from pathlib import Path

# Configuration
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)


def plot_changed_fields_distribution(changed_fields: Dict[str, int], output_path: Path):
    """
    Graphique 23: Distribution des champs modifiés.
    
    Args:
        changed_fields: {field_name: count}
        output_path: Chemin de sortie
    """
    # Trier par fréquence
    sorted_fields = sorted(changed_fields.items(), key=lambda x: x[1], reverse=True)
    fields = [item[0] for item in sorted_fields]
    counts = [item[1] for item in sorted_fields]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    bars = ax.barh(fields, counts, color='#3498db', edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bar in bars:
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f'{int(width)}', ha='left', va='center', fontweight='bold', fontsize=10)
    
    ax.set_xlabel('Number of Modifications', fontsize=12, fontweight='bold')
    ax.set_ylabel('Cookie Field', fontsize=12, fontweight='bold')
    ax.set_title('Distribution of Modified Fields\n(Which cookie attributes change most often?)', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_num_changes_distribution(num_changes: Dict[int, int], output_path: Path):
    """
    Graphique 24: Distribution du nombre de changements par cookie.
    
    Args:
        num_changes: {num_fields_changed: count}
        output_path: Chemin de sortie
    """
    # Trier par nombre de changements
    sorted_changes = sorted(num_changes.items())
    nums = [str(item[0]) for item in sorted_changes]
    counts = [item[1] for item in sorted_changes]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    bars = ax.bar(nums, counts, color='#e74c3c', edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom', fontweight='bold', fontsize=10)
    
    ax.set_xlabel('Number of Fields Changed', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Distribution of Number of Changes per Cookie\n(Do cookies change 1 field or multiple?)', 
                 fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_duration_change_scatter(duration_changes: List[Tuple[float, float, str]], output_path: Path):
    """
    Graphique 25: Scatter plot - Durée avant × Durée après.
    
    Args:
        duration_changes: [(duration_before, duration_after, pii_type), ...]
        output_path: Chemin de sortie
    """
    if not duration_changes:
        # Créer un graphique vide avec message
        fig, ax = plt.subplots(figsize=(12, 8))
        ax.text(0.5, 0.5, 'No duration changes detected', 
                ha='center', va='center', fontsize=16)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        return
    
    durations_before = [item[0] for item in duration_changes]
    durations_after = [item[1] for item in duration_changes]
    
    fig, ax = plt.subplots(figsize=(12, 10))
    
    # Scatter plot
    ax.scatter(durations_before, durations_after, alpha=0.5, s=50, 
               c='#3498db', edgecolors='black', linewidth=0.5)
    
    # Ligne de référence (pas de changement)
    max_val = max(max(durations_before), max(durations_after))
    ax.plot([0, max_val], [0, max_val], 'r--', alpha=0.5, linewidth=2, label='No Change')
    
    # Zones
    ax.axhline(y=365, color='orange', linestyle='--', alpha=0.3, linewidth=1.5, label='1 Year')
    ax.axvline(x=365, color='orange', linestyle='--', alpha=0.3, linewidth=1.5)
    
    ax.set_xlabel('Duration Before (days)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Duration After (days)', fontsize=12, fontweight='bold')
    ax.set_title('Cookie Lifetime Evolution\n(Above line = Increased, Below = Decreased)', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='upper left')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_entropy_evolution_scatter(entropy_changes: List[Tuple[float, float, str]], output_path: Path):
    """
    Graphique 26: Scatter plot - Entropie avant × Entropie après.
    
    Args:
        entropy_changes: [(entropy_before, entropy_after, pii_type), ...]
        output_path: Chemin de sortie
    """
    if not entropy_changes:
        fig, ax = plt.subplots(figsize=(12, 8))
        ax.text(0.5, 0.5, 'No entropy changes detected', 
                ha='center', va='center', fontsize=16)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        return
    
    entropy_before = [item[0] for item in entropy_changes]
    entropy_after = [item[1] for item in entropy_changes]
    
    fig, ax = plt.subplots(figsize=(12, 10))
    
    # Scatter plot
    ax.scatter(entropy_before, entropy_after, alpha=0.5, s=50, 
               c='#9b59b6', edgecolors='black', linewidth=0.5)
    
    # Ligne de référence (pas de changement)
    max_val = max(max(entropy_before), max(entropy_after))
    ax.plot([0, max_val], [0, max_val], 'r--', alpha=0.5, linewidth=2, label='No Change')
    
    # Seuils d'entropie
    ax.axhline(y=4.0, color='orange', linestyle='--', alpha=0.3, linewidth=1.5, label='High Entropy (4.0)')
    ax.axvline(x=4.0, color='orange', linestyle='--', alpha=0.3, linewidth=1.5)
    
    ax.set_xlabel('Entropy Before (bits)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Entropy After (bits)', fontsize=12, fontweight='bold')
    ax.set_title('Cookie Value Entropy Evolution\n(Above line = More unique, Below = Less unique)', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='upper left')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_changes_by_pii_type(changes_by_pii: Dict[str, Dict[str, int]], output_path: Path):
    """
    Graphique 27: Changements par type de PII (barres empilées).
    
    Args:
        changes_by_pii: {pii_type: {field: count}}
        output_path: Chemin de sortie
    """
    # Calculer le total de changements par PII type
    pii_totals = {pii: sum(fields.values()) for pii, fields in changes_by_pii.items()}
    
    # Top 15 PII types
    top_piis = sorted(pii_totals.items(), key=lambda x: x[1], reverse=True)[:15]
    pii_types = [item[0] for item in top_piis]
    
    # Identifier les champs les plus fréquents
    all_fields = set()
    for fields in changes_by_pii.values():
        all_fields.update(fields.keys())
    
    # Préparer les données empilées
    field_data = {}
    for field in all_fields:
        field_data[field] = [changes_by_pii[pii].get(field, 0) for pii in pii_types]
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Barres empilées
    bottom = np.zeros(len(pii_types))
    colors = plt.cm.Set3(np.linspace(0, 1, len(all_fields)))
    
    for idx, (field, counts) in enumerate(field_data.items()):
        ax.bar(pii_types, counts, bottom=bottom, label=field, 
               color=colors[idx], edgecolor='black', linewidth=0.5)
        bottom += np.array(counts)
    
    ax.set_xlabel('PII Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Changes', fontsize=12, fontweight='bold')
    ax.set_title('Changes by PII Type (Top 15)\n(Which PII categories are most volatile?)', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.set_xticklabels(pii_types, rotation=45, ha='right')
    ax.legend(loc='upper right', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_modifications_timeline(timeline: Dict[str, int], output_path: Path):
    """
    Graphique 28: Timeline des modifications.
    
    Args:
        timeline: {task_id: count}
        output_path: Chemin de sortie
    """
    # Trier par task_id (chronologique)
    sorted_timeline = sorted(timeline.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)
    task_ids = [item[0] for item in sorted_timeline]
    counts = [item[1] for item in sorted_timeline]
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Ligne avec points
    ax.plot(task_ids, counts, marker='o', linewidth=2, markersize=8, 
            color='#e74c3c', markerfacecolor='#c0392b', markeredgecolor='black')
    
    # Remplissage sous la courbe
    ax.fill_between(range(len(task_ids)), counts, alpha=0.3, color='#e74c3c')
    
    ax.set_xlabel('Task ID (Chronological)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Modifications', fontsize=12, fontweight='bold')
    ax.set_title('Timeline of Cookie Modifications\n(When do modifications occur?)', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.grid(True, alpha=0.3)
    
    # Rotation des labels si trop nombreux
    if len(task_ids) > 20:
        ax.set_xticklabels(task_ids, rotation=45, ha='right')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
