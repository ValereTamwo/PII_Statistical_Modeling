#!/usr/bin/env python3
"""
Module de visualisations pour l'analyse de cycle de vie.
Génère 5 graphiques temporels montrant l'évolution des cookies.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import plotly.graph_objects as go
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
from pathlib import Path

# Configuration
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 10)


def plot_lifecycle_sankey(timelines: Dict, output_path: Path, top_n: int = 10):
    """
    Graphique 29: Sankey temporel - Flux des cookies entre périodes.
    Version ultra-simplifiée avec regroupement par périodes.
    
    Args:
        timelines: {cookie_key: timeline_data}
        output_path: Chemin de sortie
        top_n: Nombre de cookies à afficher (très réduit pour clarté)
    """
    # Sélectionner les cookies les plus modifiés
    top_cookies = sorted(
        timelines.values(),
        key=lambda x: x['num_modifications'],
        reverse=True
    )[:top_n]
    
    # Identifier toutes les tasks pour créer des périodes
    all_task_ids = set()
    for timeline in top_cookies:
        for event in timeline['events']:
            all_task_ids.add(event['task_id'])
    
    task_ids_sorted = sorted(all_task_ids)
    
    # Créer 3 périodes : Début, Milieu, Fin
    num_tasks = len(task_ids_sorted)
    period_size = max(1, num_tasks // 3)
    
    def get_period(task_id):
        idx = task_ids_sorted.index(task_id)
        if idx < period_size:
            return "Début (T{}-T{})".format(task_ids_sorted[0], task_ids_sorted[period_size-1])
        elif idx < 2 * period_size:
            return "Milieu (T{}-T{})".format(task_ids_sorted[period_size], task_ids_sorted[2*period_size-1])
        else:
            return "Fin (T{}-T{})".format(task_ids_sorted[2*period_size], task_ids_sorted[-1])
    
    # Construire les flux entre périodes
    links = defaultdict(int)
    
    for timeline in top_cookies:
        events = timeline['events']
        for i in range(len(events) - 1):
            source_period = get_period(events[i]['task_id'])
            target_period = get_period(events[i+1]['task_id'])
            # Ne compter que les transitions entre périodes différentes
            if source_period != target_period:
                links[(source_period, target_period)] += 1
    
    if not links:
        # Aucune transition entre périodes, créer un graphique simple
        print("      ⚠️  Pas de transitions entre périodes, graphique simplifié")
        return
    
    # Créer les nœuds
    nodes = set()
    for source, target in links.keys():
        nodes.add(source)
        nodes.add(target)
    
    node_list = sorted(nodes)
    node_dict = {node: idx for idx, node in enumerate(node_list)}
    
    # Créer les liens
    sources = []
    targets = []
    values = []
    
    for (source, target), count in links.items():
        sources.append(node_dict[source])
        targets.append(node_dict[target])
        values.append(count)
    
    # Couleurs par période
    colors = ['#3498db', '#9b59b6', '#e74c3c'][:len(node_list)]
    
    fig = go.Figure(data=[go.Sankey(
        arrangement='snap',
        node=dict(
            pad=50,  # Beaucoup d'espacement
            thickness=40,  # Nœuds très épais
            line=dict(color="black", width=2),
            label=node_list,
            color=colors,
            hovertemplate='%{label}<br>%{value} transitions<extra></extra>'
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values,
            color='rgba(52, 152, 219, 0.3)',
            hovertemplate='%{value} cookies<br>%{source.label} → %{target.label}<extra></extra>'
        )
    )])
    
    fig.update_layout(
        title={
            'text': f'Cookie Lifecycle Flow - Top {top_n} Cookies<br>' +
                    '<sub>Simplified view: transitions between time periods</sub>',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20}
        },
        font=dict(size=16, family='Arial', color='black'),
        width=2000,  # Très large
        height=800,  # Moins haut
        margin=dict(l=100, r=100, t=120, b=50),
        plot_bgcolor='white',
        paper_bgcolor='white'
    )
    
    # Sauvegarder en HTML (prioritaire)
    html_path = str(output_path).replace('.png', '.html')
    fig.write_html(html_path)
    print(f"      → HTML interactif: {html_path}")
    
    # Aussi sauvegarder en PNG si possible
    try:
        fig.write_image(str(output_path), width=2000, height=800, scale=2)
        print(f"      → PNG statique: {output_path}")
    except:
        print(f"      → PNG non disponible (Kaleido), voir HTML")


def plot_duration_evolution(timelines: Dict, output_path: Path, top_n: int = 20):
    """
    Graphique 30: Évolution de la durée de vie.
    
    Args:
        timelines: {cookie_key: timeline_data}
        output_path: Chemin de sortie
        top_n: Nombre de cookies à afficher
    """
    # Sélectionner les cookies avec le plus de changements de durée
    cookies_with_duration_change = []
    for key, timeline in timelines.items():
        if len(timeline['duration_evolution']) > 1:
            duration_range = max(timeline['duration_evolution']) - min(timeline['duration_evolution'])
            if duration_range > 0:
                cookies_with_duration_change.append((key, timeline, duration_range))
    
    top_cookies = sorted(cookies_with_duration_change, key=lambda x: x[2], reverse=True)[:top_n]
    
    fig, ax = plt.subplots(figsize=(16, 10))
    
    colors = plt.cm.tab20(np.linspace(0, 1, len(top_cookies)))
    
    for idx, (key, timeline, _) in enumerate(top_cookies):
        events = timeline['events']
        task_ids = [e['task_id'] for e in events]
        durations = timeline['duration_evolution']
        
        # Nom court pour la légende
        cookie_name = key.split('|')[0][:20]
        
        ax.plot(task_ids, durations, marker='o', linewidth=2, markersize=6,
                color=colors[idx], label=cookie_name, alpha=0.7)
    
    ax.set_xlabel('Task ID', fontsize=14, fontweight='bold')
    ax.set_ylabel('Duration (days)', fontsize=14, fontweight='bold')
    ax.set_title(f'Cookie Lifetime Evolution (Top {top_n} Cookies)\nIncreasing = More Persistent',
                 fontsize=16, fontweight='bold', pad=20)
    ax.axhline(y=365, color='red', linestyle='--', alpha=0.5, linewidth=2, label='1 Year')
    ax.legend(loc='upper left', fontsize=9, ncol=2)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_entropy_evolution(timelines: Dict, output_path: Path, top_n: int = 20):
    """
    Graphique 31: Évolution de l'entropie.
    
    Args:
        timelines: {cookie_key: timeline_data}
        output_path: Chemin de sortie
        top_n: Nombre de cookies à afficher
    """
    # Sélectionner les cookies avec le plus de changements d'entropie
    cookies_with_entropy_change = []
    for key, timeline in timelines.items():
        if len(timeline['entropy_evolution']) > 1:
            entropy_range = max(timeline['entropy_evolution']) - min(timeline['entropy_evolution'])
            if entropy_range > 0:
                cookies_with_entropy_change.append((key, timeline, entropy_range))
    
    top_cookies = sorted(cookies_with_entropy_change, key=lambda x: x[2], reverse=True)[:top_n]
    
    fig, ax = plt.subplots(figsize=(16, 10))
    
    colors = plt.cm.viridis(np.linspace(0, 1, len(top_cookies)))
    
    for idx, (key, timeline, _) in enumerate(top_cookies):
        events = timeline['events']
        task_ids = [e['task_id'] for e in events]
        entropies = timeline['entropy_evolution']
        
        # Nom court pour la légende
        cookie_name = key.split('|')[0][:20]
        
        ax.plot(task_ids, entropies, marker='s', linewidth=2, markersize=6,
                color=colors[idx], label=cookie_name, alpha=0.7)
    
    ax.set_xlabel('Task ID', fontsize=14, fontweight='bold')
    ax.set_ylabel('Entropy (bits)', fontsize=14, fontweight='bold')
    ax.set_title(f'Cookie Value Entropy Evolution (Top {top_n} Cookies)\nIncreasing = More Complex/Unique',
                 fontsize=16, fontweight='bold', pad=20)
    ax.axhline(y=4.0, color='orange', linestyle='--', alpha=0.5, linewidth=2, label='High Entropy (4.0)')
    ax.legend(loc='upper left', fontsize=9, ncol=2)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_pii_transition_matrix(timelines: Dict, output_path: Path):
    """
    Graphique 32: Matrice de transition PII.
    
    Args:
        timelines: {cookie_key: timeline_data}
        output_path: Chemin de sortie
    """
    # Calculer les transitions
    transitions = defaultdict(int)
    
    for timeline in timelines.values():
        if len(timeline['pii_categories']) > 1:
            initial = timeline['pii_categories'][0]
            final = timeline['pii_categories'][-1]
            transitions[(initial, final)] += 1
    
    if not transitions:
        # Créer un graphique vide avec message
        fig, ax = plt.subplots(figsize=(12, 8))
        ax.text(0.5, 0.5, 'No PII transitions detected', 
                ha='center', va='center', fontsize=16)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        return
    
    # Identifier les catégories uniques
    all_categories = set()
    for (initial, final) in transitions.keys():
        all_categories.add(initial)
        all_categories.add(final)
    
    categories = sorted(all_categories)
    
    # Créer la matrice
    matrix = np.zeros((len(categories), len(categories)))
    for (initial, final), count in transitions.items():
        i = categories.index(initial)
        j = categories.index(final)
        matrix[i, j] = count
    
    fig, ax = plt.subplots(figsize=(14, 12))
    
    # Heatmap
    im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto')
    
    # Axes
    ax.set_xticks(np.arange(len(categories)))
    ax.set_yticks(np.arange(len(categories)))
    ax.set_xticklabels(categories, rotation=45, ha='right')
    ax.set_yticklabels(categories)
    
    # Labels
    ax.set_xlabel('Final PII Category', fontsize=12, fontweight='bold')
    ax.set_ylabel('Initial PII Category', fontsize=12, fontweight='bold')
    ax.set_title('PII Category Transition Matrix\n(How cookies change their nature)',
                 fontsize=14, fontweight='bold', pad=20)
    
    # Colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Number of Cookies', fontsize=11, fontweight='bold')
    
    # Annotations
    for i in range(len(categories)):
        for j in range(len(categories)):
            if matrix[i, j] > 0:
                text = ax.text(j, i, int(matrix[i, j]),
                             ha="center", va="center", color="black", fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_activity_heatmap(timelines: Dict, output_path: Path, top_n: int = 50):
    """
    Graphique 33: Heatmap temporelle d'activité.
    
    Args:
        timelines: {cookie_key: timeline_data}
        output_path: Chemin de sortie
        top_n: Nombre de cookies à afficher
    """
    # Sélectionner les cookies les plus actifs
    top_cookies = sorted(
        timelines.values(),
        key=lambda x: len(x['events']),
        reverse=True
    )[:top_n]
    
    # Identifier toutes les tasks
    all_tasks = set()
    for timeline in top_cookies:
        for event in timeline['events']:
            all_tasks.add(event['task_id'])
    
    tasks = sorted(all_tasks)
    
    # Créer la matrice et les annotations
    matrix = np.zeros((len(top_cookies), len(tasks)))
    annotations = {}  # {(i, j): "label"}
    cookie_labels = []
    
    for i, timeline in enumerate(top_cookies):
        # Label court
        cookie_name = timeline['key'].split('|')[0][:30]
        cookie_labels.append(cookie_name)
        
        for event in timeline['events']:
            j = tasks.index(event['task_id'])
            if event['type'] == 'added':
                matrix[i, j] = 1  # Vert
                annotations[(i, j)] = "A"  # A = Added
            else:  # modified
                matrix[i, j] = 2  # Orange
                
                # Créer un label court pour les champs modifiés
                changed_fields = event.get('changed_fields', [])
                if changed_fields:
                    # Abréviations
                    abbrev = {
                        'value': 'V',
                        'expires': 'E',
                        'httpOnly': 'H',
                        'secure': 'S',
                        'sameSite': 'SS'
                    }
                    labels = [abbrev.get(f, f[0].upper()) for f in changed_fields[:2]]  # Max 2
                    annotations[(i, j)] = ','.join(labels)
                else:
                    annotations[(i, j)] = "M"  # M = Modified (champ inconnu)
    
    fig, ax = plt.subplots(figsize=(16, 14))
    
    # Heatmap avec couleurs personnalisées
    cmap = plt.cm.colors.ListedColormap(['white', '#2ecc71', '#e67e22'])
    im = ax.imshow(matrix, cmap=cmap, aspect='auto', vmin=0, vmax=2)
    
    # Axes
    ax.set_xticks(np.arange(len(tasks)))
    ax.set_yticks(np.arange(len(cookie_labels)))
    ax.set_xticklabels(tasks)
    ax.set_yticklabels(cookie_labels, fontsize=8)
    
    # Ajouter les annotations (labels discrets)
    for (i, j), label in annotations.items():
        if matrix[i, j] > 0:  # Seulement si actif
            # Couleur du texte selon le fond
            text_color = 'white' if matrix[i, j] == 2 else 'black'
            ax.text(j, i, label, ha='center', va='center',
                   fontsize=7, fontweight='bold', color=text_color)
    
    # Labels
    ax.set_xlabel('Task ID', fontsize=12, fontweight='bold')
    ax.set_ylabel('Cookie', fontsize=12, fontweight='bold')
    ax.set_title(f'Cookie Activity Timeline (Top {top_n} Most Active)\n' +
                 'Green=Added (A), Orange=Modified (V=Value, E=Expires, H=HttpOnly, S=Secure)',
                 fontsize=14, fontweight='bold', pad=20)
    
    # Grille
    ax.set_xticks(np.arange(len(tasks))-.5, minor=True)
    ax.set_yticks(np.arange(len(cookie_labels))-.5, minor=True)
    ax.grid(which="minor", color="gray", linestyle='-', linewidth=0.5, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
