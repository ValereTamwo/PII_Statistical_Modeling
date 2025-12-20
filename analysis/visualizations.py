#!/usr/bin/env python3
"""
Module de génération des visualisations pour l'analyse PII.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import Counter
from typing import Dict, List
from pathlib import Path

# Configuration du style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10


def plot_lifetime_distribution(lifetime_data: Dict[str, int], output_path: Path):
    """Graphique 1: Distribution globale des durées de vie des cookies PII"""
    categories = list(lifetime_data.keys())
    values = list(lifetime_data.values())
    
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ['#2ecc71', '#f39c12', '#e74c3c', '#c0392b']
    bars = ax.bar(categories, values, color=colors[:len(categories)], edgecolor='black', linewidth=1.2)
    
    # Ajouter les valeurs sur les barres
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom', fontweight='bold')
    
    ax.set_xlabel('Cookie Lifetime Category', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of PII Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Distribution of PII Cookie Lifetimes', fontsize=14, fontweight='bold', pad=20)
    plt.xticks(rotation=15, ha='right')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_lifetime_by_pii_type(lifetime_by_type: Dict[str, Dict[str, int]], output_path: Path):
    """Graphique 2: Distribution des durées de vie par type de PII"""
    pii_types = list(lifetime_by_type.keys())
    lifetime_categories = ['Session', '<6 months', '6-18 months', '>18 months']
    
    # Préparer les données
    data = {cat: [] for cat in lifetime_categories}
    for pii_type in pii_types:
        for cat in lifetime_categories:
            data[cat].append(lifetime_by_type[pii_type].get(cat, 0))
    
    fig, ax = plt.subplots(figsize=(12, 7))
    x = np.arange(len(pii_types))
    width = 0.2
    colors = ['#2ecc71', '#f39c12', '#e74c3c', '#c0392b']
    
    for i, (cat, color) in enumerate(zip(lifetime_categories, colors)):
        offset = width * (i - 1.5)
        ax.bar(x + offset, data[cat], width, label=cat, color=color, edgecolor='black', linewidth=0.8)
    
    ax.set_xlabel('PII Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Distribution of PII Cookie Lifetimes Per PII Type', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(pii_types, rotation=45, ha='right')
    ax.legend(title='Lifetime', loc='upper right')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_httponly_distribution(httponly_data: Dict[str, int], output_path: Path):
    """Graphique 3: Distribution globale HttpOnly"""
    labels = list(httponly_data.keys())
    sizes = list(httponly_data.values())
    colors = ['#e74c3c', '#2ecc71']  # False=Rouge, True=Vert
    explode = tuple([0.05] + [0] * (len(labels) - 1)) if len(labels) > 1 else (0.05,)
    
    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%',
                                        colors=colors[:len(labels)], explode=explode,
                                        startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    ax.set_title('Distribution isHttpOnly Cookie PII', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_httponly_by_pii_type(httponly_by_type: Dict[str, Dict[str, int]], output_path: Path):
    """Graphique 4: Distribution HttpOnly par type de PII"""
    pii_types = list(httponly_by_type.keys())
    
    false_counts = [httponly_by_type[pt].get('False', 0) for pt in pii_types]
    true_counts = [httponly_by_type[pt].get('True', 0) for pt in pii_types]
    
    fig, ax = plt.subplots(figsize=(12, 7))
    x = np.arange(len(pii_types))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, false_counts, width, label='HttpOnly=False', 
                   color='#e74c3c', edgecolor='black', linewidth=1)
    bars2 = ax.bar(x + width/2, true_counts, width, label='HttpOnly=True', 
                   color='#2ecc71', edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom', fontsize=9)
    
    ax.set_xlabel('PII Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Distribution isHttpOnly Cookie PII per PII Type', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(pii_types, rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_secure_distribution(secure_data: Dict[str, int], output_path: Path):
    """Graphique 5: Distribution globale Secure"""
    labels = list(secure_data.keys())
    sizes = list(secure_data.values())
    colors = ['#e74c3c', '#2ecc71']
    explode = tuple([0.05] + [0] * (len(labels) - 1)) if len(labels) > 1 else (0.05,)
    
    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%',
                                        colors=colors[:len(labels)], explode=explode,
                                        startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    ax.set_title('Distribution isSecure Cookie PII', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_secure_by_pii_type(secure_by_type: Dict[str, Dict[str, int]], output_path: Path):
    """Graphique 6: Distribution Secure par type de PII"""
    pii_types = list(secure_by_type.keys())
    
    false_counts = [secure_by_type[pt].get('False', 0) for pt in pii_types]
    true_counts = [secure_by_type[pt].get('True', 0) for pt in pii_types]
    
    fig, ax = plt.subplots(figsize=(12, 7))
    x = np.arange(len(pii_types))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, false_counts, width, label='Secure=False', 
                   color='#e74c3c', edgecolor='black', linewidth=1)
    bars2 = ax.bar(x + width/2, true_counts, width, label='Secure=True', 
                   color='#2ecc71', edgecolor='black', linewidth=1)
    
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom', fontsize=9)
    
    ax.set_xlabel('PII Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Distribution isSecure Cookie PII per PII Type', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(pii_types, rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_samesite_distribution(samesite_data: Dict[str, int], output_path: Path):
    """Graphique 7: Distribution globale SameSite"""
    categories = list(samesite_data.keys())
    values = list(samesite_data.values())
    colors = ['#2ecc71', '#f39c12', '#e74c3c']
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(categories, values, color=colors[:len(categories)], edgecolor='black', linewidth=1.2)
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom', fontweight='bold')
    
    ax.set_xlabel('SameSite Policy', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of PII Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Distribution sameSite Cookie PII', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_samesite_by_pii_type(samesite_by_type: Dict[str, Dict[str, int]], output_path: Path):
    """Graphique 8: Distribution SameSite par type de PII"""
    pii_types = list(samesite_by_type.keys())
    samesite_categories = ['Strict', 'Lax', 'No Restriction']
    
    data = {cat: [] for cat in samesite_categories}
    for pii_type in pii_types:
        for cat in samesite_categories:
            data[cat].append(samesite_by_type[pii_type].get(cat, 0))
    
    fig, ax = plt.subplots(figsize=(12, 7))
    x = np.arange(len(pii_types))
    width = 0.25
    colors = ['#2ecc71', '#f39c12', '#e74c3c']
    
    for i, (cat, color) in enumerate(zip(samesite_categories, colors)):
        offset = width * (i - 1)
        ax.bar(x + offset, data[cat], width, label=cat, color=color, edgecolor='black', linewidth=0.8)
    
    ax.set_xlabel('PII Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Distribution sameSite Cookie PII per PII Type', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(pii_types, rotation=45, ha='right')
    ax.legend(title='SameSite')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_security_matrix(matrix_data: Dict[tuple, int], output_path: Path):
    """Graphique 9: Matrice de sécurité (HttpOnly × Secure)"""
    # Créer la matrice
    matrix = np.zeros((2, 2))
    labels = [['HttpOnly=False\nSecure=False', 'HttpOnly=False\nSecure=True'],
              ['HttpOnly=True\nSecure=False', 'HttpOnly=True\nSecure=True']]
    
    matrix[0, 0] = matrix_data.get((False, False), 0)
    matrix[0, 1] = matrix_data.get((False, True), 0)
    matrix[1, 0] = matrix_data.get((True, False), 0)
    matrix[1, 1] = matrix_data.get((True, True), 0)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(matrix, cmap='RdYlGn', aspect='auto')
    
    # Ajouter les valeurs
    for i in range(2):
        for j in range(2):
            text = ax.text(j, i, f'{int(matrix[i, j])}\ncookies',
                          ha="center", va="center", color="black", fontsize=14, fontweight='bold')
    
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Secure=False', 'Secure=True'], fontsize=11)
    ax.set_yticklabels(['HttpOnly=False', 'HttpOnly=True'], fontsize=11)
    ax.set_title('PII Cookies Security Matrix', fontsize=14, fontweight='bold', pad=20)
    
    plt.colorbar(im, ax=ax, label='Number of Cookies')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_security_posture(security_by_type: Dict[str, Dict[str, int]], output_path: Path):
    """Graphique 10: Posture de sécurité globale par type de PII"""
    pii_types = list(security_by_type.keys())
    
    lowly_secure = [security_by_type[pt].get('Lowly Secure', 0) for pt in pii_types]
    partially_secure = [security_by_type[pt].get('Partially Secure', 0) for pt in pii_types]
    secure = [security_by_type[pt].get('Secure', 0) for pt in pii_types]
    
    fig, ax = plt.subplots(figsize=(12, 7))
    x = np.arange(len(pii_types))
    width = 0.6
    
    p1 = ax.bar(x, lowly_secure, width, label='Lowly Secure', color='#e74c3c', edgecolor='black')
    p2 = ax.bar(x, partially_secure, width, bottom=lowly_secure, label='Partially Secure', 
                color='#f39c12', edgecolor='black')
    p3 = ax.bar(x, secure, width, bottom=np.array(lowly_secure) + np.array(partially_secure),
                label='Secure', color='#2ecc71', edgecolor='black')
    
    ax.set_xlabel('PII Type', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Overall Security Posture by PII Type', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(pii_types, rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_keyword_frequency(keywords: Counter, output_path: Path, top_n: int = 15):
    """Graphique 11: Mots-clés les plus fréquents dans les noms de cookies PII"""
    most_common = keywords.most_common(top_n)
    words = [item[0] for item in most_common]
    counts = [item[1] for item in most_common]
    
    fig, ax = plt.subplots(figsize=(10, 8))
    colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(words)))
    bars = ax.barh(words, counts, color=colors, edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bar in bars:
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f'{int(width)}', ha='left', va='center', fontweight='bold', fontsize=10)
    
    ax.set_xlabel('Frequency', fontsize=12, fontweight='bold')
    ax.set_ylabel('Keyword', fontsize=12, fontweight='bold')
    ax.set_title('Most Frequent Keywords in PII Cookie Names', fontsize=14, fontweight='bold', pad=20)
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_subcategory_distribution(subcategory_data: Dict[str, int], output_path: Path):
    """Graphique 7: Distribution des sous-catégories PII"""
    subcategories = list(subcategory_data.keys())
    counts = list(subcategory_data.values())
    
    fig, ax = plt.subplots(figsize=(12, 8))
    colors = plt.cm.tab20(np.linspace(0, 1, len(subcategories)))
    bars = ax.barh(subcategories, counts, color=colors, edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bar in bars:
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f'{int(width)}', ha='left', va='center', fontweight='bold', fontsize=9)
    
    ax.set_xlabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_ylabel('PII Subcategory', fontsize=12, fontweight='bold')
    ax.set_title('Distribution of PII Subcategories', fontsize=14, fontweight='bold', pad=20)
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_match_type_distribution(match_type_data: Dict[str, int], output_path: Path):
    """Graphique 8: Distribution des types de match (name vs value)"""
    labels = list(match_type_data.keys())
    sizes = list(match_type_data.values())
    colors = ['#3498db', '#e74c3c', '#95a5a6']  # Bleu, Rouge, Gris
    explode = tuple([0.05] + [0] * (len(labels) - 1)) if len(labels) > 1 else (0.05,)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%',
                                        colors=colors[:len(labels)], explode=explode,
                                        startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    ax.set_title('Distribution of Match Types (Name vs Value)', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_subcategory_security_attribute(subcategory_attr_data: Dict[str, Dict[str, int]], 
                                         attribute_name: str, output_path: Path):
    """Graphiques 9-10: Sous-catégories × Attribut de sécurité (HttpOnly ou Secure)"""
    # Limiter aux top 10 sous-catégories
    total_by_subcat = {k: sum(v.values()) for k, v in subcategory_attr_data.items()}
    top_subcats = sorted(total_by_subcat.items(), key=lambda x: x[1], reverse=True)[:10]
    subcategories = [item[0] for item in top_subcats]
    
    false_counts = [subcategory_attr_data[sc].get('False', 0) for sc in subcategories]
    true_counts = [subcategory_attr_data[sc].get('True', 0) for sc in subcategories]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    x = np.arange(len(subcategories))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, false_counts, width, label=f'{attribute_name}=False', 
                   color='#e74c3c', edgecolor='black', linewidth=1)
    bars2 = ax.bar(x + width/2, true_counts, width, label=f'{attribute_name}=True', 
                   color='#2ecc71', edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom', fontsize=8)
    
    ax.set_xlabel('PII Subcategory', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_title(f'PII Subcategories × {attribute_name} Attribute', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(subcategories, rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_thirdparty_distribution(thirdparty_data: Dict[str, int], output_path: Path):
    """Graphique 12: Distribution Third-Party vs First-Party"""
    labels = list(thirdparty_data.keys())
    sizes = list(thirdparty_data.values())
    colors = ['#e74c3c', '#2ecc71']  # Third-Party=Rouge, First-Party=Vert
    explode = tuple([0.05] + [0] * (len(labels) - 1)) if len(labels) > 1 else (0.05,)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%',
                                        colors=colors[:len(labels)], explode=explode,
                                        startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    ax.set_title('Third-Party vs First-Party Cookie Distribution', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_thirdparty_by_subcategory(thirdparty_by_subcat: Dict[str, Dict[str, int]], output_path: Path):
    """Graphique 13: Third-Party par sous-catégorie PII"""
    # Limiter aux top 10 sous-catégories
    total_by_subcat = {k: sum(v.values()) for k, v in thirdparty_by_subcat.items()}
    top_subcats = sorted(total_by_subcat.items(), key=lambda x: x[1], reverse=True)[:10]
    subcategories = [item[0] for item in top_subcats]
    
    first_party = [thirdparty_by_subcat[sc].get('First-Party', 0) for sc in subcategories]
    third_party = [thirdparty_by_subcat[sc].get('Third-Party', 0) for sc in subcategories]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    x = np.arange(len(subcategories))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, first_party, width, label='First-Party', 
                   color='#2ecc71', edgecolor='black', linewidth=1)
    bars2 = ax.bar(x + width/2, third_party, width, label='Third-Party', 
                   color='#e74c3c', edgecolor='black', linewidth=1)
    
    # Ajouter les valeurs
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom', fontsize=8)
    
    ax.set_xlabel('PII Subcategory', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax.set_title('Third-Party Distribution Per PII Type (Subcategory)', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(subcategories, rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_thirdparty_security_matrix(thirdparty_security: Dict[str, int], 
                                     attribute_name: str, output_path: Path):
    """Graphiques 14-15: Third-Party × Attribut de sécurité (HttpOnly ou Secure)"""
    # Créer la matrice 2x2
    matrix = np.zeros((2, 2))
    labels_text = [['Third-Party\n' + attribute_name + '=False', 'Third-Party\n' + attribute_name + '=True'],
                   ['First-Party\n' + attribute_name + '=False', 'First-Party\n' + attribute_name + '=True']]
    
    matrix[0, 0] = thirdparty_security.get('Third-Party_False', 0)
    matrix[0, 1] = thirdparty_security.get('Third-Party_True', 0)
    matrix[1, 0] = thirdparty_security.get('First-Party_False', 0)
    matrix[1, 1] = thirdparty_security.get('First-Party_True', 0)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(matrix, cmap='RdYlGn', aspect='auto')
    
    # Ajouter les valeurs
    for i in range(2):
        for j in range(2):
            text = ax.text(j, i, f'{int(matrix[i, j])}\ncookies',
                          ha="center", va="center", color="black", fontsize=14, fontweight='bold')
    
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels([f'{attribute_name}=False', f'{attribute_name}=True'], fontsize=11)
    ax.set_yticklabels(['Third-Party', 'First-Party'], fontsize=11)
    ax.set_title(f'Third-Party × {attribute_name} Security Matrix', fontsize=14, fontweight='bold', pad=20)
    
    plt.colorbar(im, ax=ax, label='Number of Cookies')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_risk_matrix(risk_levels: Dict[str, int], risk_by_subcat: Dict[str, Dict[str, int]], 
                     output_path: Path):
    """Graphique 16: Matrice de Risque RGPD"""
    # Créer une figure avec 2 sous-graphiques
    fig = plt.figure(figsize=(16, 8))
    
    # Sous-graphique 1: Distribution globale des niveaux de risque
    ax1 = plt.subplot(1, 2, 1)
    
    # Ordre des niveaux de risque
    risk_order = ['Critical Risk', 'High Risk', 'Medium Risk', 'Low Risk']
    colors_risk = ['#c0392b', '#e74c3c', '#f39c12', '#2ecc71']
    
    levels = [risk_levels.get(level, 0) for level in risk_order]
    colors = [colors_risk[i] for i, level in enumerate(risk_order) if risk_levels.get(level, 0) > 0]
    labels = [level for level in risk_order if risk_levels.get(level, 0) > 0]
    values = [v for v in levels if v > 0]
    
    if values:
        wedges, texts, autotexts = ax1.pie(values, labels=labels, autopct='%1.1f%%',
                                            colors=colors, startangle=90,
                                            textprops={'fontsize': 11, 'fontweight': 'bold'})
    
    ax1.set_title('GDPR Risk Level Distribution\n(PII + Duration>1yr + HttpOnly=False + Third-Party)', 
                  fontsize=13, fontweight='bold', pad=15)
    
    # Sous-graphique 2: Risque par sous-catégorie (top 10)
    ax2 = plt.subplot(1, 2, 2)
    
    # Calculer le score de risque moyen par sous-catégorie
    risk_scores = {}
    for subcat, risks in risk_by_subcat.items():
        total = sum(risks.values())
        if total > 0:
            score = (risks.get('Critical Risk', 0) * 3 + 
                    risks.get('High Risk', 0) * 2 + 
                    risks.get('Medium Risk', 0) * 1) / total
            risk_scores[subcat] = (score, total)
    
    # Top 10 sous-catégories par score de risque
    top_subcats = sorted(risk_scores.items(), key=lambda x: x[1][0], reverse=True)[:10]
    subcats = [item[0] for item in top_subcats]
    
    # Préparer les données empilées
    critical = [risk_by_subcat[sc].get('Critical Risk', 0) for sc in subcats]
    high = [risk_by_subcat[sc].get('High Risk', 0) for sc in subcats]
    medium = [risk_by_subcat[sc].get('Medium Risk', 0) for sc in subcats]
    low = [risk_by_subcat[sc].get('Low Risk', 0) for sc in subcats]
    
    x = np.arange(len(subcats))
    width = 0.6
    
    p1 = ax2.bar(x, critical, width, label='Critical Risk', color='#c0392b', edgecolor='black')
    p2 = ax2.bar(x, high, width, bottom=critical, label='High Risk', color='#e74c3c', edgecolor='black')
    p3 = ax2.bar(x, medium, width, bottom=np.array(critical)+np.array(high), 
                 label='Medium Risk', color='#f39c12', edgecolor='black')
    p4 = ax2.bar(x, low, width, bottom=np.array(critical)+np.array(high)+np.array(medium),
                 label='Low Risk', color='#2ecc71', edgecolor='black')
    
    ax2.set_xlabel('PII Subcategory', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Number of Cookies', fontsize=12, fontweight='bold')
    ax2.set_title('Risk Distribution by PII Type (Top 10)', fontsize=13, fontweight='bold', pad=15)
    ax2.set_xticks(x)
    ax2.set_xticklabels(subcats, rotation=45, ha='right')
    ax2.legend(loc='upper right')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

