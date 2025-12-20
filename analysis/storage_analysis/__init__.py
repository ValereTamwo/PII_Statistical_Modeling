"""
Module d'analyse des stockages web (localStorage, sessionStorage, IndexedDB).

Ce module fournit des outils d'analyse RGPD pour les différents types de stockage web,
adaptés de l'analyse des cookies mais sans les attributs de sécurité spécifiques aux cookies.
"""

__version__ = '1.0.0'
__author__ = 'PII Statistical Modeling'

from . import storage_consolidated_analysis
from . import storage_visualizations
from . import storage_lifecycle_analysis
from . import storage_lifecycle_visualizations

__all__ = [
    'storage_consolidated_analysis',
    'storage_visualizations',
    'storage_lifecycle_analysis',
    'storage_lifecycle_visualizations'
]
