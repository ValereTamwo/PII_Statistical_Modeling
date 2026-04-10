"""
Module d'analyse des stockages web (localStorage, sessionStorage, IndexedDB).

"""

__version__ = '1.0.0'
__author__ = 'PII Statistical Modeling'

from . import storage_consolidated_analysis
# from . import storage_visualizations
from . import storage_lifecycle_analysis
# from . import storage_lifecycle_visualizations

__all__ = [
    'storage_consolidated_analysis',
    'storage_visualizations',
    'storage_lifecycle_analysis',
    'storage_lifecycle_visualizations'
]
