#!/usr/bin/env python3
"""
Module de détection et classification des PII dans les cookies.
"""

import re
from typing import Dict, List, Set
from pathlib import Path


# Catégories considérées comme contenant des PII
PII_CATEGORIES = {
    'DIRECT_PII',
    'IDENTITY_TRACKING',
    'ID_SOLUTIONS_AND_EXCHANGES',
    'SUSPICIOUS_VALUES',
    'BEHAVIORAL_DATA',
    'NAVIGATION_HISTORY'
}

# Mapping des sous-catégories vers des types PII lisibles
PII_TYPE_MAPPING = {
    # Direct PII
    'email': 'Email',
    'phone': 'Phone Number',
    'full_name': 'Full Name',
    'partial_name': 'Name (Partial)',
    'address': 'Address',
    'postal_code': 'Postal Code',
    
    # Identity
    'ip_address': 'IP Address',
    'user_id': 'User ID',
    'session_id': 'Session ID',
    'device_id': 'Device ID',
    'fingerprint': 'Browser Fingerprint',
    
    # Tracking IDs
    'google_analytics': 'Google Analytics ID',
    'facebook_pixel': 'Facebook Pixel',
    'advertising_id': 'Advertising ID',
    
    # Autres
    'geolocation': 'Geolocation',
    'isp': 'ISP Info',
    'city': 'City',
    'country': 'Country'
}


def classify_pii_type(cookie: Dict) -> str:
    """
    Classifie le type de PII contenu dans un cookie.
    
    Args:
        cookie: Dictionnaire contenant les données du cookie
        
    Returns:
        Type de PII (ex: 'IP Address', 'Email', etc.)
    """
    subcategory = cookie.get('matched_subcategory', '').lower()
    
    # Chercher dans le mapping
    for key, pii_type in PII_TYPE_MAPPING.items():
        if key in subcategory:
            return pii_type
    
    # Analyser le nom du cookie pour détecter le type
    name = cookie.get('name', '').lower()
    
    if any(x in name for x in ['email', 'mail']):
        return 'Email'
    elif any(x in name for x in ['ip', 'ipaddr']):
        return 'IP Address'
    elif any(x in name for x in ['user', 'uid', 'userid']):
        return 'User ID'
    elif any(x in name for x in ['device', 'deviceid']):
        return 'Device ID'
    elif any(x in name for x in ['session', 'sess']):
        return 'Session ID'
    elif any(x in name for x in ['name', 'username']):
        return 'Name (Partial)'
    elif any(x in name for x in ['city', 'location', 'geo']):
        return 'Geolocation'
    elif any(x in name for x in ['_ga', 'analytics']):
        return 'Google Analytics ID'
    elif any(x in name for x in ['_fb', 'facebook']):
        return 'Facebook Pixel'
    elif any(x in name for x in ['fingerprint', 'fp']):
        return 'Browser Fingerprint'
    
    # Par défaut, utiliser la catégorie
    category = cookie.get('source_file', '').replace('.json', '').replace('added_', '').replace('modified_', '')
    return category.replace('_', ' ').title() if category else 'Other PII'


def is_pii_cookie(cookie: Dict, source_category: str = None) -> bool:
    """
    Détermine si un cookie contient des PII.
    
    Args:
        cookie: Dictionnaire contenant les données du cookie
        source_category: Catégorie du fichier source (optionnel)
        
    Returns:
        True si le cookie contient des PII
    """
    # Si la catégorie source est fournie, l'utiliser
    if source_category:
        for pii_cat in PII_CATEGORIES:
            if pii_cat in source_category:
                return True
    
    # Sinon, vérifier le fichier source
    source_file = cookie.get('source_file', '')
    for pii_cat in PII_CATEGORIES:
        if pii_cat in source_file:
            return True
    
    return False


def extract_keywords(cookie_name: str) -> List[str]:
    """
    Extrait les mots-clés significatifs d'un nom de cookie.
    
    Args:
        cookie_name: Nom du cookie
        
    Returns:
        Liste de mots-clés
    """
    # Séparer par underscores, tirets, points
    parts = re.split(r'[_\-\.]', cookie_name.lower())
    
    # Filtrer les mots courts et communs
    stopwords = {'com', 'www', 'http', 'https', 'cookie', 'the', 'and', 'for', 'with'}
    keywords = [p for p in parts if len(p) > 2 and p not in stopwords]
    
    return keywords


def get_pii_summary(cookies: List[Dict]) -> Dict:
    """
    Génre un résumé des PII trouvées dans les cookies.
    
    Args:
        cookies: Liste de cookies
        
    Returns:
        Dictionnaire avec statistiques PII
    """
    pii_cookies = [c for c in cookies if is_pii_cookie(c)]
    
    # Compter par type
    pii_by_type = {}
    for cookie in pii_cookies:
        pii_type = classify_pii_type(cookie)
        pii_by_type[pii_type] = pii_by_type.get(pii_type, 0) + 1
    
    return {
        'total_cookies': len(cookies),
        'pii_cookies': len(pii_cookies),
        'pii_percentage': (len(pii_cookies) / len(cookies) * 100) if cookies else 0,
        'pii_by_type': pii_by_type
    }
