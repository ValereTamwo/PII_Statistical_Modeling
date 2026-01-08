#!/usr/bin/env python3
"""
Module de calcul des métriques vie privée pour l'analyse RGPD.
Implémente les 4 axes d'analyse avancée.
"""

import re
import json
import base64
import math
from typing import Dict, List, Tuple, Optional
from urllib.parse import unquote, urlparse
from collections import Counter


def calculate_entropy(value: str) -> float:
    """
    Calcule l'entropie de Shannon d'une chaîne de caractères.
    
    L'entropie mesure l'unicité/imprévisibilité d'une valeur :
    - 0 bits : Valeur constante (ex: "true", "1")
    - 1-2 bits : Faible entropie (ex: "fr", "en")
    - 3-5 bits : Entropie moyenne (ex: dates, compteurs)
    - 6+ bits : Haute entropie (ex: UUID, tokens, identifiants uniques)
    
    Args:
        value: La valeur du cookie
        
    Returns:
        Entropie en bits (0 à ~8+)
    """
    if not value or len(value) == 0:
        return 0.0
    
    # Compter la fréquence de chaque caractère
    char_counts = Counter(value)
    length = len(value)
    
    # Calculer l'entropie de Shannon
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def decode_value(value: str) -> Tuple[str, str, bool]:
    """
    Tente de décoder une valeur de cookie avec différentes méthodes.
    
    Args:
        value: Valeur brute du cookie
        
    Returns:
        Tuple (valeur_décodée, méthode_décodage, succès)
        - valeur_décodée: La valeur après décodage
        - méthode_décodage: 'base64', 'url', 'json', 'jwt', 'none'
        - succès: True si décodage réussi
    """
    if not value:
        return value, 'none', False
    
    # Tentative 1: Base64
    try:
        # Vérifier si ça ressemble à du Base64
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', value):
            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 0:
                return decoded, 'base64', True
    except:
        pass
    
    # Tentative 2: URL encoding
    try:
        decoded = unquote(value)
        if decoded != value:  # Si différent, c'était encodé
            return decoded, 'url', True
    except:
        pass
    
    # Tentative 3: JSON
    try:
        parsed = json.loads(value)
        if isinstance(parsed, (dict, list)):
            return json.dumps(parsed, indent=2), 'json', True
    except:
        pass
    
    # Tentative 4: JWT (3 parties séparées par des points)
    if value.count('.') == 2:
        try:
            parts = value.split('.')
            # Décoder la partie payload (2ème partie)
            payload = parts[1]
            # Ajouter padding si nécessaire
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            decoded = base64.urlsafe_b64decode(payload).decode('utf-8')
            return decoded, 'jwt', True
        except:
            pass
    
    return value, 'none', False


def detect_data_type(value: str, decoded_value: str = None) -> str:
    """
    Détecte le type de données contenu dans une valeur de cookie.
    
    Args:
        value: Valeur brute
        decoded_value: Valeur décodée (optionnel)
        
    Returns:
        Type de données détecté
    """
    # Utiliser la valeur décodée si disponible
    check_value = decoded_value if decoded_value else value
    
    if not check_value:
        return 'empty'
    
    # UUID (format standard)
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', check_value.lower()):
        return 'uuid'
    
    # UUID compact (sans tirets)
    if re.match(r'^[0-9a-f]{32}$', check_value.lower()):
        return 'uuid_compact'
    
    # Email
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', check_value):
        return 'email'
    
    # Adresse IP
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', check_value):
        return 'ip_address'
    
    # Token/ID long (20+ caractères alphanumériques)
    if re.match(r'^[A-Za-z0-9_-]{20,}$', check_value):
        return 'token_id'
    
    # JSON structuré
    if check_value.startswith('{') or check_value.startswith('['):
        try:
            json.loads(check_value)
            return 'json_structured'
        except:
            pass
    
    # Timestamp Unix (10 chiffres)
    if re.match(r'^\d{10}$', check_value):
        return 'timestamp'
    
    # Booléen
    if check_value.lower() in ['true', 'false', '1', '0', 'yes', 'no']:
        return 'boolean'
    
    # Nombre
    if re.match(r'^\d+$', check_value):
        return 'number'
    
    # Code langue (2-5 lettres)
    if re.match(r'^[a-z]{2,5}(-[A-Z]{2})?$', check_value):
        return 'language_code'
    
    # Texte court (< 20 caractères, pas de caractères spéciaux)
    if len(check_value) < 20 and re.match(r'^[a-zA-Z0-9_-]+$', check_value):
        return 'short_text'
    
    # Par défaut
    return 'complex_string'


def is_third_party(cookie_domain: str, initial_url: str) -> bool:
    """
    Détermine si un cookie est third-party en comparant son domaine avec l'URL initiale.
    
    Args:
        cookie_domain: Domaine du cookie (ex: '.example.com')
        initial_url: URL initiale de la page (ex: 'https://www.example.com/page')
    
    Returns:
        True si le cookie est third-party
    """
    if not cookie_domain or not initial_url:
        return False
    
    # Extraire le domaine de l'URL
    try:
        parsed_url = urlparse(initial_url)
        url_domain = parsed_url.netloc.lower()
        
        # Nettoyer le domaine du cookie (enlever le point initial)
        clean_cookie_domain = cookie_domain.lower().lstrip('.')
        
        # Vérifier si le domaine du cookie correspond à l'URL
        # First-party si le domaine de l'URL se termine par le domaine du cookie
        return not url_domain.endswith(clean_cookie_domain)
    except:
        return False


def extract_vendor_from_domain(domain: str) -> str:
    """
    Extrait le vendor (entreprise) à partir d'un domaine.
    
    Utilise la base de données étendue de vendor_database.py (50+ vendors).
    
    Args:
        domain: Domaine du cookie (ex: '.doubleclick.net')
        
    Returns:
        Nom du vendor (ex: 'Google')
    """
    # Importer depuis vendor_database
    try:
        from vendor_database import extract_vendor_from_domain as extract_vendor_extended
        return extract_vendor_extended(domain)
    except ImportError:
        # Fallback si vendor_database n'est pas disponible
        clean_domain = domain.lower().lstrip('.')
        parts = clean_domain.split('.')
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return clean_domain


def classify_entropy_level(entropy: float) -> str:
    """
    Classifie le niveau d'entropie.
    
    Args:
        entropy: Valeur d'entropie en bits
        
    Returns:
        Niveau : 'Very Low', 'Low', 'Medium', 'High', 'Very High'
    """
    if entropy < 1.0:
        return 'Very Low'
    elif entropy < 2.5:
        return 'Low'
    elif entropy < 4.0:
        return 'Medium'
    elif entropy < 5.5:
        return 'High'
    else:
        return 'Very High'


def analyze_cookie_privacy(cookie: Dict) -> Dict:
    """
    Analyse complète vie privée d'un cookie.
    
    Args:
        cookie: Dictionnaire contenant les données du cookie
        
    Returns:
        Dictionnaire avec toutes les métriques vie privée
    """
    value = cookie.get('value', '')
    domain = cookie.get('domain', '')
    
    # Calcul de l'entropie
    entropy = calculate_entropy(value)
    entropy_level = classify_entropy_level(entropy)
    
    # Décodage
    decoded_value, decode_method, decode_success = decode_value(value)
    
    # Détection du type de données
    data_type = detect_data_type(value, decoded_value if decode_success else None)
    
    # Extraction du vendor
    vendor = extract_vendor_from_domain(domain)
    
    return {
        'entropy': entropy,
        'entropy_level': entropy_level,
        'decoded_value': decoded_value if decode_success else None,
        'decode_method': decode_method,
        'decode_success': decode_success,
        'data_type': data_type,
        'vendor': vendor,
        'is_unique_identifier': data_type in ['uuid', 'uuid_compact', 'token_id', 'email'],
        'tracking_potential': 'High' if entropy > 4.0 and data_type in ['uuid', 'token_id'] else 
                             'Medium' if entropy > 2.5 else 'Low'
    }
