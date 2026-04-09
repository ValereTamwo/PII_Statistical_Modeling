#!/usr/bin/env python3
"""
MODULE  SCORE DE RISQUE RGPD UNIFIÉ (VERSION  RIGUEUR FORMELLE)


Ce score est :
- ORDINAL (comparatif)
- HEURISTIQUE (risk-based, non probabiliste)
- DISCRET (points entiers)

Il ne constitue PAS une mesure légale de non-conformité,
mais un outil daide  laudit et  la priorisation RGPD.

Inspiré :
- RGPD (art. 4, 24, 25, 32)
- Lignes directrices EDPB (identifiabilité, linkabilité)
- Analyse technique des stockages web modernes
"""

from pathlib import Path
from typing import Dict, Tuple, NamedTuple
from urllib.parse import urlparse
import sys

# =====================================================================
# IMPORTS INTERNES
# =====================================================================

sys.path.insert(0, str(Path(__file__).parent))

from privacy_metrics import (
    calculate_entropy,
    is_third_party
)

from vendor_database import (
    extract_vendor_from_domain,
    is_tracking_domain,
    TRACKING_VENDORS
)

# =====================================================================
# DIMENSION 1  SENSIBILITÉ DU CONTENU (04)
# =====================================================================

CATEGORY_SEVERITY_POINTS = {
    # Identification directe
    'DIRECT_PII': 3,

    # Identification indirecte forte
    'IDENTITY_TRACKING': 2,
    'ID_SOLUTIONS_AND_EXCHANGES': 2,
    'FINGERPRINTING_ADVANCED': 2,
    'SERVER_SIDE_TRACKING': 2,
    'SUSPICIOUS_VALUES': 2,
    'SESSION_MANAGEMENT': 2,

    # Données corrélables
    'BEHAVIORAL_DATA': 1,
    'NAVIGATION_HISTORY': 1,
    'DEVICE_ENV': 1,
    'UX_AND_PERFORMANCE_ANALYTICS': 1,
    'USER_PREFERENCES': 1,
    'USER_PREFERENCES_EXTENDED': 1,
    'TELEMETRY_AND_ERRORS': 1,
    'CONSENT_AND_PRIVACY': 1,

    # Techniques / neutres
    'SECURITY_AND_BOT_MITIGATION': 0,
    'APP_STATE_STORAGE': 0,
    'INFRASTRUCTURE': 0,
    'CUSTOMER_INTERACTION': 0,
    'UNCATEGORIZED': 0
}

SUBCATEGORY_WEIGHTS = {

    # =========================
    # NAVIGATION HISTORY
    # =========================
    'NAVIGATION_HISTORY': {
        'explicit_history': 3,
        'breadcrumb': 1,
        'referrer_data': 2,
        'journey_flow': 3,
        'campaign_tags': 0,
        'hash_history': 0,
        'navigation_timestamps': 1,
        'embedded_urls': 2,
    },

    # =========================
    # BEHAVIORAL DATA
    # =========================
    'BEHAVIORAL_DATA': {
        'mouse_tracking': 0,
        'click_tracking': 1,
        'scroll_tracking': 0,
        'timing_metrics': 1,
        'input_logging': 3,

        'vendor_hotjar': 2,
        'vendor_clarity': 2,
        'vendor_fullstory': 2,
        'vendor_crazyegg': 2,
        'vendor_logrocket': 2,
        'vendor_mouseflow': 2,

        'tab_focus': 1,
        'viewport_tracking': 1,
        'touch_tracking': 1,

        'google_telemetry': 1,
        'usage_telemetry': 2,
    },

    # =========================
    # APP STATE STORAGE
    # =========================
    'APP_STATE_STORAGE': {
        'redux_state': 0,
        'vue_state': 0,
        'ngrx_state': 0,

        'firebase_auth': 2,
        'apollo_cache': 1,
        'cart_data': 1,
        'pwa_indexeddb': 1,
        'user_preferences': 1,
    },

    # =========================
    # SUSPICIOUS VALUES
    # =========================
    'SUSPICIOUS_VALUES': {
        'url_list': 2,
        'base64_json': 2,
        'php_serialized': 1,
        'uuid_format': 2,
        'geo_coordinates': 3,
        'jwt_token': 3,
        'auth_tokens': 3,
    },

    # =========================
    # DEVICE ENV
    # =========================
    'DEVICE_ENV': {
        'os_browser': 1,
        'screen_resolution': 0,
        'language': 0,
        'youtube_device': 1,
        'device_memory': 1,
        'time_zone': 1,
        'plugins_mime': 2,
        'touch_support': 1,
        'browser_info': 2,
    },

    # =========================
    # TELEMETRY & ERRORS
    # =========================
    'TELEMETRY_AND_ERRORS': {
        'sentry_keys': 1,
        'newrelic': 1,
        'datadog': 1,
        'bugsnag': 1,
        'performance_metrics': 0,
    },

    # =========================
    # CONSENT & PRIVACY
    # =========================
    'CONSENT_AND_PRIVACY': {
        'tcf_v2': 2,
        'ccpa_gpp': 2,
        'google_consent': 2,
        'trust_commander': 1,
        'didomi': 1,
        'cmp_generic': 1,
        'consent_management': 1,
        'optanon': 1,
        'cookie_notice': 0,
    },

    # =========================
    # SERVER SIDE TRACKING
    # =========================
    'SERVER_SIDE_TRACKING': {
        'facebook_capi': 3,
        'google_enhanced': 3,
    },

    # =========================
    # USER PREFERENCES EXTENDED
    # =========================
    'USER_PREFERENCES_EXTENDED': {
        'cmp_vendors_specific': 1,
        'ab_testing_state': 1,
        'user_config_storage': 2,
        'preference_endpoints': 2,
        'persistence_vectors': 3,
        'abtasty': 1,
    },

    # =========================
    # USER PREFERENCES
    # =========================
    'USER_PREFERENCES': {
        'theme': 0,
        'language': 0,
        'notifications': 1,
        'privacy': 2,
        'layout': 1,
        'other_settings': 1,
    },

    # =========================
    # UX & PERFORMANCE ANALYTICS
    # =========================
    'UX_AND_PERFORMANCE_ANALYTICS': {
        'contentsquare': 2,
        'chartbeat': 1,
        'datadog': 1,
        'appdynamics': 1,
        'hotjar_clarity': 2,
        'ab_testing_generic': 1,
        'tealium': 2,
        'piano_analytics': 2,
        'atinternet': 2,
    },

    # =========================
    # SECURITY & BOT MITIGATION
    # =========================
    'SECURITY_AND_BOT_MITIGATION': {
        'cloudflare': 1,
        'recaptcha_google': 1,
        'anti_csrf': 0,
        'imperva_incapsula': 1,
        'datadome': 1,
        'akamai_bot': 1,
        'auth_security': 2,
        'oauth': 2,
        'dtm_token': 1,
    },

    # =========================
    # SESSION MANAGEMENT
    # =========================
    'SESSION_MANAGEMENT': {
        'php_session': 2,
        'java_session': 2,
        'generic_session': 1,
        'asp_session': 2,
    },

    # =========================
    # INFRASTRUCTURE
    # =========================
    'INFRASTRUCTURE': {
        'load_balancer': 0,
        'cdn': 0,
        'idb_structure_keys': 0,
    },

    # =========================
    # CUSTOMER INTERACTION
    # =========================
    'CUSTOMER_INTERACTION': {
        'chat_support': 2,
        'marketing_overlays': 1,
        'feedback_tools': 1,
    },
}



STORAGE_TYPE_WEIGHTS = {
    'cookies': 1.0,
    'localstorage': 1.0,
    'sessionstorage': 0.9,
    'indexeddb': 1.0
}


class EntropyAssessment(NamedTuple):
    confirmatory: bool
    reason: str


def interpret_entropy_in_context(entropy: float, category: str, value: str) -> EntropyAssessment:
    """
    Lentropie ne crée jamais le risque.
    Elle confirme ou renforce une gravité existante.
    """
    if category == 'DIRECT_PII':
        if entropy > 5.5 and len(value) > 50:
            return EntropyAssessment(True, "PII directe encodée/hachée")

    if category in {
        'IDENTITY_TRACKING',
        'ID_SOLUTIONS_AND_EXCHANGES',
        'FINGERPRINTING_ADVANCED',
        'SUSPICIOUS_VALUES',
        'SESSION_MANAGEMENT'
    }:
        if entropy > 4.5:
            return EntropyAssessment(True, "Identifiant ou token  forte entropie")

    if category in {'BEHAVIORAL_DATA', 'NAVIGATION_HISTORY'}:
        if entropy > 5.0 and len(value) > 200:
            return EntropyAssessment(True, "Données comportementales riches")

    return EntropyAssessment(False, "")


from typing import Dict, Tuple

MAX_CATEGORY_SCORE = 4
FIXED_MAX_SCORE_CATEGORIES = {'DIRECT_PII', 'IDENTITY_TRACKING', 'ID_SOLUTIONS_AND_EXCHANGES'}

CATEGORY_BASE_SCORE = {
    'BEHAVIORAL_DATA': 1,              
    'NAVIGATION_HISTORY': 1,           
    'TELEMETRY_AND_ERRORS': 0,         
    'DEVICE_ENV': 0,                   
    'APP_STATE_STORAGE': 0,            
    'USER_PREFERENCES': 0,             
    'USER_PREFERENCES_EXTENDED': 1,    
    'UX_AND_PERFORMANCE_ANALYTICS': 1, 
    'SECURITY_AND_BOT_MITIGATION': 1,
    'SESSION_MANAGEMENT': 1,
    'SERVER_SIDE_TRACKING': 2,
    'FINGERPRINTING_ADVANCED': 3,
    'CONSENT_AND_PRIVACY': 0,
    'INFRASTRUCTURE': 0,
    'CUSTOMER_INTERACTION': 1,         
    'SUSPICIOUS_VALUES': 2,            
}

def calculate_content_sensitivity_score(item: Dict) -> Tuple[int, str]:
    """
    Renvoie un score de sensibilité et une explication,
    basé sur la catégorie et la sous-catégorie ayant permis le match.
    """

    # 1 Récupération des infos de l'item
    category = item.get('_category', item.get('_primary_category', 'UNCATEGORIZED'))
    matched_subcategory = item.get('matched_subcategory')

    reasons = []

    # 2 Si catégorie FIXE  score max
    if category in FIXED_MAX_SCORE_CATEGORIES:
        reasons.append(f"Catégorie {category} (score fixe maximal)")
        return MAX_CATEGORY_SCORE, "; ".join(reasons)

    # 3 Base score + poids sous-catégorie
    base_score = CATEGORY_BASE_SCORE.get(category, 0)
    weight = 0

    if matched_subcategory:
        weight = SUBCATEGORY_WEIGHTS.get(category, {}).get(matched_subcategory, 0)
        reasons.append(f"Catégorie {category}, sous-catégorie {matched_subcategory} (poids {weight})")

    score = min(MAX_CATEGORY_SCORE, base_score + weight)

    # 4 Retour final
    if score == 0:
        reasons.append("Pas de contenu sensible identifié")

    return score, "; ".join(reasons)



# =====================================================================
# DIMENSION 2  EXPOSITION TECHNIQUE (03)
# =====================================================================

def calculate_exposure_score(item: Dict, storage_type: str) -> Tuple[int, str]:
    score = 0
    reasons = []

    if storage_type.lower() == 'cookies':
        if not item.get('httpOnly', False):
            score += 1
            reasons.append("Accessible JavaScript (XSS)")
        if not item.get('secure', False):
            score += 1
            reasons.append("Transmission non chiffrée (HTTP)")
        if item.get('sameSite', '').lower() in ('none', ''):
            score += 1
            reasons.append("SameSite=None (CSRF)")

    else:
        score = 2
        reasons.append("Stockage accessible JavaScript (XSS)")

    return min(3, score), "; ".join(reasons) or "Exposition minimale"


# =====================================================================
# DIMENSION 3  PERSISTANCE (02)
# =====================================================================

def calculate_persistence_score(item: Dict, storage_type: str) -> Tuple[int, str]:
    """Calcule le score de persistance basé sur la durée restante du cookie
    
    Args:
        item: Dictionnaire contenant les informations du cookie/storage
        storage_type: Type de stockage ('cookies', 'localstorage', etc.)
    
    Returns:
        Tuple (score, raison)
    """
    from datetime import datetime
    
    if storage_type.lower() == 'cookies':
        expires = item.get('expires')
        collection_timestamp = item.get('timestamp')
        
        # Convertir le timestamp de collecte si c'est une chaîne
        if isinstance(collection_timestamp, str):
            try:
                # Essayer de parser comme ISO format
                collection_timestamp = datetime.fromisoformat(
                    collection_timestamp.replace('Z', '+00:00')
                ).timestamp()
            except (ValueError, AttributeError):
                try:
                    # Essayer comme timestamp numérique en chaîne
                    collection_timestamp = float(collection_timestamp)
                except (ValueError, TypeError):
                    collection_timestamp = None
        
        if expires:
            try:
                # Utiliser le timestamp de collecte si disponible, sinon utiliser le temps actuel
                reference_time = collection_timestamp if collection_timestamp else datetime.now().timestamp()
                
                # Calculer la durée restante en secondes
                duration_seconds = float(expires) - reference_time
                
                # Si déj expiré au moment de la collecte
                if duration_seconds <= 0:
                    days_expired = abs(duration_seconds) / 86400
                    return 0, f"Cookie expiré depuis {int(days_expired)} jours"
                
                # Convertir en jours
                days = duration_seconds / 86400
                
                if days > 365:
                    return 2, f"Durée >1 an ({int(days)} jours)"
                if days >= 30:
                    return 1, f"Durée 30j1an ({int(days)} jours)"
                
                # Cookie de courte durée mais pas de session
                return 0, f"Courte durée ({int(days)} jours)"
                
            except (ValueError, TypeError) as e:
                # Log l'erreur si vous avez un systme de logging
                return 0, f"Erreur de calcul: {str(e)}"
        
        # Pas d'attribut expires = cookie de session
        return 0, "Cookie de session (pas d'expiration)"

    if storage_type.lower() in ('localstorage', 'indexeddb'):
        return 2, "Persistant sans limite temporelle"

    return 0, "Session uniquement"

# =====================================================================
# DIMENSION 4  CONTEXTE TIERS (02)
# =====================================================================

def calculate_third_party_score(item: Dict, storage_type: str) -> Tuple[int, str]:
    domain = ""
    initial_url = item.get('initial_url', "")

    if storage_type.lower() == 'cookies':
        domain = item.get('domain', "")
        if domain and initial_url:
            if is_third_party(domain, initial_url):
                vendor = extract_vendor_from_domain(domain)
                if vendor in TRACKING_VENDORS:
                    return 2, f"Vendor tracking ({vendor})"
                return 1, f"Domaine tiers ({domain})"
        return 0, "First-party"

    if initial_url:
        parsed = urlparse(initial_url)
        domain = parsed.netloc.lower()
        vendor = extract_vendor_from_domain(domain)
        if vendor in TRACKING_VENDORS:
            return 2, f"Vendor tracking ({vendor})"
        if is_tracking_domain(domain):
            return 1, f"Domaine tiers ({domain})"

    return 0, "First-party"


# =====================================================================
# SCORE GLOBAL (011)
# =====================================================================

def calculate_unified_risk_score(item: Dict, storage_type: str) -> Dict:
    content, c_reason = calculate_content_sensitivity_score(item)
    exposure, e_reason = calculate_exposure_score(item, storage_type)
    persistence, p_reason = calculate_persistence_score(item, storage_type)
    third_party, t_reason = calculate_third_party_score(item, storage_type)

    total = content + exposure + persistence + third_party

    if total >= 9:
        category = "Critical Risk"
    elif total >= 6:
        category = "High Risk"
    elif total >= 3:
        category = "Medium Risk"
    else:
        category = "Low Risk"

    return {
        "total_score": total,
        "risk_category": category,
        "dimension_scores": {
            "content_sensitivity": content,
            "exposure": exposure,
            "persistence": persistence,
            "third_party_context": third_party
        },
        "justifications": {
            "content_sensitivity": c_reason,
            "exposure": e_reason,
            "persistence": p_reason,
            "third_party_context": t_reason
        }
    }
