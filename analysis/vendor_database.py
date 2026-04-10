#!/usr/bin/env python3
"""
Base de données des vendors de tracking 

1. WhoTracks.Me - Tracker Database (https://whotracks.me/)
2. Cookiepedia - Cookie Database (https://cookiepedia.co.uk/)
3. Ghostery Tracker Database
4. IAB Tech Lab - Ads.txt Specification
"""

VENDOR_MAPPING_EXTENDED = {
    # ========================================================================
    # GOOGLE ECOSYSTEM
    # ========================================================================
    'google.com': 'Google',
    'google.fr': 'Google',
    'google.de': 'Google',
    'google.co.uk': 'Google',
    'doubleclick.net': 'Google',
    'googlesyndication.com': 'Google',
    'googleadservices.com': 'Google',
    'youtube.com': 'Google',
    'gstatic.com': 'Google',
    'googleapis.com': 'Google',
    'google-analytics.com': 'Google',
    'googletagmanager.com': 'Google',
    'googleusercontent.com': 'Google',
    'ggpht.com': 'Google',
    'ytimg.com': 'Google',
    
    # ========================================================================
    # META/FACEBOOK
    # ========================================================================
    'facebook.com': 'Meta',
    'facebook.net': 'Meta',
    'fbcdn.net': 'Meta',
    'instagram.com': 'Meta',
    'whatsapp.com': 'Meta',
    'connect.facebook.net': 'Meta',
    'messenger.com': 'Meta',
    
    # ========================================================================
    # AMAZON
    # ========================================================================
    'amazon.com': 'Amazon',
    'amazon.fr': 'Amazon',
    'amazon.de': 'Amazon',
    'amazon.co.uk': 'Amazon',
    'amazonaws.com': 'Amazon',
    'amazon-adsystem.com': 'Amazon',
    'cloudfront.net': 'Amazon CloudFront',
    
    # ========================================================================
    # MICROSOFT
    # ========================================================================
    'microsoft.com': 'Microsoft',
    'live.com': 'Microsoft',
    'bing.com': 'Microsoft',
    'msn.com': 'Microsoft',
    'linkedin.com': 'Microsoft',
    'clarity.ms': 'Microsoft',
    'office.com': 'Microsoft',
    'windows.net': 'Microsoft',
    
    # ========================================================================
    # ADVERTISING/TRACKING (Top 50 selon WhoTracks.Me 2024)
    # ========================================================================
    
    # Criteo
    'criteo.com': 'Criteo',
    'criteo.net': 'Criteo',
    
    # Taboola
    'taboola.com': 'Taboola',
    'trc.taboola.com': 'Taboola',
    
    # Outbrain
    'outbrain.com': 'Outbrain',
    'widgets.outbrain.com': 'Outbrain',
    
    # PubMatic
    'pubmatic.com': 'PubMatic',
    
    # Rubicon Project
    'rubiconproject.com': 'Rubicon',
    'rubiconproject.net': 'Rubicon',
    
    # Adform
    'adform.net': 'Adform',
    'adform.com': 'Adform',
    
    # Smart AdServer
    'smartadserver.com': 'Smart AdServer',
    'smartadserver.fr': 'Smart AdServer',
    
    # Xandr (AppNexus)
    'appnexus.com': 'Xandr',
    'adnxs.com': 'Xandr',
    
    # OpenX
    'openx.com': 'OpenX',
    'openx.net': 'OpenX',
    
    # Index Exchange
    'indexexchange.com': 'Index Exchange',
    'casalemedia.com': 'Index Exchange',
    
    # Teads
    'teads.tv': 'Teads',
    'teads.com': 'Teads',
    
    # Verizon Media
    'advertising.com': 'Verizon Media',
    'oath.com': 'Verizon Media',
    
    # The Trade Desk
    'adsrvr.org': 'The Trade Desk',
    'thetradedesk.com': 'The Trade Desk',
    
    # PulsePoint
    'contextweb.com': 'PulsePoint',
    'pulsepoint.com': 'PulsePoint',
    
    # Sharethrough
    'sharethrough.com': 'Sharethrough',
    
    # Sovrn
    'sovrn.com': 'Sovrn',
    'lijit.com': 'Sovrn',
    
    # Improve Digital
    'improvedigital.com': 'Improve Digital',
    
    # ========================================================================
    # ANALYTICS
    # Source: WhoTracks.Me, Ghostery
    # ========================================================================
    
    # Hotjar
    'hotjar.com': 'Hotjar',
    'hotjar.io': 'Hotjar',
    
    # Mixpanel
    'mixpanel.com': 'Mixpanel',
    
    # Segment
    'segment.com': 'Segment',
    'segment.io': 'Segment',
    
    # Amplitude
    'amplitude.com': 'Amplitude',
    
    # Chartbeat
    'chartbeat.com': 'Chartbeat',
    'chartbeat.net': 'Chartbeat',
    
    # Contentsquare
    'contentsquare.net': 'Contentsquare',
    'contentsquare.com': 'Contentsquare',
    
    # New Relic
    'newrelic.com': 'New Relic',
    'nr-data.net': 'New Relic',
    
    # Sentry
    'sentry.io': 'Sentry',
    
    # Bugsnag
    'bugsnag.com': 'Bugsnag',
    
    # FullStory
    'fullstory.com': 'FullStory',
    
    # LogRocket
    'logrocket.com': 'LogRocket',
    'logrocket.io': 'LogRocket',
    
    # Mouseflow
    'mouseflow.com': 'Mouseflow',
    
    # Crazy Egg
    'crazyegg.com': 'Crazy Egg',
    
    # ========================================================================
    # CDN/INFRASTRUCTURE
    # ========================================================================
    'cloudflare.com': 'Cloudflare',
    'akamai.net': 'Akamai',
    'akamaihd.net': 'Akamai',
    'fastly.net': 'Fastly',
    
    # ========================================================================
    # TAG MANAGEMENT
    # ========================================================================
    'tealium.com': 'Tealium',
    'ensighten.com': 'Ensighten',
    'tagcommander.com': 'Commanders Act',
    
    # ========================================================================
    # CONSENT MANAGEMENT PLATFORMS (CMP)
    # ========================================================================
    'didomi.io': 'Didomi',
    'onetrust.com': 'OneTrust',
    'cookiebot.com': 'Cookiebot',
    'quantcast.com': 'Quantcast',
    'trustarc.com': 'TrustArc',
    'usercentrics.com': 'Usercentrics',
    
    # ========================================================================
    # SOCIAL MEDIA
    # ========================================================================
    'twitter.com': 'Twitter',
    'twimg.com': 'Twitter',
    'tiktok.com': 'TikTok',
    'pinterest.com': 'Pinterest',
    'snapchat.com': 'Snapchat',
    'reddit.com': 'Reddit',
    
    # ========================================================================
    # A/B TESTING & PERSONALIZATION
    # ========================================================================
    'optimizely.com': 'Optimizely',
    'abtasty.com': 'AB Tasty',
    'vwo.com': 'VWO',
    'kameleoon.com': 'Kameleoon',
    
    # ========================================================================
    # CUSTOMER DATA PLATFORMS (CDP)
    # ========================================================================
    'salesforce.com': 'Salesforce',
    'pardot.com': 'Salesforce',
    'hubspot.com': 'HubSpot',
    'hubspot.net': 'HubSpot',
    
    # ========================================================================
    # FRENCH PUBLISHERS & ADTECH
    # ========================================================================
    'weborama.fr': 'Weborama',
    'weborama.com': 'Weborama',
    'rossel.be': 'Rossel',
    'piano.io': 'Piano',
    'atinternet.com': 'AT Internet',
    'xiti.com': 'AT Internet',
}


# Vendors considérés comme "tracking" (liste étendue)
TRACKING_VENDORS = {
    'Google', 'Meta', 'Criteo', 'Taboola', 'Outbrain',
    'PubMatic', 'Rubicon', 'Adform', 'Smart AdServer', 'Xandr',
    'OpenX', 'Index Exchange', 'Teads', 'Verizon Media',
    'The Trade Desk', 'PulsePoint', 'Sharethrough', 'Sovrn',
    'Improve Digital', 'Hotjar', 'Mixpanel', 'Segment',
    'Amplitude', 'Chartbeat', 'Contentsquare', 'FullStory',
    'LogRocket', 'Mouseflow', 'Crazy Egg', 'Optimizely',
    'AB Tasty', 'VWO', 'Kameleoon', 'Weborama', 'AT Internet'
}


# Mots-clés de tracking (étendu et défendable)
TRACKING_KEYWORDS = [
    # Advertising
    'ads', 'ad-', 'adserver', 'advertising', 'adtech', 'advert',
    'doubleclick', 'adsystem', 'adnxs', 'adsrvr',
    
    # Analytics
    'analytics', 'tracking', 'tracker', 'telemetry', 'metrics',
    'stats', 'statistic', 'monitor', 'insight',
    
    # Pixels & Tags
    'pixel', 'tag', 'beacon', 'collect', 'event',
    
    # Specific vendors (partial matches)
    'facebook', 'fbcdn', 'criteo', 'taboola', 'outbrain',
    'pubmatic', 'rubiconproject', 'smartadserver', 'hotjar',
    'mixpanel', 'segment', 'amplitude', 'chartbeat',
    'contentsquare', 'tealium', 'ensighten',
    
    # Syndication
    'syndication', 'syndicate', 'exchange', 'bidder',
    
    # User identification
    'fingerprint', 'identify', 'userid', 'visitor',
]


def extract_vendor_from_domain(domain: str) -> str:
    """
    Extrait le vendor  partir d'un domaine.
    Utilise VENDOR_MAPPING_EXTENDED.
    
    Args:
        domain: Domaine (ex: '.doubleclick.net')
    
    Returns:
        Nom du vendor (ex: 'Google')
    """
    # Nettoyer le domaine
    clean_domain = domain.lower().lstrip('.')
    
    # Recherche exacte
    if clean_domain in VENDOR_MAPPING_EXTENDED:
        return VENDOR_MAPPING_EXTENDED[clean_domain]
    
    # Recherche par sous-domaine
    for vendor_domain, vendor_name in VENDOR_MAPPING_EXTENDED.items():
        if clean_domain.endswith(vendor_domain):
            return vendor_name
    
    # Si pas trouvé, retourner le domaine principal
    parts = clean_domain.split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    
    return clean_domain


def is_tracking_domain(domain: str) -> bool:
    """
    Vérifie si un domaine est un domaine de tracking.
    
    Args:
        domain: Domaine  vérifier
    
    Returns:
        True si domaine de tracking
    """
    domain_lower = domain.lower()
    
    return any(keyword in domain_lower for keyword in TRACKING_KEYWORDS)
