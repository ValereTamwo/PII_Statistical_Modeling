"""
Pattern Matcher - Helper module to use regex.py patterns for profile reconstruction
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

# Regex pattern external source management
scripts_path = Path(__file__).parent.parent.parent / 'scripts'
sys.path.insert(0, str(scripts_path))

# Import from our custom regex.py
import regex as custom_regex
TRACKING_PATTERNS_COMPLETE = custom_regex.TRACKING_PATTERNS_COMPLETE

# Remove from path to avoid conflicts
sys.path.remove(str(scripts_path))


class PatternMatcher:
    """Helper class to match keys/values against regex patterns"""
    
    def __init__(self):
        self.patterns = TRACKING_PATTERNS_COMPLETE
        # Pattern pre-compilation
        self._compiled_patterns = {}
        self._compile_all_patterns()
    
    def _compile_all_patterns(self):
        """Pre-compile all regex patterns for performance"""
        for category, patterns_dict in self.patterns.items():
            if category == 'DIRECT_PII':
                # DIRECT_PII is a list (per user), skip for now
                continue
            
            if not isinstance(patterns_dict, dict):
                continue
            
            self._compiled_patterns[category] = {}
            for pattern_name, pattern in patterns_dict.items():
                try:
                    self._compiled_patterns[category][pattern_name] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    print(f"Warning: Failed to compile pattern {category}.{pattern_name}: {e}")
    
    def matches_category(self, key: str, category: str) -> bool:
        """
        Check if a key matches any pattern in a category
        
        Args:
            key: The key to match
            category: The category name (e.g., 'NAVIGATION_HISTORY')
        
        Returns:
            True if key matches any pattern in the category
        """
        if category not in self._compiled_patterns:
            return False
        
        for pattern_name, compiled_pattern in self._compiled_patterns[category].items():
            if compiled_pattern.search(key):
                return True
        
        return False
    
    def get_matching_subcategory(self, key: str, category: str) -> Optional[str]:
        """
        Get the specific subcategory that matches the key
        
        Args:
            key: The key to match
            category: The category name
        
        Returns:
            The subcategory name (e.g., 'referrer_data') or None
        """
        if category not in self._compiled_patterns:
            return None
        
        for pattern_name, compiled_pattern in self._compiled_patterns[category].items():
            if compiled_pattern.search(key):
                return pattern_name
        
        return None
    
    # Navigation History specialized matchers
    
    def is_navigation_history(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is navigation history"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'NAVIGATION_HISTORY')
        return subcategory in ['explicit_history', 'breadcrumb', 'journey_flow', 'path_tracking']
    
    def is_page_view(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is page view tracking"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'NAVIGATION_HISTORY')
        return subcategory in ['page_tracking']
    
    def is_referrer(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is referrer data"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'NAVIGATION_HISTORY')
        return subcategory in ['referrer_data', 'embedded_urls']
    
    # Behavioral Data specialized matchers
    
    def is_click_tracking(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is click tracking"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'BEHAVIORAL_DATA')
        return subcategory in ['click_tracking', 'interaction_tracking']
    
    def is_scroll_tracking(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is scroll tracking"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'BEHAVIORAL_DATA')
        return subcategory == 'scroll_tracking'
    
    def is_time_tracking(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is time/timing tracking"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'BEHAVIORAL_DATA')
        return subcategory in ['timing_metrics', 'timestamp_key']
    
    # User Preferences specialized matchers
    
    def is_language_preference(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is language preference"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'USER_PREFERENCES')
        return subcategory == 'language'
    
    def is_theme_preference(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is theme preference"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'USER_PREFERENCES')
        return subcategory == 'theme'
    
    def is_notification_preference(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is notification preference"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'USER_PREFERENCES')
        return subcategory == 'notifications'
    
    # Demographics specialized matchers
    
    def is_timezone(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is timezone"""
        if subcategory:
            return subcategory == 'time_zone' or (subcategory == 'general_loc' and key and 'timezone' in key.lower())
        
        if key:
            # Check both LOCATION_AND_DEMOGRAPHICS and DEVICE_ENV
            subcategory_loc = self.get_matching_subcategory(key, 'LOCATION_AND_DEMOGRAPHICS')
            subcategory_dev = self.get_matching_subcategory(key, 'DEVICE_ENV')
            return (subcategory_loc == 'general_loc' and 'timezone' in key.lower()) or \
                   (subcategory_dev == 'time_zone')
        return False
    
    def is_location(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is location data"""
        if subcategory:
            return subcategory in ['precise_coords', 'general_loc', 'geolocation', 'location_data']
        if key:
            return self.matches_category(key, 'LOCATION_AND_DEMOGRAPHICS') or \
                   self.matches_category(key, 'SENSITIVE_LOCATION_PII')
        return False
    
    # Identification specialized matchers
    
    def is_email_key(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is email"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'DIRECT_PII_KEYS')
        return subcategory in ['email_key', 'email_exact', 'email_encoded']
    
    def is_phone_key(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is phone"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'DIRECT_PII_KEYS')
        return subcategory in ['phone_key', 'phone_full', 'phone_national']
    
    def is_name_key(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is name"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'DIRECT_PII_KEYS')
        return subcategory in ['first_name_key', 'last_name_key', 'full_name_key', 'full_name', 'first_name', 'last_name']
    
    def is_address_key(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is address"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'DIRECT_PII_KEYS')
        return subcategory in ['address_key', 'city_key', 'postal_code_key', 'country_key', 'address_full', 'city']
    
    def is_birthdate_key(self, key: str = None, subcategory: str = None) -> bool:
        """Check if key or subcategory is birthdate"""
        if not subcategory and key:
            subcategory = self.get_matching_subcategory(key, 'DIRECT_PII_KEYS')
        return subcategory in ['birthdate_key', 'birth_year_key', 'birth_month_key', 'birth_day_key', 'birth_date_slash', 'birth_date_iso']


# Global instance for easy import
pattern_matcher = PatternMatcher()
