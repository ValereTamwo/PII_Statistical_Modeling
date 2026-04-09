"""
Test script to compare profile reconstruction before/after pattern matcher improvements
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

sys.path.append(str(Path(__file__).parent))
from pattern_matcher import pattern_matcher
from utils import load_all_user_data, filter_by_category, get_storage_key

def test_pattern_matching():
    """Test pattern matching on real data"""
    
    print("="*80)
    print("TESTING PATTERN MATCHER ON REAL DATA")
    print("="*80)
    
    # Load data for one user
    base_path = Path(__file__).parent.parent.parent / 'data' / 'user'
    nav_mode = 'Auth'
    user_id = 'FR_0417'
    policy = 'ALL'
    
    print(f"\nLoading data for: {nav_mode}/{user_id}/{policy}")
    
    all_data = load_all_user_data(str(base_path), nav_mode, user_id, policy)
    
    # Test on NAVIGATION_HISTORY items
    print("\n" + "="*80)
    print("NAVIGATION HISTORY ITEMS")
    print("="*80)
    
    nav_items = filter_by_category(list(all_data.values())[0] if all_data.values() else [], 'NAVIGATION_HISTORY')
    
    if not nav_items:
        # Try to get all items and filter manually
        all_items = []
        for items in all_data.values():
            all_items.extend(items)
        
        nav_items = filter_by_category(all_items, 'NAVIGATION_HISTORY')
    
    print(f"\nTotal NAVIGATION_HISTORY items: {len(nav_items)}")
    
    # Categorize with pattern matcher
    categorized = {
        'navigation_history': [],
        'page_views': [],
        'referrers': [],
        'other': []
    }
    
    for item in nav_items[:20]:  # Test first 20
        key = get_storage_key(item)
        
        if pattern_matcher.is_navigation_history(key):
            categorized['navigation_history'].append(key)
        elif pattern_matcher.is_page_view(key):
            categorized['page_views'].append(key)
        elif pattern_matcher.is_referrer(key):
            categorized['referrers'].append(key)
        else:
            categorized['other'].append(key)
    
    print(f"\nCategorization results (first 20 items):")
    print(f"  Navigation history: {len(categorized['navigation_history'])}")
    print(f"  Page views: {len(categorized['page_views'])}")
    print(f"  Referrers: {len(categorized['referrers'])}")
    print(f"  Other: {len(categorized['other'])}")
    
    # Show examples
    print(f"\nExamples of Navigation History:")
    for key in categorized['navigation_history'][:5]:
        print(f"  - {key}")
    
    print(f"\nExamples of Page Views:")
    for key in categorized['page_views'][:5]:
        print(f"  - {key}")
    
    print(f"\nExamples of Referrers:")
    for key in categorized['referrers'][:5]:
        print(f"  - {key}")
    
    # Test on BEHAVIORAL_DATA items
    print("\n" + "="*80)
    print("BEHAVIORAL DATA ITEMS")
    print("="*80)
    
    all_items = []
    for items in all_data.values():
        all_items.extend(items)
    
    behavioral_items = filter_by_category(all_items, 'BEHAVIORAL_DATA')
    print(f"\nTotal BEHAVIORAL_DATA items: {len(behavioral_items)}")
    
    # Categorize with pattern matcher
    behavioral_categorized = {
        'clicks': [],
        'scrolls': [],
        'time_tracking': [],
        'other': []
    }
    
    for item in behavioral_items[:20]:  # Test first 20
        key = get_storage_key(item)
        
        if pattern_matcher.is_click_tracking(key):
            behavioral_categorized['clicks'].append(key)
        elif pattern_matcher.is_scroll_tracking(key):
            behavioral_categorized['scrolls'].append(key)
        elif pattern_matcher.is_time_tracking(key):
            behavioral_categorized['time_tracking'].append(key)
        else:
            behavioral_categorized['other'].append(key)
    
    print(f"\nCategorization results (first 20 items):")
    print(f"  Clicks: {len(behavioral_categorized['clicks'])}")
    print(f"  Scrolls: {len(behavioral_categorized['scrolls'])}")
    print(f"  Time tracking: {len(behavioral_categorized['time_tracking'])}")
    print(f"  Other: {len(behavioral_categorized['other'])}")
    
    # Show examples
    print(f"\nExamples of Click Tracking:")
    for key in behavioral_categorized['clicks'][:5]:
        print(f"  - {key}")
    
    print(f"\nExamples of Time Tracking:")
    for key in behavioral_categorized['time_tracking'][:5]:
        print(f"  - {key}")
    
    # Test on USER_PREFERENCES items
    print("\n" + "="*80)
    print("USER PREFERENCES ITEMS")
    print("="*80)
    
    pref_items = filter_by_category(all_items, 'USER_PREFERENCES')
    print(f"\nTotal USER_PREFERENCES items: {len(pref_items)}")
    
    # Categorize with pattern matcher
    pref_categorized = {
        'language': [],
        'theme': [],
        'notifications': [],
        'other': []
    }
    
    for item in pref_items[:20]:  # Test first 20
        key = get_storage_key(item)
        
        if pattern_matcher.is_language_preference(key):
            pref_categorized['language'].append(key)
        elif pattern_matcher.is_theme_preference(key):
            pref_categorized['theme'].append(key)
        elif pattern_matcher.is_notification_preference(key):
            pref_categorized['notifications'].append(key)
        else:
            pref_categorized['other'].append(key)
    
    print(f"\nCategorization results (first 20 items):")
    print(f"  Language: {len(pref_categorized['language'])}")
    print(f"  Theme: {len(pref_categorized['theme'])}")
    print(f"  Notifications: {len(pref_categorized['notifications'])}")
    print(f"  Other: {len(pref_categorized['other'])}")
    
    # Show examples
    print(f"\nExamples of Language Preferences:")
    for key in pref_categorized['language'][:5]:
        print(f"  - {key}")
    
    print(f"\nExamples of Theme Preferences:")
    for key in pref_categorized['theme'][:5]:
        print(f"  - {key}")
    
    print("\n" + "="*80)
    print("PATTERN MATCHER TEST COMPLETE")
    print("="*80)


if __name__ == '__main__':
    test_pattern_matching()
