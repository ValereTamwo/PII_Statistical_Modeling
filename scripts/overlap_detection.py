#!/usr/bin/env python3
"""
Utility module for overlap detection in PII pattern matching.

This module provides functions to find all pattern matches with their positions
and remove overlapping matches where shorter matches are entirely contained
within longer ones.
"""

import re
from typing import List, Tuple


def find_all_matches_with_positions(pattern: str, text: str, flags=re.IGNORECASE) -> List[Tuple[str, int, int]]:
    """
    Find all matches of a pattern in text with their positions.
    
    Args:
        pattern: Regular expression pattern to search for
        text: Text to search in
        flags: Regex flags (default: re.IGNORECASE)
    
    Returns:
        List of tuples (match_text, start_pos, end_pos)
        
    Example:
        >>> find_all_matches_with_positions(r'Chris', 'Chris Martin and Chris')
        [('Chris', 0, 5), ('Chris', 17, 22)]
    """
    if not text or not pattern:
        return []
    
    matches = []
    try:
        for match in re.finditer(pattern, text, flags):
            matches.append((match.group(), match.start(), match.end()))
    except re.error:
        # Invalid regex pattern
        return []
    
    return matches


def remove_overlapping_matches(matches: List[Tuple[str, int, int]]) -> List[Tuple[str, int, int]]:
    """
    Remove overlapping matches, keeping only the longest ones.
    
    A match is considered overlapping if it is entirely contained within another match.
    Multiple non-overlapping occurrences at different positions are preserved.
    
    Args:
        matches: List of tuples (match_text, start_pos, end_pos)
    
    Returns:
        Filtered list with overlapping matches removed
        
    Example:
        >>> matches = [
        ...     ('Chris Martin', 0, 12),
        ...     ('Chris', 0, 5),      # Overlaps with 'Chris Martin'
        ...     ('Martin', 6, 12),    # Overlaps with 'Chris Martin'
        ...     ('Chris', 20, 25)     # Different position, keep
        ... ]
        >>> remove_overlapping_matches(matches)
        [('Chris Martin', 0, 12), ('Chris', 20, 25)]
    """
    if not matches:
        return []
    
    # Sort by length (descending) then by start position
    # This ensures we process longer matches first
    sorted_matches = sorted(matches, key=lambda x: (-(x[2] - x[1]), x[1]))
    
    kept_matches = []
    
    for current_match in sorted_matches:
        current_text, current_start, current_end = current_match
        
        # Check if this match is contained within any already kept match
        is_contained = False
        for kept_match in kept_matches:
            kept_text, kept_start, kept_end = kept_match
            
            # Check if current match is entirely within kept match
            if kept_start <= current_start and current_end <= kept_end:
                # Additional check: they must actually overlap, not just be adjacent
                if not (current_start == kept_end or current_end == kept_start):
                    is_contained = True
                    break
        
        if not is_contained:
            kept_matches.append(current_match)
    
    # Sort by position for consistent output
    kept_matches.sort(key=lambda x: x[1])
    
    return kept_matches


def find_deduplicated_matches(pattern: str, text: str, flags=re.IGNORECASE) -> List[Tuple[str, int, int]]:
    """
    Find all matches of a pattern and remove overlapping ones.
    
    This is the main function to use in categorization scripts.
    It combines find_all_matches_with_positions and remove_overlapping_matches.
    
    Args:
        pattern: Regular expression pattern to search for
        text: Text to search in
        flags: Regex flags (default: re.IGNORECASE)
    
    Returns:
        List of non-overlapping matches with positions: [(match_text, start, end), ...]
        
    Example:
        >>> text = "Chris Martin works with Chris and Martin"
        >>> find_deduplicated_matches(r'Chris Martin', text)
        [('Chris Martin', 0, 12)]
        >>> find_deduplicated_matches(r'Chris', text)
        [('Chris', 0, 5), ('Chris', 24, 29)]
    """
    all_matches = find_all_matches_with_positions(pattern, text, flags)
    return remove_overlapping_matches(all_matches)


def collect_all_pii_matches(patterns_dict: dict, text: str) -> List[Tuple[str, str, int, int]]:
    """
    Collect all PII matches from multiple patterns and remove overlaps.
    
    This function is designed for DIRECT_PII detection where we have multiple
    patterns (email, phone, name, etc.) and want to find all matches while
    removing overlaps across different pattern types.
    
    Args:
        patterns_dict: Dictionary of {subcategory: pattern}
        text: Text to search in
    
    Returns:
        List of tuples (subcategory, match_text, start_pos, end_pos)
        
    Example:
        >>> patterns = {
        ...     'email_exact': r'[a-z]+@[a-z]+\\.com',
        ...     'first_name': r'Chris',
        ...     'last_name': r'Martin'
        ... }
        >>> text = "chris.martin@example.com"
        >>> collect_all_pii_matches(patterns, text)
        [('email_exact', 'chris.martin@example.com', 0, 24)]
        # Note: 'Chris' and 'Martin' are removed as they overlap with email
    """
    all_matches = []
    
    # Collect all matches from all patterns
    # Note: text should already be decoded by the caller if needed
    for subcat, pattern in patterns_dict.items():
        matches = find_all_matches_with_positions(pattern, text, re.IGNORECASE)
        for match_text, start, end in matches:
            all_matches.append((subcat, match_text, start, end))
    
    if not all_matches:
        return []
    
    # Convert to format for overlap removal
    matches_with_meta = [(match[1], match[2], match[3], match[0]) for match in all_matches]
    
    # Sort by length and position
    sorted_matches = sorted(matches_with_meta, key=lambda x: (-(x[2] - x[1]), x[1]))
    
    kept_matches = []
    
    for current_match in sorted_matches:
        current_text, current_start, current_end, current_subcat = current_match
        
        is_contained = False
        for kept_match in kept_matches:
            kept_text, kept_start, kept_end, kept_subcat = kept_match
            
            if kept_start <= current_start and current_end <= kept_end:
                if not (current_start == kept_end or current_end == kept_start):
                    is_contained = True
                    break
        
        if not is_contained:
            kept_matches.append(current_match)
    
    # Convert back to output format and sort by position
    result = [(subcat, text, start, end) for text, start, end, subcat in kept_matches]
    result.sort(key=lambda x: x[2])
    
    return result
