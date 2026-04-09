#!/usr/bin/env python3
"""
Script to merge subcategory JSON files into their main category files.
For example: ID_SOLUTIONS_AND_EXCHANGES.bidswitch.json + ID_SOLUTIONS_AND_EXCHANGES.generic_ids.json
will be merged into ID_SOLUTIONS_AND_EXCHANGES.json
"""

import json
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List

# Base directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASE_DIR = PROJECT_ROOT / "data" / "user"

# Storage types to process
STORAGE_TYPES = ["cookies", "localstorage", "sessionstorage"]

# Lifecycle folders
LIFECYCLE_FOLDERS = ["added", "removed", "modified"]


def find_all_storage_paths() -> List[Path]:
    """Find all storage paths (cookies/localstorage/sessionstorage) for all users and configs."""
    storage_paths = []
    
    # Iterate through all user directories
    for user_dir in BASE_DIR.iterdir():
        if not user_dir.is_dir():
            continue
            
        # Iterate through all user IDs (e.g., FR_0417)
        for user_id_dir in user_dir.iterdir():
            if not user_id_dir.is_dir():
                continue
                
            # Iterate through all configs (e.g., ALL, NONE, PARTIAL)
            for config_dir in user_id_dir.iterdir():
                if not config_dir.is_dir():
                    continue
                    
                # Check for each storage type
                for storage_type in STORAGE_TYPES:
                    storage_path = config_dir / storage_type
                    if storage_path.exists() and storage_path.is_dir():
                        storage_paths.append(storage_path)
    
    return storage_paths


def identify_subcategory_files(directory: Path) -> Dict[str, List[Path]]:
    """
    Identify files that follow the pattern CATEGORY.subcategory.json
    Returns a dict mapping main category to list of subcategory files.
    """
    category_map = defaultdict(list)
    
    if not directory.exists():
        return category_map
    
    for file_path in directory.glob("*.json"):
        filename = file_path.name
        
        # Check if filename contains at least one dot before .json
        # Pattern: CATEGORY.subcategory.json
        parts = filename.rsplit('.json', 1)[0].split('.', 1)
        
        if len(parts) == 2:
            # This is a subcategory file
            main_category = parts[0]
            category_map[main_category].append(file_path)
    
    return category_map


def merge_json_files(main_category: str, subcategory_files: List[Path], output_path: Path) -> int:
    """
    Merge multiple JSON files into one.
    Returns the total number of items merged.
    """
    merged_data = []
    
    # Read existing main category file if it exists
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
                if isinstance(existing_data, list):
                    merged_data.extend(existing_data)
        except Exception as e:
            print(f"    Error reading existing {output_path.name}: {e}")
    
    # Merge all subcategory files
    for subcategory_file in subcategory_files:
        try:
            with open(subcategory_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    merged_data.extend(data)
                    print(f"     Merged {len(data)} items from {subcategory_file.name}")
                else:
                    print(f"      Skipped {subcategory_file.name} (not a list)")
        except Exception as e:
            print(f"     Error reading {subcategory_file.name}: {e}")
    
    # Write merged data
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(merged_data, f, indent=2, ensure_ascii=False)
        return len(merged_data)
    except Exception as e:
        print(f"     Error writing {output_path.name}: {e}")
        return 0


def delete_subcategory_files(subcategory_files: List[Path]):
    """Delete the subcategory files after successful merge."""
    for file_path in subcategory_files:
        try:
            file_path.unlink()
            print(f"      Deleted {file_path.name}")
        except Exception as e:
            print(f"     Error deleting {file_path.name}: {e}")


def process_lifecycle_folder(lifecycle_path: Path) -> Dict[str, int]:
    """
    Process a single lifecycle folder (added/removed/modified).
    Returns stats about merged categories.
    """
    stats = {}
    
    # Identify subcategory files
    category_map = identify_subcategory_files(lifecycle_path)
    
    if not category_map:
        return stats
    
    print(f"\n  ‚ Processing {lifecycle_path.parent.name}/{lifecycle_path.name}")
    
    for main_category, subcategory_files in category_map.items():
        print(f"\n     Category: {main_category}")
        print(f"       Found {len(subcategory_files)} subcategory file(s)")
        
        # Define output path
        output_path = lifecycle_path / f"{main_category}.json"
        
        # Merge files
        total_items = merge_json_files(main_category, subcategory_files, output_path)
        
        # Delete subcategory files
        delete_subcategory_files(subcategory_files)
        
        stats[main_category] = total_items
        print(f"     Total items in {main_category}.json: {total_items}")
    
    return stats


def main():
    """Main execution function."""
    print("=" * 80)
    print(" Starting subcategory merge process")
    print("=" * 80)
    
    # Find all storage paths
    storage_paths = find_all_storage_paths()
    print(f"\n Found {len(storage_paths)} storage paths to process\n")
    
    total_stats = {
        "storage_paths_processed": 0,
        "categories_merged": 0,
        "total_items": 0
    }
    
    # Process each storage path
    for storage_path in storage_paths:
        print(f"\n{'=' * 80}")
        print(f"¦ Processing: {storage_path.relative_to(BASE_DIR)}")
        print(f"{'=' * 80}")
        
        storage_processed = False
        
        # Process each lifecycle folder
        for lifecycle_folder in LIFECYCLE_FOLDERS:
            lifecycle_path = storage_path / lifecycle_folder
            
            if lifecycle_path.exists():
                stats = process_lifecycle_folder(lifecycle_path)
                
                if stats:
                    storage_processed = True
                    total_stats["categories_merged"] += len(stats)
                    total_stats["total_items"] += sum(stats.values())
        
        if storage_processed:
            total_stats["storage_paths_processed"] += 1
    
    # Print final summary
    print("\n" + "=" * 80)
    print("MERGE COMPLETE")
    print("=" * 80)
    print(f"Storage paths processed: {total_stats['storage_paths_processed']}")
    print(f"Categories merged: {total_stats['categories_merged']}")
    print(f"Total items processed: {total_stats['total_items']}")
    print("=" * 80)


if __name__ == "__main__":
    main()
