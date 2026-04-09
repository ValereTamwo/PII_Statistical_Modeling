#!/usr/bin/env python3
"""
Script to clean the user folder by moving UNCATEGORIZED.json and INTERNAL_IDB_KEYS.json
files to a user_raws directory while preserving the directory structure.
"""

import os
import shutil
from pathlib import Path
from typing import List, Tuple

# Base directories
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASE_DIR = PROJECT_ROOT / "data" / "user"
RAW_DIR = PROJECT_ROOT / "data" / "user_raws"

# Files to move
FILES_TO_MOVE = [
    "UNCATEGORIZED.json",
    "INTERNAL_IDB_KEYS.json"
]


def find_files_to_move() -> List[Tuple[Path, Path]]:
    """
    Find all files to move and calculate their destination paths.
    Returns list of (source_path, destination_path) tuples.
    """
    files_map = []
    
    # Walk through all directories in user folder
    for root, dirs, files in os.walk(BASE_DIR):
        root_path = Path(root)
        
        for filename in files:
            if filename in FILES_TO_MOVE:
                source_path = root_path / filename
                
                # Calculate relative path from BASE_DIR
                relative_path = source_path.relative_to(BASE_DIR)
                
                # Create destination path in user_raws
                dest_path = RAW_DIR / relative_path
                
                files_map.append((source_path, dest_path))
    
    return files_map


def move_files(files_map: List[Tuple[Path, Path]]) -> dict:
    """
    Move files from source to destination, creating directories as needed.
    Returns statistics about the operation.
    """
    stats = {
        "total_files": len(files_map),
        "moved": 0,
        "errors": 0,
        "uncategorized": 0,
        "internal_idb": 0
    }
    
    for source_path, dest_path in files_map:
        try:
            # Create destination directory if it doesn't exist
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move the file
            shutil.move(str(source_path), str(dest_path))
            
            # Update stats
            stats["moved"] += 1
            
            if source_path.name == "UNCATEGORIZED.json":
                stats["uncategorized"] += 1
            elif source_path.name == "INTERNAL_IDB_KEYS.json":
                stats["internal_idb"] += 1
            
            # Calculate relative path for display
            rel_path = source_path.relative_to(BASE_DIR)
            print(f"   Moved: {rel_path}")
            
        except Exception as e:
            stats["errors"] += 1
            print(f"   Error moving {source_path.relative_to(BASE_DIR)}: {e}")
    
    return stats


def main():
    """Main execution function."""
    print("=" * 80)
    print(" Starting user folder cleanup")
    print("=" * 80)
    print(f"\nSource directory: {BASE_DIR}")
    print(f"Destination directory: {RAW_DIR}")
    print(f"\nFiles to move: {', '.join(FILES_TO_MOVE)}")
    print("\n" + "=" * 80)
    
    # Find all files to move
    print("\n Scanning for files to move...")
    files_map = find_files_to_move()
    
    if not files_map:
        print("\n No files found to move. Directory is already clean!")
        return

    print(f"\n Found {len(files_map)} file(s) to move")
    print("\n" + "=" * 80)
    print(" Moving files...")
    print("=" * 80 + "\n")
    
    # Move files
    stats = move_files(files_map)
    
    # Print summary
    print("\n" + "=" * 80)
    print(" CLEANUP COMPLETE")
    print("=" * 80)
    print(f"Total files found: {stats['total_files']}")
    print(f"Successfully moved: {stats['moved']}")
    print(f"  - UNCATEGORIZED.json: {stats['uncategorized']}")
    print(f"  - INTERNAL_IDB_KEYS.json: {stats['internal_idb']}")
    print(f"Errors: {stats['errors']}")
    print("=" * 80)
    
    if stats['errors'] > 0:
        print("\n  Some files could not be moved. Please check the errors above.")
    else:
        print(f"\n All files successfully moved to {RAW_DIR}")


if __name__ == "__main__":
    main()
