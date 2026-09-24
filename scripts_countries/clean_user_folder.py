#!/usr/bin/env python3
"""
Cleans the user_countries folder by moving UNCATEGORIZED.json and
INTERNAL_IDB_KEYS.json files to a user_countries_raws directory while
preserving the directory structure.

Adapted from scripts/clean_user_folder.py for the country extension
(data/user_countries -> data/user_countries_raws), run as the last
finalization step after AI categorization + redistribution.
"""

import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from countries_config import add_users_arg, resolve_users

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASE_DIR = PROJECT_ROOT / "data" / "user_countries"
RAW_DIR = PROJECT_ROOT / "data" / "user_countries_raws"

FILES_TO_MOVE = [
    "UNCATEGORIZED.json",
    "INTERNAL_IDB_KEYS.json"
]


def find_files_to_move(users: Optional[List[str]] = None) -> List[Tuple[Path, Path]]:
    files_map = []
    users_filter = set(users) if users else None

    for root, dirs, files in os.walk(BASE_DIR):
        root_path = Path(root)

        if users_filter is not None:
            rel_parts = root_path.relative_to(BASE_DIR).parts
            user = rel_parts[1] if len(rel_parts) > 1 else None
            if user is not None and user not in users_filter:
                continue

        for filename in files:
            if filename in FILES_TO_MOVE:
                source_path = root_path / filename
                relative_path = source_path.relative_to(BASE_DIR)
                dest_path = RAW_DIR / relative_path
                files_map.append((source_path, dest_path))

    return files_map


def move_files(files_map: List[Tuple[Path, Path]]) -> dict:
    stats = {
        "total_files": len(files_map),
        "moved": 0,
        "errors": 0,
        "uncategorized": 0,
        "internal_idb": 0
    }

    for source_path, dest_path in files_map:
        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source_path), str(dest_path))

            stats["moved"] += 1

            if source_path.name == "UNCATEGORIZED.json":
                stats["uncategorized"] += 1
            elif source_path.name == "INTERNAL_IDB_KEYS.json":
                stats["internal_idb"] += 1

            rel_path = source_path.relative_to(BASE_DIR)
            print(f"   Moved: {rel_path}")

        except Exception as e:
            stats["errors"] += 1
            print(f"   Error moving {source_path.relative_to(BASE_DIR)}: {e}")

    return stats


def main(users=None):
    users = users or resolve_users(None)

    print("=" * 80)
    print(" Starting user_countries folder cleanup")
    print("=" * 80)
    print(f"\nSource directory: {BASE_DIR}")
    print(f"Destination directory: {RAW_DIR}")
    print(f"\nFiles to move: {', '.join(FILES_TO_MOVE)}")
    print(f"Scoped to users: {users}")
    print("\n" + "=" * 80)

    print("\n Scanning for files to move...")
    files_map = find_files_to_move(users=users)

    if not files_map:
        print("\n No files found to move. Directory is already clean!")
        return

    print(f"\n Found {len(files_map)} file(s) to move")
    print("\n" + "=" * 80)
    print(" Moving files...")
    print("=" * 80 + "\n")

    stats = move_files(files_map)

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
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
