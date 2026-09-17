#!/usr/bin/env python3
"""
Extract (copy) IndexedDB dumps from the country-extension raw data.
Adapted from preprocessing/extract_indexeddb.py for the 6 new-country
personas (data/Countries_data/Users/), PARTIAL policy only.
"""

import os
import sys
import shutil

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import paths


def extract_indexeddb_for_user(source_dir, output_dir):
    if not source_dir.exists():
        print(f"  IndexedDB source not found: {source_dir}")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    json_files = list(source_dir.glob('*.json'))
    for json_file in json_files:
        shutil.copy2(json_file, output_dir / json_file.name)
    return len(json_files)


def main():
    print("=" * 70)
    print("INDEXEDDB EXTRACTION (countries)")
    print("=" * 70)

    total_files = 0
    for user in paths.USERS:
        for auth_status in paths.AUTH_STATUSES:
            source_dir = paths.indexeddb_dir(user, auth_status)
            output_dir = paths.output_dir(auth_status, user, 'indexeddb')

            count = extract_indexeddb_for_user(source_dir, output_dir)
            if count > 0:
                print(f"  {user}/{auth_status}: {count} IndexedDB files")
                total_files += count

    print(f"\nTotal IndexedDB files copied: {total_files}")


if __name__ == '__main__':
    try:
        main()
        print("EXTRACTION COMPLETE")
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
