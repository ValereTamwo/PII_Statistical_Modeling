#!/usr/bin/env python3
"""
Extract sessionStorage entries from the country-extension raw storage_state
JSON files. Adapted from preprocessing/extract_sessionstorage.py for the 6
new-country personas (data/Countries_data/Users/), PARTIAL policy only.
"""

import os
import sys
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from countries_config import add_users_arg, resolve_users


def _meta(data):
    metadata = data.get('metadata', {})
    return {
        'initial_url': metadata.get('initial_url', metadata.get('initial url', '')),
        'final_url': metadata.get('final_url', ''),
        'timestamp': metadata.get('timestamp', ''),
    }


def extract_added(data, task_id):
    meta = _meta(data)
    entries = []
    for key, value in data.get('sessionStorage', {}).get('added', {}).items():
        entries.append({
            'task_id': task_id, 'key': key, 'value': value,
            'value_length': len(str(value)), **meta
        })
    return entries


def extract_modified(data, task_id):
    meta = _meta(data)
    entries = []
    for key, change_data in data.get('sessionStorage', {}).get('modified', {}).items():
        if isinstance(change_data, dict):
            from_value = change_data.get('from', '')
            to_value = change_data.get('to', '')
        else:
            from_value = ''
            to_value = change_data
        entries.append({
            'task_id': task_id, 'key': key, 'value': to_value,
            'value_from': from_value, 'value_to': to_value,
            'value_from_length': len(str(from_value)),
            'value_to_length': len(str(to_value)),
            'value_changed': from_value != to_value, **meta
        })
    return entries


def extract_removed(data, task_id):
    meta = _meta(data)
    entries = []
    for key, value in data.get('sessionStorage', {}).get('removed', {}).items():
        entries.append({
            'task_id': task_id, 'key': key, 'value': value,
            'value_length': len(str(value)), **meta
        })
    return entries


def main(users=None):
    for user in (users or paths.USERS):
        for auth_status in paths.AUTH_STATUSES:
            input_dir = paths.storage_state_dir(user, auth_status)
            if not input_dir.exists():
                print(f"Directory {input_dir} not found, skipping.")
                continue

            output_dir = paths.output_dir(auth_status, user, 'sessionstorage')
            output_dir.mkdir(parents=True, exist_ok=True)

            all_added, all_modified, all_removed = [], [], []

            json_files = sorted(input_dir.glob('*.json'), key=lambda x: int(x.stem))
            print(f"=== Extracting sessionStorage: {user}/{auth_status} ({len(json_files)} files) ===\n")

            for json_file in json_files:
                task_id = json_file.stem
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    all_added.extend(extract_added(data, task_id))
                    all_modified.extend(extract_modified(data, task_id))
                    all_removed.extend(extract_removed(data, task_id))
                except Exception as e:
                    print(f"  Error processing {json_file.name}: {e}")

            if all_added:
                out = output_dir / 'added_sessionstorage.json'
                with open(out, 'w', encoding='utf-8') as f:
                    json.dump(all_added, f, ensure_ascii=False, indent=2)
                print(f"  {len(all_added)} added entries -> {out}")

            if all_modified:
                out = output_dir / 'modified_sessionstorage.json'
                with open(out, 'w', encoding='utf-8') as f:
                    json.dump(all_modified, f, ensure_ascii=False, indent=2)
                print(f"  {len(all_modified)} modified entries -> {out}")

            if all_removed:
                out = output_dir / 'removed_sessionstorage.json'
                with open(out, 'w', encoding='utf-8') as f:
                    json.dump(all_removed, f, ensure_ascii=False, indent=2)
                print(f"  {len(all_removed)} removed entries -> {out}")

            print("=== Done ===\n")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
