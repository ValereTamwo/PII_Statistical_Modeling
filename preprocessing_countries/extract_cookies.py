#!/usr/bin/env python3
"""
Extract cookies from the country-extension raw storage_state JSON files.
Adapted from preprocessing/extract_cookies.py for the 6 new-country
personas (data/Countries_data/Users/), PARTIAL policy only.
"""

import os
import sys
import json
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from countries_config import add_users_arg, resolve_users


def load_cookies_from_json(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def format_timestamp(ts):
    if ts and ts > 0:
        try:
            return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return ''
    return ''


def main(users=None):
    for user in (users or paths.USERS):
        for auth_status in paths.AUTH_STATUSES:
            input_dir = paths.storage_state_dir(user, auth_status)
            if not input_dir.exists():
                print(f"Directory {input_dir} not found, skipping.")
                continue

            output_dir = paths.output_dir(auth_status, user, 'cookies')
            output_dir.mkdir(parents=True, exist_ok=True)

            added_cookies = []
            modified_cookies = []
            removed_cookies = []

            print(f"=== Extracting cookies: {user}/{auth_status} ===\n")

            json_files = sorted(input_dir.glob('*.json'), key=lambda x: int(x.stem))
            if not json_files:
                print(f"No files found in {input_dir}")
                continue

            for filepath in json_files:
                task_id = filepath.stem
                try:
                    data = load_cookies_from_json(filepath)

                    metadata = data.get('metadata', {})
                    initial_url = metadata.get('initial_url', metadata.get('initial url', ''))
                    final_url = metadata.get('final_url', '')
                    timestamp = metadata.get('timestamp', '')

                    cookies_data = data.get('cookies', {})

                    for c_key, cookie in cookies_data.get('added', {}).items():
                        added_cookies.append({
                            'task_id': task_id,
                            'cookie_key': c_key,
                            'name': cookie.get('name', ''),
                            'value': cookie.get('value', ''),
                            'domain': cookie.get('domain', ''),
                            'path': cookie.get('path', ''),
                            'expires': cookie.get('expires', -1),
                            'expires_human': format_timestamp(cookie.get('expires', -1)),
                            'httpOnly': cookie.get('httpOnly', False),
                            'secure': cookie.get('secure', False),
                            'sameSite': cookie.get('sameSite', None),
                            'initial_url': initial_url,
                            'final_url': final_url,
                            'timestamp': timestamp
                        })

                    for c_key, change_data in cookies_data.get('modified', {}).items():
                        from_cookie = change_data.get('from', {})
                        to_cookie = change_data.get('to', {})
                        modified_cookies.append({
                            'task_id': task_id,
                            'cookie_key': c_key,
                            'name': from_cookie.get('name', ''),
                            'domain': from_cookie.get('domain', ''),
                            'path': from_cookie.get('path', ''),

                            'value': to_cookie.get('value', ''),
                            'value_from': from_cookie.get('value', ''),
                            'value_to': to_cookie.get('value', ''),
                            'value_changed': from_cookie.get('value') != to_cookie.get('value'),

                            'expires': to_cookie.get('expires', -1),
                            'expires_from': from_cookie.get('expires', -1),
                            'expires_to': to_cookie.get('expires', -1),
                            'expires_human': format_timestamp(to_cookie.get('expires', -1)),
                            'expires_changed': from_cookie.get('expires') != to_cookie.get('expires'),

                            'httpOnly': to_cookie.get('httpOnly', False),
                            'httpOnly_from': from_cookie.get('httpOnly', False),
                            'httpOnly_to': to_cookie.get('httpOnly', False),
                            'httpOnly_changed': from_cookie.get('httpOnly') != to_cookie.get('httpOnly'),

                            'secure': to_cookie.get('secure', False),
                            'secure_from': from_cookie.get('secure', False),
                            'secure_to': to_cookie.get('secure', False),
                            'secure_changed': from_cookie.get('secure') != to_cookie.get('secure'),

                            'sameSite': to_cookie.get('sameSite', None),
                            'sameSite_from': from_cookie.get('sameSite', None),
                            'sameSite_to': to_cookie.get('sameSite', None),
                            'sameSite_changed': from_cookie.get('sameSite') != to_cookie.get('sameSite'),

                            'initial_url': initial_url,
                            'final_url': final_url,
                            'timestamp': timestamp
                        })

                    for c_key, cookie in cookies_data.get('removed', {}).items():
                        removed_cookies.append({
                            'task_id': task_id,
                            'cookie_key': c_key,
                            'name': cookie.get('name', ''),
                            'value': cookie.get('value', ''),
                            'domain': cookie.get('domain', ''),
                            'path': cookie.get('path', ''),
                            'expires': cookie.get('expires', -1),
                            'expires_human': format_timestamp(cookie.get('expires', -1)),
                            'httpOnly': cookie.get('httpOnly', False),
                            'secure': cookie.get('secure', False),
                            'sameSite': cookie.get('sameSite', None),
                            'initial_url': initial_url,
                            'final_url': final_url,
                            'timestamp': timestamp
                        })

                except Exception as e:
                    print(f"  Error processing {filepath.name}: {e}")
                    continue

            print(f"{len(json_files)} files processed\n")

            if added_cookies:
                out = output_dir / 'added_cookies.json'
                with open(out, 'w', encoding='utf-8') as f:
                    json.dump(added_cookies, f, ensure_ascii=False, indent=2)
                print(f"  {len(added_cookies)} added cookies -> {out}")

            if modified_cookies:
                out = output_dir / 'modified_cookies.json'
                with open(out, 'w', encoding='utf-8') as f:
                    json.dump(modified_cookies, f, ensure_ascii=False, indent=2)
                print(f"  {len(modified_cookies)} modified cookies -> {out}")

            if removed_cookies:
                out = output_dir / 'removed_cookies.json'
                with open(out, 'w', encoding='utf-8') as f:
                    json.dump(removed_cookies, f, ensure_ascii=False, indent=2)
                print(f"  {len(removed_cookies)} removed cookies -> {out}")

            print("=== Done ===\n")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
