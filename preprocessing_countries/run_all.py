#!/usr/bin/env python3
"""
Runs all country-extension preprocessing scripts.
Mirrors preprocessing/run_all.py, fully separate from the FR pipeline.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from countries_config import add_users_arg


def run_script(script_name, extra_args=None):
    script_path = Path(__file__).parent / script_name

    print(f"\n{'='*60}")
    print(f"Running {script_name}")
    print(f"{'='*60}\n")

    try:
        subprocess.run([sys.executable, str(script_path)] + (extra_args or []), check=True)
        print(f"\n{script_name} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\nError running {script_name} (exit code {e.returncode})")
        return False


def main(extra_args=None):
    print("\n" + "=" * 60)
    print("COUNTRY-EXTENSION PREPROCESSING")
    print("=" * 60)

    scripts = [
        'extract_cookies.py',
        'extract_localstorage.py',
        'extract_sessionstorage.py',
        'extract_indexeddb.py',
    ]

    results = {script: run_script(script, extra_args) for script in scripts}

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for script, success in results.items():
        status = "OK   " if success else "FAILED"
        print(f"{status:8} - {script}")

    if all(results.values()):
        print("\nAll scripts completed successfully.")
        print("Output: data/preprocessing_countries/<AUTH|NOTAUTH>/<user>/PARTIAL/<storage_type>/")
    else:
        print("\nSome scripts failed. See errors above.")
        sys.exit(1)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    extra_args = ["--users", args.users] if args.users else []
    main(extra_args=extra_args)
