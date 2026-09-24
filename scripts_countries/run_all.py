#!/usr/bin/env python3
"""
Country-extension pipeline orchestrator.

Runs Stage 2 (regex-based classification, regex_merged_v3), Stage 3
(cleaning), Stage 4 (IndexedDB aggregation), Stage 5 (AI-powered
categorization) and Stage 6 (finalization/redistribution), mirroring
PHASE 1 through PHASE 5 of scripts/run_all.py.

Stage 5 requires OPENAI_API_KEY in the environment - it is not fetched or
set by this script. Run manually, e.g.:
    OPENAI_API_KEY=sk-... python3 scripts_countries/run_all.py
If the key is missing, the AI steps fail gracefully (warning + continue)
exactly like the FR pipeline's run_all.py.
"""

import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from countries_config import add_users_arg

SCRIPTS_DIR = Path(__file__).resolve().parent


def run_script(script_name, description, extra_args=None):
    print("\n" + "=" * 80)
    print(f" STEP: {description}")
    print(f" Executing: {script_name}")
    print("=" * 80)

    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        print(f" Error: {script_name} not found in {SCRIPTS_DIR}")
        return False

    try:
        result = subprocess.run([sys.executable, str(script_path)] + (extra_args or []),
                                 cwd=SCRIPTS_DIR.parent,
                                 check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f" Error executing {script_name}: {e}")
        return False


def main(extra_args=None):
    print("\n" + "#" * 80)
    print("#" + " " * 20 + "COUNTRY-EXTENSION PIPELINE RUNNER" + " " * 24 + "#")
    print("#" * 80)
    if extra_args:
        print(f"Forwarding extra args to every stage: {extra_args}")

    print("\n--- STAGE 2: REGEX-BASED CATEGORIZATION ---")
    if not run_script("categorize_cookies.py", "Cookie Classification", extra_args):
        return
    if not run_script("categorize_localstorage.py", "Storage (LS/SS) Classification", extra_args):
        return
    if not run_script("categorize_indexeddb.py", "IndexedDB Classification", extra_args):
        return

    print("\n--- STAGE 3: DATA CLEANING & REFINEMENT ---")
    if not run_script("clean_idb.py", "IndexedDB Pre-filtering", extra_args):
        return
    if not run_script("clean_pii.py", "PII Deduplication & False Positive Removal", extra_args):
        return

    print("\n--- STAGE 4: AGGREGATION ---")
    if not run_script("aggregate_indexeddb.py", "IndexedDB Hierarchical Aggregation", extra_args):
        return

    print("\n--- STAGE 5: AI-POWERED CATEGORIZATION (OpenAI) ---")
    # Note: These require OPENAI_API_KEY in the environment.
    if not run_script("ai_categorize_all_storages.py", "LLM-based Storage Categorization", extra_args):
        print(" Warning: AI Storage categorization failed or skipped (check API status). Continuing...")

    if not run_script("ai_parallel_indexededdb.py", "LLM-based IndexedDB Categorization", extra_args):
        print(" Warning: AI IndexedDB categorization failed or skipped. Continuing...")

    print("\n--- STAGE 6: FINALIZATION & REDISTRIBUTION ---")
    if not run_script("redistribute_ai_categorizations.py", "Merging AI Results", extra_args):
        return
    if not run_script("clean_user_folder.py", "Finalizing User Directory Structure", extra_args):
        return

    print("\n" + "#" * 80)
    print("#" + " " * 27 + "PIPELINE COMPLETE" + " " * 34 + "#")
    print("#" * 80 + "\n")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    extra_args = ["--users", args.users] if args.users else []
    main(extra_args=extra_args)
