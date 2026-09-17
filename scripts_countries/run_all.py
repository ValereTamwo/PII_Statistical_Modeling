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

SCRIPTS_DIR = Path(__file__).resolve().parent


def run_script(script_name, description):
    print("\n" + "=" * 80)
    print(f" STEP: {description}")
    print(f" Executing: {script_name}")
    print("=" * 80)

    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        print(f" Error: {script_name} not found in {SCRIPTS_DIR}")
        return False

    try:
        result = subprocess.run([sys.executable, str(script_path)],
                                 cwd=SCRIPTS_DIR.parent,
                                 check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f" Error executing {script_name}: {e}")
        return False


def main():
    print("\n" + "#" * 80)
    print("#" + " " * 20 + "COUNTRY-EXTENSION PIPELINE RUNNER" + " " * 24 + "#")
    print("#" * 80)

    print("\n--- STAGE 2: REGEX-BASED CATEGORIZATION ---")
    if not run_script("categorize_cookies.py", "Cookie Classification"):
        return
    if not run_script("categorize_localstorage.py", "Storage (LS/SS) Classification"):
        return
    if not run_script("categorize_indexeddb.py", "IndexedDB Classification"):
        return

    print("\n--- STAGE 3: DATA CLEANING & REFINEMENT ---")
    if not run_script("clean_idb.py", "IndexedDB Pre-filtering"):
        return
    if not run_script("clean_pii.py", "PII Deduplication & False Positive Removal"):
        return

    print("\n--- STAGE 4: AGGREGATION ---")
    if not run_script("aggregate_indexeddb.py", "IndexedDB Hierarchical Aggregation"):
        return

    print("\n--- STAGE 5: AI-POWERED CATEGORIZATION (OpenAI) ---")
    # Note: These require OPENAI_API_KEY in the environment.
    if not run_script("ai_categorize_all_storages.py", "LLM-based Storage Categorization"):
        print(" Warning: AI Storage categorization failed or skipped (check API status). Continuing...")

    if not run_script("ai_parallel_indexededdb.py", "LLM-based IndexedDB Categorization"):
        print(" Warning: AI IndexedDB categorization failed or skipped. Continuing...")

    print("\n--- STAGE 6: FINALIZATION & REDISTRIBUTION ---")
    if not run_script("redistribute_ai_categorizations.py", "Merging AI Results"):
        return
    if not run_script("clean_user_folder.py", "Finalizing User Directory Structure"):
        return

    print("\n" + "#" * 80)
    print("#" + " " * 27 + "PIPELINE COMPLETE" + " " * 34 + "#")
    print("#" * 80 + "\n")


if __name__ == '__main__':
    main()
