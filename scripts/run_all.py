#!/usr/bin/env python3
"""
GLOBAL ORCHESTRATOR FOR PII CATEGORIZATION PIPELINE
This script coordinates the entire  pipeline from raw data to finalized categorizations.
"""

import sys
import subprocess
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent

def run_script(script_name, description):
    print(f"\n" + "="*80)
    print(f" STEP: {description}")
    print(f" Executing: {script_name}")
    print("="*80)
    
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
    except Exception as e:
        print(f" Unexpected error: {e}")
        return False

def main():
    print("\n" + "#"*80)
    print("#" + " "*26 + "PII PIPELINE GLOBAL RUNNER" + " "*26 + "#")
    print("#"*80)

    # 0. Preprocessing Foundation
    print("\n--- PHASE 0: PREPROCESSING FOUNDATION ---")
    # Call the run_all.py in the preprocessing folder
    prepro_path = SCRIPTS_DIR.parent / "preprocessing" / "run_all.py"
    if prepro_path.exists():
        try:
            print(f" Executing: {prepro_path}")
            subprocess.run([sys.executable, str(prepro_path)], 
                           cwd=SCRIPTS_DIR.parent / "preprocessing", 
                           check=True)
        except subprocess.CalledProcessError as e:
            print(f" Warning: Preprocessing foundation failed (Code {e.returncode}). Continuing...")
    else:
        print(" Info: Preprocessing runner not found, skipping...")

    # 1. Regex-based classification
    print("\n--- PHASE 1: REGEX-BASED CATEGORIZATION ---")
    if not run_script("categorize_cookies.py", "Cookie Classification"): return
    if not run_script("categorize_localstorage.py", "Storage (LS/SS) Classification"): return
    if not run_script("categorize_indexeddb.py", "IndexedDB Classification"): return

    # 2. Cleaning Phase
    print("\n--- PHASE 2: DATA CLEANING & REFINEMENT ---")
    if not run_script("clean_idb.py", "IndexedDB Pre-filtering"): return
    if not run_script("clean_pii.py", "PII Deduplication & False Positive Removal"): return

    # 3. Aggregation Phase
    print("\n--- PHASE 3: AGGREGATION ---")
    if not run_script("aggregate_indexeddb.py", "IndexedDB Hierarchical Aggregation"): return

    # 4. AI-Powered Enhancement
    print("\n--- PHASE 4: AI-POWERED CATEGORIZATION (Groq/OpenAI) ---")
    # Note: These require API keys in the environment
    if not run_script("ai_categorize_all_storages.py", "LLM-based Storage Categorization"): 
        print(" Warning: AI Storage categorization failed or skipped (check API status). Continuing...")
        
    if not run_script("ai_parallel_indexededdb.py", "LLM-based IndexedDB Categorization"):
        print(" Warning: AI IndexedDB categorization failed or skipped. Continuing...")

    # 5. Finalization
    print("\n--- PHASE 5: FINALIZATION & REDISTRIBUTION ---")
    if not run_script("redistribute_ai_categorizations.py", "Merging AI Results"): return
    if not run_script("clean_user_folder.py", "Finalizing User Directory Structure"): return

    print("\n" + "#"*80)
    print("#" + " "*25 + "PII PIPELINE RUN COMPLETED" + " "*27 + "#")
    print("#"*80 + "\n")

if __name__ == "__main__":
    main()
