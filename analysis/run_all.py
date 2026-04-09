#!/usr/bin/env python3
"""
GLOBAL ORCHESTRATOR FOR PROFILE-LEVEL ANALYSIS
This script coordinates consolidated and lifecycle analysis for both cookies and other web storages.
"""

import sys
import subprocess
from pathlib import Path

# Base directory for analysis scripts
ANALYSIS_DIR = Path(__file__).resolve().parent

def run_script(script_path, description):
    print(f"\n" + "="*80)
    print(f" STEP: {description}")
    print(f" Executing: {script_path.name}")
    print("="*80)
    
    if not script_path.exists():
        print(f" Error: {script_path.name} not found in {script_path.parent}")
        return False
        
    try:
        result = subprocess.run([sys.executable, str(script_path)], 
                               cwd=script_path.parent, 
                               check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f" Error executing {script_path.name}: {e}")
        return False
    except Exception as e:
        print(f" Unexpected error: {e}")
        return False

def main():
    print("\n" + "#"*80)
    print("#" + " "*24 + "PROFILE-LEVEL ANALYSIS RUNNER" + " "*25 + "#")
    print("#"*80)

    # 1. Cookie Analysis
    print("\n--- PHASE 1: COOKIE ANALYSIS ---")
    run_script(ANALYSIS_DIR / "consolidated_analysis.py", "Cookie Consolidated Analysis")
    run_script(ANALYSIS_DIR / "lifecycle_analysis.py", "Cookie Lifecycle Analysis")

    # 2. Storage Analysis (LocalStorage, SessionStorage, IndexedDB)
    print("\n--- PHASE 2: STORAGE ANALYSIS ---")
    storage_dir = ANALYSIS_DIR / "storage_analysis"
    run_script(storage_dir / "storage_consolidated_analysis.py", "Other Storages Consolidated Analysis")
    run_script(storage_dir / "storage_lifecycle_analysis.py", "Other Storages Lifecycle Analysis")

    print("\n" + "#"*80)
    print("#" + " "*24 + "ANALYSIS PIPELINE COMPLETED" + " "*27 + "#")
    print("#"*80 + "\n")

if __name__ == "__main__":
    main()
