#!/usr/bin/env python3
"""
GLOBAL ORCHESTRATOR FOR STATISTICAL MODELING
This script coordinates global aggregation and lifecycle metrics analysis.
"""

import sys
import subprocess
from pathlib import Path

# Base directory for statistical model scripts
STATS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = STATS_DIR.parent

def run_script(script_path, args=None, description=""):
    print(f"\n" + "="*80)
    print(f" STEP: {description}")
    print(f" Executing: {script_path.name} {' '.join(args) if args else ''}")
    print("="*80)
    
    if not script_path.exists():
        print(f" Error: {script_path.name} not found in {script_path.parent}")
        return False
        
    cmd = [sys.executable, str(script_path)]
    if args:
        cmd.extend(args)
        
    try:
        # We use subprocess to run each script as a separate process
        result = subprocess.run(cmd, 
                               cwd=PROJECT_ROOT, 
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
    print("#" + " "*24 + "PII STATISTICAL MODEL RUNNER" + " "*26 + "#")
    print("#"*80)

    # 1. Global Aggregation (Privacy/Security Metrics)
    # Arguments required: results_path and output_path
    results_path = "./results"
    output_path = "./results/aggregated_data"
    
    print("\n--- PHASE 1: GLOBAL METRIC AGGREGATION ---")
    run_script(STATS_DIR / "aggregation.py", [results_path, output_path], "Global Metrics Aggregation")

    # 2. Lifecycle Aggregation
    print("\n--- PHASE 2: LIFECYCLE AGGREGATION ---")
    run_script(STATS_DIR / "aggregate_lifecycle.py", None, "Lifecycle Metrics Aggregation")

    print("\n" + "#"*80)
    print("#" + " "*26 + "STATISTICAL PIPELINE COMPLETED" + " "*22 + "#")
    print("#"*80 + "\n")

if __name__ == "__main__":
    main()
