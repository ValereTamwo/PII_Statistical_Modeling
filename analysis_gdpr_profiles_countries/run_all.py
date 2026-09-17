#!/usr/bin/env python3
"""
GLOBAL ORCHESTRATOR FOR GDPR PROFILES ANALYSIS - country extension.

Adapted from analysis_gdpr_profiles/run_all.py: same two-phase execution
(PII aggregation, then report generation), but runs the
analysis_gdpr_profiles_countries/scripts/ (data/user_countries/,
outputs/, reports/) instead of the FR-only scripts.
"""

import sys
import subprocess
from pathlib import Path

GDPR_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = GDPR_DIR / "scripts"


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
    print("#" + " "*16 + "COUNTRY GDPR PROFILES ANALYSIS RUNNER" + " "*18 + "#")
    print("#"*80)

    print("\n--- PHASE 1: PII AGGREGATION ---")
    if not run_script(SCRIPTS_DIR / "pii_aggregator.py", "Global PII Aggregation"):
        print(" Error during aggregation. Stopping.")
        return

    print("\n--- PHASE 2: REPORT ---")
    run_script(SCRIPTS_DIR / "generate_report.py", "Report Generation")

    print("\n" + "#"*80)
    print("#" + " "*26 + "GDPR PIPELINE COMPLETED" + " "*29 + "#")
    print("#"*80 + "\n")


if __name__ == "__main__":
    main()
