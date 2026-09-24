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

sys.path.insert(0, str(GDPR_DIR.parent))
from countries_config import add_users_arg


def run_script(script_path, description, extra_args=None):
    print(f"\n" + "="*80)
    print(f" STEP: {description}")
    print(f" Executing: {script_path.name}")
    print("="*80)

    if not script_path.exists():
        print(f" Error: {script_path.name} not found in {script_path.parent}")
        return False

    try:
        result = subprocess.run([sys.executable, str(script_path)] + (extra_args or []),
                               cwd=script_path.parent,
                               check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f" Error executing {script_path.name}: {e}")
        return False
    except Exception as e:
        print(f" Unexpected error: {e}")
        return False


def main(extra_args=None):
    print("\n" + "#"*80)
    print("#" + " "*16 + "COUNTRY GDPR PROFILES ANALYSIS RUNNER" + " "*18 + "#")
    print("#"*80)
    if extra_args:
        print(f"Forwarding extra args to aggregation stage: {extra_args}")

    print("\n--- PHASE 1: PII AGGREGATION ---")
    if not run_script(SCRIPTS_DIR / "pii_aggregator.py", "Global PII Aggregation", extra_args):
        print(" Error during aggregation. Stopping.")
        return

    print("\n--- PHASE 2: REPORT ---")
    # generate_report.py has no --users override: it just reads whatever
    # pii_comparative_analysis.json the aggregation step above produced.
    run_script(SCRIPTS_DIR / "generate_report.py", "Report Generation")

    print("\n" + "#"*80)
    print("#" + " "*26 + "GDPR PIPELINE COMPLETED" + " "*29 + "#")
    print("#"*80 + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    extra_args = ["--users", args.users] if args.users else []
    main(extra_args=extra_args)
