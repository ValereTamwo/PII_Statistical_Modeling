#!/usr/bin/env python3
"""
GLOBAL ORCHESTRATOR FOR RISK ANALYSIS (PxI) - country extension.

Adapted from risk_analysis_PxI/run_all.py: runs the core risk-scoring
pipeline (vectorization -> exposure -> impact -> risk -> stats -> F1
boxplots) against data/user_countries/ for the 6 new-country personas.

Per the user's explicit instruction, sensitivity analysis is skipped for
now: this orchestrator has no Phase 4 (sensibility_analysis.py /
sensibility_analysis_viz.py) or Phase 5 (within_tier_analysis.py) - those
were never ported to risk_analysis_PxI_countries/.

Calibration (expert_eta_calibration.py) is also not re-run here: its
output (the exposure model's betas) is a fixed, dataset-independent
artifact derived from hand-authored expert scenarios, not from data/user/
- item_exposure_engine.py already carries the same calibrated betas as a
frozen constant, exactly as the FR version does.
"""

import sys
import subprocess
from pathlib import Path

RISK_DIR = Path(__file__).resolve().parent
SRC_DIR = RISK_DIR / "src"
UTILS_DIR = SRC_DIR / "utils"


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
    print("#" + " "*18 + "COUNTRY RISK ANALYSIS PxI RUNNER" + " "*25 + "#")
    print("#"*80)

    print("\n--- PHASE 1: VECTORIZATION ---")
    if not run_script(UTILS_DIR / "items_vectorizer.py", "Items Vectorization"): return

    print("\n--- PHASE 2: RISK ENGINES (Pi, Ii, Ri) ---")
    if not run_script(SRC_DIR / "item_exposure_engine.py", "Item Exposure Engine (Pi)"): return
    if not run_script(SRC_DIR / "item_impact_engine.py", "Item Impact Engine (Ii)"): return
    if not run_script(SRC_DIR / "item_risk_engine.py", "Item Risk Engine (Ri)"): return

    print("\n--- PHASE 3: STATISTICS & VISUALIZATIONS ---")
    if not run_script(SRC_DIR / "risk_stats.py", "Risk Statistics Generation"): return
    if not run_script(SRC_DIR / "boxplots.py", "Boxplot Generation (F1)"): return

    print("\n" + "#"*80)
    print("#" + " "*23 + "COUNTRY RISK PIPELINE COMPLETED" + " "*24 + "#")
    print("#"*80 + "\n")


if __name__ == "__main__":
    main()
