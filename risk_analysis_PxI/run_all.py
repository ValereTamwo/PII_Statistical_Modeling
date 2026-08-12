#!/usr/bin/env python3
"""
GLOBAL ORCHESTRATOR FOR RISK ANALYSIS (PxI)
This script coordinates the entire risk modeling pipeline, from calibration to visualization.
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
    print("#" + " "*25 + "RISK ANALYSIS PxI RUNNER" + " "*29 + "#")
    print("#"*80)

    # 1. Calibration & Vectorization
    print("\n--- PHASE 1: CALIBRATION & VECTORIZATION ---")
    if not run_script(UTILS_DIR / "expert_eta_calibration.py", "Expert Pi Calibration"): return
    if not run_script(UTILS_DIR / "items_vectorizer.py", "Items Vectorization"): return

    # 2. Risk Engines
    print("\n--- PHASE 2: RISK ENGINES (Pi, Ii, Ri) ---")
    if not run_script(SRC_DIR / "item_exposure_engine.py", "Item Exposure Engine (Pi)"): return
    if not run_script(SRC_DIR / "item_impact_engine.py", "Item Impact Engine (Ii)"): return
    if not run_script(SRC_DIR / "item_risk_engine.py", "Item Risk Engine (Ri)"): return

    # 3. Statistics & Visualizations
    print("\n--- PHASE 3: STATISTICS & VISUALIZATIONS ---")
    if not run_script(SRC_DIR / "risk_stats.py", "Risk Statistics Generation"): return
    if not run_script(SRC_DIR / "boxplots.py", "Boxplot Generation (Main Figures)"): return

    # 4. Sensitivity Analysis
    print("\n--- PHASE 4: SENSITIVITY ANALYSIS ---")
    if not run_script(SRC_DIR / "sensibility_analysis.py", "Sensitivity Analysis (Full Grid)"): return
    if not run_script(SRC_DIR / "sensibility_analysis_viz.py", "Sensitivity Visualizations (Appendix)"): return

    # 5. Within-Tier Robustness (Level 1)
    print("\n--- PHASE 5: WITHIN-TIER ROBUSTNESS (Level 1) ---")
    if not run_script(SRC_DIR / "within_tier_analysis.py", "Within-Tier Robustness Analysis (z_W × z_S grid)"): return

    print("\n" + "#"*80)
    print("#" + " "*26 + "RISK PIPELINE COMPLETED" + " "*29 + "#")
    print("#"*80 + "\n")

if __name__ == "__main__":
    main()
