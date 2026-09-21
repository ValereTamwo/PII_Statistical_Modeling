"""
ITEM EXPOSURE ENGINE (Pi) - country extension.

Adapted from risk_analysis_PxI/src/item_exposure_engine.py: identical
model (same calibrated betas - expert_eta_calibration.py's output is a
fixed, dataset-independent artifact, reused as-is rather than recalibrated
against country data), but reads/writes under data/user_countries/ for the
6 new-country personas (single PARTIAL policy, AUTH/NOTAUTH naming).
"""

import json
import math
from pathlib import Path


BETAS = {
    # Calibrated coefficients via Ridge Regression in Logit Space
    # (risk_analysis_PxI/src/utils/expert_eta_calibration.py) - fixed,
    # not re-derived from country data.
    "intercept": -2.257,
    "ho": 2.1291,
    "se": 1.2413,
    "ss": 1.0986,
    "tp": 1.2208,
    "pe": 0.8172,
    "interaction_ho_pe": 0.0365
}

USERS    = ["IT_0573", "LU_0634", "PT_0838", "SE_0964", "ES_0290", "DE_0018"]
MODES    = ["AUTH", "NOTAUTH"]
POLICIES = ["PARTIAL"]

def sigmoid(eta):
    return 1 / (1 + math.exp(-eta))

def calculate_pi_exposure(xi):
    """
    Computes Pi = sigma(eta) where eta is the linear combination of technical features.
    eta = b0 + sum bk*xk + b_inter
    """

    eta = BETAS['intercept'] + \
          BETAS['ho'] * xi['js_accessible'] + \
          BETAS['se'] * xi['network_exposed'] + \
          BETAS['ss'] * xi['cross_site'] + \
          BETAS['tp'] * xi['thirdparty'] + \
          BETAS['pe'] * xi['persistent'] + \
          BETAS['interaction_ho_pe'] * (xi['js_accessible'] * xi['persistent'])

    return round(sigmoid(eta), 4)

def process_exposure(data_root: Path, mode: str, user: str, policy: str):
    """Enriches vectorized items with exposure probability scores."""

    vector_dir = data_root / "user_countries" / mode / user / policy / "_vector_data"
    input_file = vector_dir / "vectorized_items.json"

    if not input_file.exists():
        print(input_file)
        return
    with open(input_file, "r", encoding="utf-8") as f:
        items = json.load(f)

    for item in items:
        item['pi_exposure'] = calculate_pi_exposure(item['xi'])

    output_file = vector_dir / "vectorized_items_with_exposure.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2, ensure_ascii=False)

    print(f"  [Pi] {mode}/{user}/{policy} : Processed {len(items)} items")

def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    print("=" * 65)
    print("  ITEM EXPOSURE ENGINE - country extension")
    print("  Calculating Pi based on Technical Container Vulnerabilities")
    print("=" * 65)

    for mode in MODES:
        for user in USERS:
            for policy in POLICIES:
                process_exposure(data_root, mode, user, policy)

    print("=" * 65)
    print("  Technical Exposure Probability (Pi) stored.")
    print("=" * 65)

if __name__ == "__main__":
    main()
