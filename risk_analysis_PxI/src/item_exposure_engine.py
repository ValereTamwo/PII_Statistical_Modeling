"""
ITEM EXPOSURE ENGINE (Pi)
Computes the technical probability of exposure (Pi) based on storage container vulnerabilities.
Reference: Section 4.1 (Exposure Model)
"""

import json
import math
import numpy as np
from pathlib import Path


BETAS = {
    # Calibrated coefficients via Ridge Regression in Logit Space
    # Optimized for ordinal consistency and expert boundary conditions.
    "intercept": -2.257,
    "ho": 2.1291,
    "se": 1.2413,
    "ss": 1.0986,
    "tp": 1.2208,
    "pe": 0.8172,
    "interaction_ho_pe": 0.0365
}

USERS    = ["FR_0417", "FR_0446", "FR_0458"]
MODES    = ["Auth", "UnAuth"]
POLICIES = ["ALL", "PARTIAL", "NONE"]

def sigmoid(eta):
    return 1 / (1 + math.exp(-eta))

def calculate_pi_exposure(xi):
    """
    Computes Pi = σ(η) where η is the linear combination of technical features.
    η = β0 + Σ βk*xk + β_inter
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
    
    vector_dir = data_root / "user" / mode / user / policy / "_vector_data"
    input_file = vector_dir / "vectorized_items.json"
    
    if not input_file.exists():
        print(input_file)

        return
    with open(input_file, "r", encoding="utf-8") as f:
        items = json.load(f)
    
    for item in items:
        # Technical likelihood estimation
        item['pi_exposure'] = calculate_pi_exposure(item['xi'])
        
    # Persistence of enriched vector
    output_file = vector_dir / "vectorized_items_with_exposure.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2, ensure_ascii=False)
    
    print(f"  [Pi] {mode}/{user}/{policy} : Processed {len(items)} items")

def main():
    # Chemin vers la racine des données (data/)
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    print("=" * 65)
    print("  ITEM EXPOSURE ENGINE")
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