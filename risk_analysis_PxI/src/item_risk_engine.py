"""
ITEM RISK ENGINE (Ri)
Derives the final risk score (Ri) as the product of exposure (Pi) and impact (Ii).
Ri = Pi × Ii
"""
import json
import math
import numpy as np
from pathlib import Path




USERS    = ["FR_0417", "FR_0446", "FR_0458"]
MODES    = ["Auth", "UnAuth"]
POLICIES = ["ALL", "PARTIAL", "NONE"]



def process_risk_items(data_root: Path, mode: str, user: str, policy: str):
    """Calculates risk score for all items in a given configuration."""
    
    vector_dir = data_root / "user" / mode / user / policy / "_vector_data"
    input_file = vector_dir / "vectorized_items_full_scores.json"
    
    if not input_file.exists():
        print(input_file)

        return
    with open(input_file, "r", encoding="utf-8") as f:
        items = json.load(f)
    
    for item in items:
        item['risk_i'] = item['pi_exposure'] * item['ii_impact']
        
    output_file = vector_dir / "vectorized_items_risk_score.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2, ensure_ascii=False)
    
    print(f"  [Pi] {mode}/{user}/{policy} : Processed {len(items)} items")

def main():
    # Root data directory path
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    print("=" * 65)
    print("  ITEM RISK ENGINE")
    print("  Calculating Risk_i based on harm and likelihood (Pi × Ii)")
    print("=" * 65)

    for mode in MODES:
        for user in USERS:
            for policy in POLICIES:
                process_risk_items(data_root, mode, user, policy)

    print("=" * 65)
    print("  Technical Risk Items (Risk_i) stored.")
    print("=" * 65)

if __name__ == "__main__":
    main()