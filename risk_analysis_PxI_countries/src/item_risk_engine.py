"""
ITEM RISK ENGINE (Ri) - country extension.
Derives the final risk score (Ri) as the product of exposure (Pi) and impact (Ii).
Ri = Pi x Ii

Adapted from risk_analysis_PxI/src/item_risk_engine.py: identical formula,
reads/writes under data/user_countries/ for the 6 new-country personas
(single PARTIAL policy, AUTH/NOTAUTH naming).
"""
import json
from pathlib import Path


USERS    = ["IT_0573", "LU_0634", "PT_0838", "SE_0964", "ES_0290", "DE_0018"]
MODES    = ["AUTH", "NOTAUTH"]
POLICIES = ["PARTIAL"]


def process_risk_items(data_root: Path, mode: str, user: str, policy: str):
    """Calculates risk score for all items in a given configuration."""

    vector_dir = data_root / "user_countries" / mode / user / policy / "_vector_data"
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

    print(f"  [Ri] {mode}/{user}/{policy} : Processed {len(items)} items")

def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    print("=" * 65)
    print("  ITEM RISK ENGINE - country extension")
    print("  Calculating Risk_i based on harm and likelihood (Pi x Ii)")
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
