"""
ITEM IMPACT ENGINE (Ii) - country extension.

Adapted from risk_analysis_PxI/src/item_impact_engine.py: identical
PII_IMPACT_MAP and DEFAULT_ALPHAS (fixed, dataset-independent expert
weights), identical Noisy-OR formula, but reads/writes under
data/user_countries/ for the 6 new-country personas (single PARTIAL
policy, AUTH/NOTAUTH naming).

Note ported as-is from the FR version: the entropy/is_json_value "boost"
factor is computed but not applied (the multiplied return is commented
out in the original) - kept identical here for parity. Flag to the user
if this should be revisited.
"""
import json
import math
import sys
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from countries_config import add_users_arg, resolve_users

# Vector order z: [z_ID, z_ATO, z_LINK, z_LOC, z_PROF, z_ENV]
# z_ID   : Direct identification
# z_ATO  : Account Takeover (actionability/security)
# z_LINK : Linkability (cross-site tracking)
# z_LOC  : Location (geographic)
# z_PROF : Profiling (behavioral)
# z_ENV  : Environment (device fingerprinting)

PII_IMPACT_MAP = {
    # --- DIRECT IDENTIFICATION ---
    "DIRECT_PII":                 [1.0, 0.0, 0.5, 0.0, 0.0, 0.0],
    "DIRECT_PII_KEYS":            [0.5, 0.0, 0.5, 0.0, 0.0, 0.0],

    # --- SECURITY AND ACCESS ---
    "TECHNICAL_PASSWORDS":        [0.0, 1.0, 0.5, 0.0, 0.0, 0.0],
    "SESSION_MANAGEMENT":         [0.0, 0.5, 0.3, 0.0, 0.0, 0.0],
    "SECURITY_AND_BOT_MITIGATION":[0.0, 0.2, 0.2, 0.0, 0.0, 0.0],

    # --- TRACKING AND ADVERTISING ---
    "IDENTITY_TRACKING":          [0.0, 0.0, 1.0, 0.0, 0.5, 0.0],
    "ID_SOLUTIONS_AND_EXCHANGES": [0.0, 0.0, 1.0, 0.0, 0.5, 0.0],
    "SERVER_SIDE_TRACKING":       [0.0, 0.0, 0.7, 0.0, 0.3, 0.0],

    # --- BEHAVIOR AND ANALYTICS ---
    "BEHAVIORAL_DATA":            [0.0, 0.0, 0.5, 0.0, 1.0, 0.0],
    "NAVIGATION_HISTORY":         [0.0, 0.0, 0.5, 0.0, 1.0, 0.0],
    "USER_PREFERENCES":           [0.0, 0.0, 0.2, 0.0, 0.7, 0.0],
    "UX_AND_PERFORMANCE_ANALYTICS":[0.0, 0.0, 0.2, 0.0, 0.5, 0.0],
    "APP_STATE_STORAGE":          [0.0, 0.0, 0.1, 0.0, 0.3, 0.0],

    # --- LOCATION ---
    "SENSITIVE_LOCATION_PII":     [0.0, 0.0, 0.3, 1.0, 0.3, 0.0],
    "LOCATION_AND_DEMOGRAPHICS":  [0.0, 0.3, 0.3, 0.5, 0.3, 0.0],

    # --- DEVICE FINGERPRINT ---
    "FINGERPRINTING_ADVANCED":    [0.0, 0.0, 1.0, 0.0, 0.5, 1.0],
    "DEVICE_ENV":                 [0.0, 0.0, 0.7, 0.0, 0.2, 1.0],

    # --- TECHNICAL / INFRA ---
    "INFRASTRUCTURE":             [0.0, 0.2, 0.2, 0.0, 0.0, 0.0],
    "TELEMETRY_AND_ERRORS":       [0.0, 0.0, 0.2, 0.0, 0.2, 0.2],
    "CONSENT_AND_PRIVACY":        [0.0, 0.0, 0.7, 0.0, 0.2, 0.0],
}



DEFAULT_ALPHAS = {
    'id': 0.90, 'ato': 0.95, 'link': 0.85, 'loc': 0.75, 'prof': 0.70, 'env': 0.50
}


def calculate_item_impact(categories, alphas, xi):
    """
    Computes Ii using a Noisy-OR model over the composite impact vector.
    """
    prob_no_impact = 1.0

    z_composite = np.zeros(6)
    for cat in categories:
        if cat in PII_IMPACT_MAP:
            z_composite = np.maximum(z_composite, PII_IMPACT_MAP[cat])

    alpha_vals = [alphas['id'], alphas['ato'], alphas['link'], alphas['loc'], alphas['prof'], alphas['env']]
    for ak, zk in zip(alpha_vals, z_composite):
        prob_no_impact *= (1 - ak * zk)

    base_impact = 1 - prob_no_impact

    boost = (1 + xi['entropy'] * 0.2) * (1 + xi['is_json_value'] * 0.3)

    # return round(min(base_impact * boost, 1.0), 4)
    return base_impact

def process_impact_for_policy(data_root, mode, user, policy, alphas=DEFAULT_ALPHAS):
    input_path = data_root / "user_countries" / mode / user / policy / "_vector_data" / "vectorized_items_with_exposure.json"
    if not input_path.exists(): return

    with open(input_path, "r", encoding="utf-8") as f:
        items = json.load(f)

    for item in items:
        item['ii_impact'] = calculate_item_impact(item['categories'], alphas, item['xi'])

    output_path = input_path.parent / "vectorized_items_full_scores.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2, ensure_ascii=False)


def main(users=None):
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    users = users or resolve_users(None)

    print("=" * 65)
    print("  ITEM IMPACT ENGINE - country extension")
    print("  Model: Noisy-OR Aggregate with Information-Theoretic Boost")
    print("=" * 65)
    print(f"Scoped to users: {users}")

    for mode in ["AUTH", "NOTAUTH"]:
        for user in users:
            for policy in ["PARTIAL"]:
                process_impact_for_policy(data_root, mode, user, policy)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
