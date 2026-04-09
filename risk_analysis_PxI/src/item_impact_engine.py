import json
import math
import numpy as np
from pathlib import Path

# Ordre du vecteur z : [z_ID, z_ATO, z_LINK, z_LOC, z_PROF, z_ENV]
# z_ID   : Identification (Directe)
# z_ATO  : Account Takeover (Actionabilité/Sécurité)
# z_LINK : Linkability (Tracking cross-site)
# z_LOC  : Location (Géographique)
# z_PROF : Profiling (Comportemental)
# z_ENV  : Environment (Device Fingerprinting)

PII_IMPACT_MAP = {
    # --- IDENTIFICATION DIRECTE ---
    "DIRECT_PII":                 [1.0, 0.0, 0.5, 0.0, 0.0, 0.0],
    "DIRECT_PII_KEYS":            [0.5, 0.0, 0.5, 0.0, 0.0, 0.0],
    
    # --- SÉCURITÉ ET ACCÈS ---
    "TECHNICAL_PASSWORDS":        [0.0, 1.0, 0.5, 0.0, 0.0, 0.0],
    "SESSION_MANAGEMENT":         [0.0, 0.5, 0.3, 0.0, 0.0, 0.0],
    "SECURITY_AND_BOT_MITIGATION":[0.0, 0.2, 0.2, 0.0, 0.0, 0.0],
    
    # --- TRACKING ET PUB ---
    "IDENTITY_TRACKING":          [0.0, 0.0, 1.0, 0.0, 0.5, 0.0],
    "ID_SOLUTIONS_AND_EXCHANGES": [0.0, 0.0, 1.0, 0.0, 0.5, 0.0],
    "SERVER_SIDE_TRACKING":       [0.0, 0.0, 0.7, 0.0, 0.3, 0.0],
    
    # --- COMPORTEMENT ET ANALYTIQUES ---
    "BEHAVIORAL_DATA":            [0.0, 0.0, 0.5, 0.0, 1.0, 0.0],
    "NAVIGATION_HISTORY":         [0.0, 0.0, 0.5, 0.0, 1.0, 0.0],
    "USER_PREFERENCES":           [0.0, 0.0, 0.2, 0.0, 0.7, 0.0],
    "UX_AND_PERFORMANCE_ANALYTICS":[0.0, 0.0, 0.2, 0.0, 0.5, 0.0],
    "APP_STATE_STORAGE":          [0.0, 0.0, 0.1, 0.0, 0.3, 0.0],
    
    # --- LOCALISATION ---
    "SENSITIVE_LOCATION_PII":     [0.0, 0.0, 0.3, 1.0, 0.3, 0.0],
    "LOCATION_AND_DEMOGRAPHICS":  [0.0, 0.3, 0.3, 0.5, 0.3, 0.0],
    
    # --- EMPREINTE APPAREIL ---
    "FINGERPRINTING_ADVANCED":    [0.0, 0.0, 1.0, 0.0, 0.5, 1.0],
    "DEVICE_ENV":                 [0.0, 0.0, 0.7, 0.0, 0.2, 1.0],
    
    # --- TECHNIQUE ET INFRA ---
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
    input_path = data_root / "user" / mode / user / policy / "_vector_data" / "vectorized_items_with_exposure.json"
    if not input_path.exists(): return
    
    with open(input_path, "r", encoding="utf-8") as f:
        items = json.load(f)
    
    for item in items:
        item['ii_impact'] = calculate_item_impact(item['categories'], alphas, item['xi'])
        
    output_path = input_path.parent / "vectorized_items_full_scores.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2, ensure_ascii=False)


def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    print("=" * 65)
    print("  ITEM IMPACT ENGINE")
    print("  Model: Noisy-OR Aggregate with Information-Theoretic Boost")
    print("=" * 65)

    for mode in ["Auth", "UnAuth"]:
        for user in ["FR_0417", "FR_0446", "FR_0458"]:
            for policy in ["ALL", "PARTIAL", "NONE"]:
                process_impact_for_policy(data_root, mode, user, policy)

if __name__ == "__main__":
    main()