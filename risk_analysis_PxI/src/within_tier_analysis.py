"""
WITHIN-TIER ROBUSTNESS ANALYSIS — Level 1
==========================================
Tier-wide perturbation of (z_W, z_S) over the Cartesian grid:
    z_W ∈ {0.1, 0.2, 0.3}  ×  z_S ∈ {0.5, 0.6, 0.7}  →  9 configurations.

For each configuration:
  - Reconstruct PII_IMPACT_MAP from ordinal TIER_MAP + (z_W, z_S)
  - Recompute Ii (Noisy-OR) and Ri = Pi × Ii for all items
  - Evaluate truth-value of findings F1–F6
  - Classify each finding as Invariant / Highly Robust / Sensitive

Complements the existing alpha_k sensitivity analysis (sensibility_analysis.py).
Together they span the A × Θ robustness space defined in the formal specification.
"""

import json
import numpy as np
from pathlib import Path
from collections import defaultdict


# ════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════

USERS    = ["FR_0417", "FR_0446", "FR_0458"]
MODES    = ["Auth", "UnAuth"]
POLICIES = ["ALL", "PARTIAL", "NONE"]
STORAGES = ["cookie", "localStorage", "sessionStorage", "IndexedDB"]

ALPHA_KEYS = ['id', 'ato', 'link', 'loc', 'prof', 'env']

DEFAULT_ALPHAS = {
    'id': 0.90, 'ato': 0.95, 'link': 0.85,
    'loc': 0.75, 'prof': 0.70, 'env': 0.50
}

# Level-1 grid  (Eq. 8 of formal specification)
Z_W_GRID = [0.1, 0.2, 0.3]
Z_S_GRID = [0.5, 0.6, 0.7]
TIER_GRID = [(zw, zs) for zw in Z_W_GRID for zs in Z_S_GRID]  # 9 configs


# ════════════════════════════════════════════════════════════
# ORDINAL TIER MAP  — primary theoretical judgment
# Tiers: A (Absent) | W (Weakly Facilitating) |
#        S (Strongly Facilitating) | C (Constitutive)
# Columns: [ID, ATO, LINK, LOC, PROF, ENV]
# ════════════════════════════════════════════════════════════

PII_TIER_MAP = {
    # --- DIRECT IDENTIFICATION ---
    "DIRECT_PII":                   ['C', 'A', 'S', 'A', 'A', 'A'],
    "DIRECT_PII_KEYS":              ['S', 'A', 'S', 'A', 'A', 'A'],

    # --- SECURITY AND ACCESS ---
    "TECHNICAL_PASSWORDS":          ['A', 'C', 'S', 'A', 'A', 'A'],
    "SESSION_MANAGEMENT":           ['A', 'S', 'W', 'A', 'A', 'A'],
    "SECURITY_AND_BOT_MITIGATION":  ['A', 'W', 'W', 'A', 'A', 'A'],

    # --- TRACKING AND AD-TECH ---
    "IDENTITY_TRACKING":            ['A', 'A', 'C', 'A', 'S', 'A'],
    "ID_SOLUTIONS_AND_EXCHANGES":   ['A', 'A', 'C', 'A', 'S', 'A'],
    "SERVER_SIDE_TRACKING":         ['A', 'A', 'S', 'A', 'W', 'A'],

    # --- BEHAVIORAL AND ANALYTICS ---
    "BEHAVIORAL_DATA":              ['A', 'A', 'S', 'A', 'C', 'A'],
    "NAVIGATION_HISTORY":           ['A', 'A', 'S', 'A', 'C', 'A'],
    "USER_PREFERENCES":             ['A', 'A', 'W', 'A', 'S', 'A'],
    "UX_AND_PERFORMANCE_ANALYTICS": ['A', 'A', 'W', 'A', 'S', 'A'],
    "APP_STATE_STORAGE":            ['A', 'A', 'W', 'A', 'W', 'A'],

    # --- LOCATION ---
    "SENSITIVE_LOCATION_PII":       ['A', 'A', 'W', 'C', 'W', 'A'],
    "LOCATION_AND_DEMOGRAPHICS":    ['A', 'W', 'W', 'S', 'W', 'A'],

    # --- DEVICE FINGERPRINTING ---
    "FINGERPRINTING_ADVANCED":      ['A', 'A', 'C', 'A', 'S', 'C'],
    "DEVICE_ENV":                   ['A', 'A', 'S', 'A', 'W', 'C'],

    # --- TECHNICAL AND INFRASTRUCTURE ---
    "INFRASTRUCTURE":               ['A', 'W', 'W', 'A', 'A', 'A'],
    "TELEMETRY_AND_ERRORS":         ['A', 'A', 'W', 'A', 'W', 'W'],
    "CONSENT_AND_PRIVACY":          ['A', 'A', 'S', 'A', 'W', 'A'],
}

# Baseline mapping Z^(0) — kept for reference / audit
PII_IMPACT_MAP_BASELINE = {
    "DIRECT_PII":                   [1.0, 0.0, 0.5, 0.0, 0.0, 0.0],
    "DIRECT_PII_KEYS":              [0.5, 0.0, 0.5, 0.0, 0.0, 0.0],
    "TECHNICAL_PASSWORDS":          [0.0, 1.0, 0.5, 0.0, 0.0, 0.0],
    "SESSION_MANAGEMENT":           [0.0, 0.5, 0.3, 0.0, 0.0, 0.0],
    "SECURITY_AND_BOT_MITIGATION":  [0.0, 0.2, 0.2, 0.0, 0.0, 0.0],
    "IDENTITY_TRACKING":            [0.0, 0.0, 1.0, 0.0, 0.5, 0.0],
    "ID_SOLUTIONS_AND_EXCHANGES":   [0.0, 0.0, 1.0, 0.0, 0.5, 0.0],
    "SERVER_SIDE_TRACKING":         [0.0, 0.0, 0.7, 0.0, 0.3, 0.0],
    "BEHAVIORAL_DATA":              [0.0, 0.0, 0.5, 0.0, 1.0, 0.0],
    "NAVIGATION_HISTORY":           [0.0, 0.0, 0.5, 0.0, 1.0, 0.0],
    "USER_PREFERENCES":             [0.0, 0.0, 0.2, 0.0, 0.7, 0.0],
    "UX_AND_PERFORMANCE_ANALYTICS": [0.0, 0.0, 0.2, 0.0, 0.5, 0.0],
    "APP_STATE_STORAGE":            [0.0, 0.0, 0.1, 0.0, 0.3, 0.0],
    "SENSITIVE_LOCATION_PII":       [0.0, 0.0, 0.3, 1.0, 0.3, 0.0],
    "LOCATION_AND_DEMOGRAPHICS":    [0.0, 0.3, 0.3, 0.5, 0.3, 0.0],
    "FINGERPRINTING_ADVANCED":      [0.0, 0.0, 1.0, 0.0, 0.5, 1.0],
    "DEVICE_ENV":                   [0.0, 0.0, 0.7, 0.0, 0.2, 1.0],
    "INFRASTRUCTURE":               [0.0, 0.2, 0.2, 0.0, 0.0, 0.0],
    "TELEMETRY_AND_ERRORS":         [0.0, 0.0, 0.2, 0.0, 0.2, 0.2],
    "CONSENT_AND_PRIVACY":          [0.0, 0.0, 0.7, 0.0, 0.2, 0.0],
}


# ════════════════════════════════════════════════════════════
# TIER MAP → IMPACT MAP
# ════════════════════════════════════════════════════════════

def build_impact_map(z_W: float, z_S: float) -> dict:
    """
    Reconstruct PII_IMPACT_MAP from ordinal tiers and (z_W, z_S).
    Boundary tiers are singletons: A→0.0, C→1.0.
    All W cells receive z_W; all S cells receive z_S.  (Eq. 7)
    """
    tier_to_value = {'A': 0.0, 'W': z_W, 'S': z_S, 'C': 1.0}
    return {
        cat: [tier_to_value[t] for t in tiers]
        for cat, tiers in PII_TIER_MAP.items()
    }


# ════════════════════════════════════════════════════════════
# CORE UTILITIES  (mirrored from sensibility_analysis.py)
# ════════════════════════════════════════════════════════════

def _z_composite(categories: list, impact_map: dict) -> np.ndarray:
    z = np.zeros(6)
    for cat in categories:
        if cat in impact_map:
            z = np.maximum(z, impact_map[cat])
    return z


def _calculate_ii(z: np.ndarray, alphas: dict) -> float:
    alpha_vals = [alphas[k] for k in ALPHA_KEYS]
    prob = 1.0
    for ak, zk in zip(alpha_vals, z):
        prob *= (1 - ak * zk)
    return 1 - prob


def load_all_items(data_root: Path) -> list:
    all_items = []
    for mode in MODES:
        for user in USERS:
            for policy in POLICIES:
                path = (data_root / "user" / mode / user / policy
                        / "_vector_data" / "vectorized_items_with_exposure.json")
                if not path.exists():
                    continue
                with open(path, encoding="utf-8") as f:
                    items = json.load(f)
                for it in items:
                    it['_mode']   = mode
                    it['_user']   = user
                    it['_policy'] = policy
                    cats = it.get('categories', [it.get('category', '')])
                    if isinstance(cats, str):
                        cats = [cats]
                    it['_cats'] = cats
                    it['_xi']   = it.get('meta', it.get('xi', {}))
                all_items.extend(items)
    print(f"  -> {len(all_items):,} items loaded.")
    return all_items


def _apply_tier_config(items: list, z_W: float, z_S: float, alphas: dict):
    """
    Apply a (z_W, z_S) configuration to all items.
    Recomputes _z, _ii, _risk_i for every item.
    """
    impact_map = build_impact_map(z_W, z_S)
    for it in items:
        it['_z']      = _z_composite(it['_cats'], impact_map)
        it['_ii']     = _calculate_ii(it['_z'], alphas)
        it['_risk_i'] = it['pi_exposure'] * it['_ii']


def _aggregate(items: list) -> dict:
    def mean_val(filt):
        sub = [it['_risk_i'] for it in items if filt(it)]
        return round(sum(sub) / len(sub), 4) if sub else 0.

    return {
        'global_mean_ri' : round(sum(it['_risk_i'] for it in items) / len(items), 4),
        'global_mean_ii' : round(sum(it['_ii']     for it in items) / len(items), 4),
        'mean_by_mode'   : {m: mean_val(lambda it, m=m: it['_mode'] == m)   for m in MODES},
        'mean_by_policy' : {p: mean_val(lambda it, p=p: it['_policy'] == p) for p in POLICIES},
        'mean_by_storage': {s: mean_val(lambda it, s=s: it.get('storage_type', '').lower() == s.lower())
                            for s in STORAGES},
    }


def _describe_storage(items: list) -> dict:
    result = {}
    for st in STORAGES:
        vals = np.array([it['_risk_i'] for it in items
                         if it.get('storage_type', '').lower() == st.lower()])
        if len(vals) == 0:
            result[st] = {'n': 0, 'mean': None, 'median': None,
                          'q1': None, 'q3': None, 'iqr': None}
            continue
        q1, med, q3 = np.percentile(vals, [25, 50, 75])
        result[st] = {
            'n'     : int(len(vals)),
            'mean'  : round(float(vals.mean()), 4),
            'median': round(float(med),  4),
            'q1'    : round(float(q1),   4),
            'q3'    : round(float(q3),   4),
            'iqr'   : round(float(q3 - q1), 4),
        }
    return result


# ════════════════════════════════════════════════════════════
# FINDINGS EVALUATION  (F1–F6, aligned with sensibility_analysis.py claims)
# ════════════════════════════════════════════════════════════

def _evaluate_findings(agg: dict, dist: dict, items: list) -> dict:
    """
    Evaluate the truth-value of findings F1–F6 for a given configuration.
    Definitions aligned with Table 14 of the main paper and
    the claim definitions in sensibility_analysis.py (Step 3).
    """
    mbs = agg['mean_by_storage']
    mbm = agg['mean_by_mode']
    mbp = agg['mean_by_policy']

    # --- Mean-level claims ---
    M1 = bool(abs(mbm.get('Auth', 0) - mbm.get('UnAuth', 0)) < 0.05)
    M2 = bool(mbp.get('ALL', 0) >= mbp.get('NONE', 0))
    M3 = bool(mbs.get('cookie', 0)       > mbs.get('sessionStorage', 0))
    M4 = bool(mbs.get('cookie', 0)       > mbs.get('IndexedDB', 0))
    M5 = bool(abs(mbs.get('cookie', 0)   - mbs.get('localStorage', 0)) < 0.07)
    M6 = bool(mbs.get('localStorage', 0) > mbs.get('sessionStorage', 0))
    M7 = bool(mbs.get('localStorage', 0) > mbs.get('IndexedDB', 0))

    # --- Distributional claims ---
    med_cookie = dist['cookie']['median']
    med_ss     = dist['sessionStorage']['median']
    med_ls     = dist['localStorage']['median']
    iqr_cookie = dist['cookie']['iqr']
    iqr_ss     = dist['sessionStorage']['iqr']
    iqr_ls     = dist['localStorage']['iqr']
    iqr_idb    = dist['IndexedDB']['iqr']

    D1 = bool(med_cookie is not None and med_ss  is not None and med_cookie > med_ss)
    D2 = bool(iqr_idb    is not None and iqr_idb == 0.0)
    D3 = bool(iqr_cookie is not None and iqr_ss  is not None and iqr_cookie > iqr_ss)
    D6 = bool(med_ls is not None and med_cookie is not None
              and abs(med_cookie - med_ls) < 0.09)
    D7 = bool(iqr_ls is not None and iqr_cookie is not None and iqr_ls < iqr_cookie)

    # D4 — |median_Auth - median_UnAuth| < 0.01
    vals_auth   = np.array([it['_risk_i'] for it in items if it['_mode'] == 'Auth'])
    vals_unauth = np.array([it['_risk_i'] for it in items if it['_mode'] == 'UnAuth'])
    med_auth   = float(np.median(vals_auth))   if len(vals_auth)   else None
    med_unauth = float(np.median(vals_unauth)) if len(vals_unauth) else None
    D4 = bool(med_auth is not None and med_unauth is not None
              and abs(med_auth - med_unauth) < 0.01)

    # D5 — cookie median stable across consent policies
    vals_ck_all  = np.array([it['_risk_i'] for it in items
                              if it.get('storage_type', '').lower() == 'cookie'
                              and it['_policy'] == 'ALL'])
    vals_ck_none = np.array([it['_risk_i'] for it in items
                              if it.get('storage_type', '').lower() == 'cookie'
                              and it['_policy'] == 'NONE'])
    if len(vals_ck_all) > 0 and len(vals_ck_none) > 0:
        D5 = bool(abs(float(np.median(vals_ck_all)) - float(np.median(vals_ck_none))) < 0.02)
    else:
        D5 = None

    return {
        # Mean-level
        'M1_auth_unauth_equiv'     : M1,
        'M2_all_gt_none'           : M2,
        'M3_cookie_gt_ss'          : M3,
        'M4_cookie_gt_idb'         : M4,
        'M5_ls_equiv_cookie'       : M5,
        'M6_ls_gt_ss'              : M6,
        'M7_ls_gt_idb'             : M7,
        # Distributional
        'D1_median_cookie_gt_ss'   : D1,
        'D2_idb_iqr_zero'          : D2,
        'D3_iqr_cookie_gt_ss'      : D3,
        'D4_median_mode_equiv'     : D4,
        'D5_cookie_median_stable'  : D5,
        'D6_median_ls_equiv_cookie': D6,
        'D7_iqr_ls_lt_cookie'      : D7,
    }


# ════════════════════════════════════════════════════════════
# ROBUSTNESS SUMMARY
# ════════════════════════════════════════════════════════════

FINDING_LABELS = {
    'M1_auth_unauth_equiv'     : ('mean', 'F6 : |mean_Auth - mean_UnAuth| < 0.05'),
    'M2_all_gt_none'           : ('mean', 'F2 : mean_ALL >= mean_NONE'),
    'M3_cookie_gt_ss'          : ('mean', 'F1/F4 : mean_cookie > mean_sessionStorage'),
    'M4_cookie_gt_idb'         : ('mean', 'F1/F5 : mean_cookie > mean_IndexedDB'),
    'M5_ls_equiv_cookie'       : ('mean', 'F3 : |mean_localStorage - mean_cookie| < 0.07'),
    'M6_ls_gt_ss'              : ('mean', 'F3/F4 : mean_localStorage > mean_sessionStorage'),
    'M7_ls_gt_idb'             : ('mean', 'F3/F5 : mean_localStorage > mean_IndexedDB'),
    'D1_median_cookie_gt_ss'   : ('dist', 'F1/F4 : median_cookie > median_sessionStorage'),
    'D2_idb_iqr_zero'          : ('dist', 'F5 : IQR_IndexedDB = 0'),
    'D3_iqr_cookie_gt_ss'      : ('dist', 'F1 : IQR_cookie > IQR_sessionStorage'),
    'D4_median_mode_equiv'     : ('dist', 'F6 : |median_Auth - median_UnAuth| < 0.01'),
    'D5_cookie_median_stable'  : ('dist', 'F4 : |median_cookie_ALL - median_cookie_NONE| < 0.02'),
    'D6_median_ls_equiv_cookie': ('dist', 'F3 : |median_localStorage - median_cookie| < 0.09'),
    'D7_iqr_ls_lt_cookie'      : ('dist', 'F3 : IQR_localStorage < IQR_cookie'),
}


def _summarize_robustness(results: dict) -> dict:
    """
    Classify each finding over the 9-configuration grid.
      Invariant      → 9/9
      Highly Robust  → 8/9
      Sensitive      → < 8/9
    """
    n = len(results)
    summary = {}
    print(f"\n  {'Finding':<45} {'ok':>4} / {'n':>2}  Classification")
    print(f"  {'-'*72}")
    for key, (level, label) in FINDING_LABELS.items():
        valid = [r for r in results.values() if r['findings'][key] is not None]
        ok    = sum(1 for r in valid if r['findings'][key])
        nv    = len(valid)
        classification = (
            'Invariant'     if ok == nv     else
            'Highly Robust' if ok >= nv - 1 else
            'Sensitive'
        )
        summary[key] = {
            'label'         : label,
            'level'         : level,
            'ok'            : ok,
            'total'         : nv,
            'classification': classification,
        }
        print(f"  [{level.upper()}] {label:<43} {ok:>4} / {nv:>2}  {classification}")
    return summary


# ════════════════════════════════════════════════════════════
# TIER MAP AUDIT — verify TIER_MAP coherence with baseline Z^(0)
# ════════════════════════════════════════════════════════════

def audit_tier_map() -> dict:
    """
    For each cell, verify that the baseline value lies within the tier's
    admissible set Z(t). Reports any inconsistency.
    """
    admissible = {
        'A': lambda v: v == 0.0,
        'W': lambda v: 0.1 <= v <= 0.3,
        'S': lambda v: 0.5 <= v <= 0.7,
        'C': lambda v: v == 1.0,
    }
    dim_names = ['ID', 'ATO', 'LINK', 'LOC', 'PROF', 'ENV']
    violations = []
    for cat, tiers in PII_TIER_MAP.items():
        baseline_vals = PII_IMPACT_MAP_BASELINE.get(cat, [None]*6)
        for k, (tier, bval) in enumerate(zip(tiers, baseline_vals)):
            if bval is None:
                continue
            if not admissible[tier](bval):
                violations.append({
                    'category': cat,
                    'dimension': dim_names[k],
                    'tier': tier,
                    'baseline_value': bval,
                })
    if violations:
        print(f"  [AUDIT] ⚠  {len(violations)} tier/baseline inconsistencies detected:")
        for v in violations:
            print(f"    {v['category']}.{v['dimension']}: tier={v['tier']} but baseline={v['baseline_value']}")
    else:
        print("  [AUDIT] ✓ All baseline values are consistent with their tier assignments.")
    return {'violations': violations}


# ════════════════════════════════════════════════════════════
# MAIN ANALYSIS
# ════════════════════════════════════════════════════════════

def run_tier_robustness(items: list, alphas: dict = DEFAULT_ALPHAS) -> dict:
    """
    Run the Level-1 within-tier robustness analysis over the 9-point grid.
    """
    results = {}
    print(f"\n  {'Config':<20} {'mean_Ii':>8} {'mean_Ri':>8}")
    print(f"  {'-'*40}")

    for z_W, z_S in TIER_GRID:
        label = f"zW={z_W}_zS={z_S}"
        _apply_tier_config(items, z_W, z_S, alphas)
        agg  = _aggregate(items)
        dist = _describe_storage(items)
        findings = _evaluate_findings(agg, dist, items)

        results[label] = {
            'z_W'            : z_W,
            'z_S'            : z_S,
            'global_mean_ii' : agg['global_mean_ii'],
            'global_mean_ri' : agg['global_mean_ri'],
            'mean_by_storage': agg['mean_by_storage'],
            'mean_by_mode'   : agg['mean_by_mode'],
            'mean_by_policy' : agg['mean_by_policy'],
            'dist_by_storage': dist,
            'findings'       : findings,
        }
        print(f"  ({z_W}, {z_S}){'':<12} {agg['global_mean_ii']:>8.4f} {agg['global_mean_ri']:>8.4f}")

    return results


def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    print("=" * 65)
    print("  WITHIN-TIER ROBUSTNESS ANALYSIS — Level 1")
    print("  Grid: z_W ∈ {0.1,0.2,0.3} × z_S ∈ {0.5,0.6,0.7} → 9 configs")
    print("=" * 65)

    # 1. Audit tier-map coherence
    print("\n  [Audit] Checking TIER_MAP vs baseline Z^(0)...")
    audit = audit_tier_map()

    # 2. Load items
    print("\n  [Load] Reading vectorized items...")
    items = load_all_items(data_root)
    if not items:
        print("  ERROR: No items loaded. Check data paths.")
        return

    # 3. Run Level-1 grid
    print("\n  [Level 1] Tier-wide perturbation analysis...")
    results = run_tier_robustness(items)

    # 4. Robustness summary
    print("\n  [Summary] Robustness classification...")
    summary = _summarize_robustness(results)

    # 5. Save
    output = {
        'metadata': {
            'analysis'    : 'within_tier_robustness_level1',
            'grid'        : {'z_W': Z_W_GRID, 'z_S': Z_S_GRID},
            'n_configs'   : len(TIER_GRID),
            'alphas_used' : DEFAULT_ALPHAS,
            'n_items'     : len(items),
        },
        'audit'              : audit,
        'configurations'     : results,
        'robustness_summary' : summary,
    }

    class NumpyEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, (np.bool_,)):
                return bool(obj)
            if isinstance(obj, np.integer):
                return int(obj)
            if isinstance(obj, np.floating):
                return float(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            return super().default(obj)

    out_dir  = base_dir / "data" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "within_tier_robustness_level1.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, cls=NumpyEncoder)

    print(f"\n  Saved → {out_path}")
    print("=" * 65)


if __name__ == "__main__":
    main()
