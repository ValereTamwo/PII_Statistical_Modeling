"""
WITHIN-TIER ROBUSTNESS ANALYSIS — Level 1
==========================================
Tier-wide perturbation of (z_W, z_S) over the Cartesian grid:
    z_W ∈ {0.1, 0.2, 0.3}  ×  z_S ∈ {0.5, 0.6, 0.7}  →  9 configurations.

For each configuration:
  - Rebuild the PII impact map from the ordinal TIER_MAP + (z_W, z_S)
    (A → 0, W → z_W, S → z_S, C → 1)
  - Recompute I_i (Noisy-OR, default alphas) and R_i = P_i × I_i
  - Evaluate the SAME 13 RQ4 claims as the alpha_k analysis
    (O1–O6, D1–D2, C1–C3, S1–S2), with the same definitions, tolerance,
    benchmark and status rule. The claim code is imported from the alpha_k
    script, so both analyses can never drift apart.

Complements the alpha_k sensitivity analysis. Together they span the
A × Θ robustness space defined in the formal specification.
"""

import json
import sys
from pathlib import Path

import numpy as np

# ── Shared claim machinery (single source of truth) ──────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import sensitivity_analysis as sa
except ImportError:                                   # alternative file name
    import sensibility_analysis as sa

USERS, MODES, POLICIES, STORAGES = sa.USERS, sa.MODES, sa.POLICIES, sa.STORAGES
DEFAULT_ALPHAS = sa.DEFAULT_ALPHAS


# ════════════════════════════════════════════════════════════
# GRID
# ════════════════════════════════════════════════════════════

Z_W_GRID  = [0.1, 0.2, 0.3]
Z_S_GRID  = [0.5, 0.6, 0.7]
TIER_GRID = [(zw, zs) for zw in Z_W_GRID for zs in Z_S_GRID]     # 9 configs


# ════════════════════════════════════════════════════════════
# ORDINAL TIER MAP — primary theoretical judgment
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
    "SERVER_SIDE_TRACKING":         ['A', 'A', 'S', 'A', 'W', 'A'],
    "ID_SOLUTIONS_AND_EXCHANGES":   ['A', 'A', 'C', 'A', 'S', 'A'],
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

# Baseline mapping Z^(0) = the impact map used in the paper (imported, not copied)
PII_IMPACT_MAP_BASELINE = sa.PII_IMPACT_MAP


def build_impact_map(z_W: float, z_S: float) -> dict:
    """A → 0, W → z_W, S → z_S, C → 1 (boundary tiers are singletons)."""
    tier_to_value = {'A': 0.0, 'W': z_W, 'S': z_S, 'C': 1.0}
    return {cat: [tier_to_value[t] for t in tiers] for cat, tiers in PII_TIER_MAP.items()}


def audit_tier_map() -> dict:
    """Check that every baseline value lies in the admissible range of its tier."""
    admissible = {
        'A': lambda v: v == 0.0,
        'W': lambda v: 0.1 <= v <= 0.3,
        'S': lambda v: 0.5 <= v <= 0.7,
        'C': lambda v: v == 1.0,
    }
    dims = ['ID', 'ATO', 'LINK', 'LOC', 'PROF', 'ENV']
    violations = []
    missing = sorted(set(PII_IMPACT_MAP_BASELINE) ^ set(PII_TIER_MAP))
    for cat, tiers in PII_TIER_MAP.items():
        base = PII_IMPACT_MAP_BASELINE.get(cat)
        if base is None:
            continue
        for k, (tier, v) in enumerate(zip(tiers, base)):
            if not admissible[tier](v):
                violations.append({'category': cat, 'dimension': dims[k],
                                   'tier': tier, 'baseline_value': v})
    if missing:
        print(f"  [AUDIT] categories not in both maps: {missing}")
    if violations:
        print(f"  [AUDIT] {len(violations)} tier/baseline inconsistencies:")
        for v in violations:
            print(f"    {v['category']}.{v['dimension']}: tier={v['tier']} "
                  f"but baseline={v['baseline_value']}")
    else:
        print("  [AUDIT] OK — all baseline values are consistent with their tiers.")
    return {'violations': violations, 'missing_categories': missing}


# ════════════════════════════════════════════════════════════
# DATA — same loading as the alpha_k script, but the impact map changes
# per configuration, so items are indexed by their category set.
# ════════════════════════════════════════════════════════════

def load_dataset(data_root: Path):
    """Returns a sa.Dataset-compatible object (P, storage, mode, policy, masks)
    plus, per item, the index of its category set. Z is set per configuration."""
    P, st, md, po, cat_idx = [], [], [], [], []
    cat_sets, cat_pos = [], {}
    n_other = 0
    for mode in MODES:
        for user in USERS:
            for policy in POLICIES:
                path = (data_root / "user" / mode / user / policy
                        / "_vector_data" / "vectorized_items_with_exposure.json")
                if not path.exists():
                    print(f"  [warn] missing: {path}")
                    continue
                with open(path, encoding="utf-8") as f:
                    items = json.load(f)
                for it in items:
                    cats = it.get('categories', [it.get('category', '')])
                    if isinstance(cats, str):
                        cats = [cats]
                    key = tuple(sorted(set(cats)))
                    if key not in cat_pos:
                        cat_pos[key] = len(cat_sets)
                        cat_sets.append(key)
                    s = sa._STORAGE_CANON.get(str(it.get('storage_type', '')).lower(), "other")
                    n_other += s == "other"
                    P.append(float(it['pi_exposure']))
                    st.append(s); md.append(mode); po.append(policy)
                    cat_idx.append(cat_pos[key])

    ds = sa.Dataset.__new__(sa.Dataset)          # reuse mask()/risk(), skip its loader
    ds.P       = np.asarray(P, dtype=float)
    ds.storage = np.asarray(st)
    ds.mode    = np.asarray(md)
    ds.policy  = np.asarray(po)
    ds.n       = len(ds.P)
    ds.z_inv   = np.asarray(cat_idx)
    ds._masks  = {}
    print(f"  -> {ds.n:,} items loaded ({len(cat_sets)} distinct category sets, "
          f"{n_other} with unknown storage).")
    return ds, cat_sets


def set_impact_map(ds, cat_sets: list, impact_map: dict):
    """Composite z-vector (element-wise max over categories) per category set."""
    ds.Zu = np.vstack([_z_composite(cats, impact_map) for cats in cat_sets])


def _z_composite(categories, impact_map: dict) -> np.ndarray:
    z = np.zeros(6)
    for cat in categories:
        if cat in impact_map:
            z = np.maximum(z, impact_map[cat])
    return z


# ════════════════════════════════════════════════════════════
# ANALYSIS
# ════════════════════════════════════════════════════════════

def run_tier_robustness(ds, cat_sets: list) -> dict:
    # Reference: the baseline map Z^(0) used in the paper
    set_impact_map(ds, cat_sets, PII_IMPACT_MAP_BASELINE)
    baseline = sa.evaluate_claims(sa.summarize(ds, ds.risk(DEFAULT_ALPHAS)))

    configs = {}
    print(f"\n  {'Config':<16}{'mean_Ri':>9}  " + " ".join(f"{c[0]:>3}" for c in sa.CLAIMS))
    print(f"  {'-' * (27 + 4 * len(sa.CLAIMS))}")
    for z_W, z_S in TIER_GRID:
        label = f"zW={z_W}_zS={z_S}"
        set_impact_map(ds, cat_sets, build_impact_map(z_W, z_S))
        S   = sa.summarize(ds, ds.risk(DEFAULT_ALPHAS))
        res = sa.evaluate_claims(S)
        configs[label] = {
            'z_W': z_W, 'z_S': z_S,
            'global_mean_ri' : sa._r(S['global']['mean']),
            'mean_by_storage': {s: sa._r(S['storage_policy'][f"{s}|{sa.REF_POLICY}"]['mean'])
                                for s in STORAGES},
            'claims'         : res,
        }
        marks = " ".join(f"{'ok' if res[c[0]]['ok'] else ('--' if res[c[0]]['ok'] is None else 'X'):>3}"
                         for c in sa.CLAIMS)
        print(f"  ({z_W}, {z_S}){'':<6}{S['global']['mean']:>9.4f}  {marks}")
    return {'baseline': baseline, 'configs': configs}


def summarize_robustness(run: dict) -> dict:
    configs, baseline = run['configs'], run['baseline']
    summary = {}
    print(f"\n  {'ID':<4}{'Finding':<8}{'Baseline Z0':<30}{'Rate':>7}  {'Status':<12}Failing configs")
    print(f"  {'-' * 95}")
    for cid, finding, level, desc, latex in sa.CLAIMS:
        valid = {k: v for k, v in configs.items() if v['claims'][cid]['ok'] is not None}
        ok    = sum(v['claims'][cid]['ok'] for v in valid.values())
        fails = [f"({v['z_W']},{v['z_S']})" for v in valid.values() if not v['claims'][cid]['ok']]
        # min / max of every audited quantity over the 9 configurations
        grid_range = {}
        for k in baseline[cid]['raw']:
            vals = [v['claims'][cid]['raw'][k] for v in valid.values()
                    if v['claims'][cid]['raw'][k] is not None]
            if vals:
                grid_range[k] = {'min': min(vals), 'max': max(vals)}
        summary[cid] = {
            'finding': finding, 'level': level, 'description': desc, 'latex': latex,
            'baseline_ok': baseline[cid]['ok'], 'baseline_value': baseline[cid]['value'],
            'ok': ok, 'total': len(valid), 'excluded': len(configs) - len(valid),
            'rate': sa._r(ok / len(valid)) if valid else None,
            'status': sa.status_of(ok, len(valid)),
            'failing_configs': fails, 'grid_range': grid_range,
        }
        flag = "" if baseline[cid]['ok'] else "  <-- FAILS AT BASELINE"
        print(f"  {cid:<4}{finding:<8}{baseline[cid]['value']:<30}{ok:>3}/{len(valid):<3}  "
              f"{summary[cid]['status']:<12}{', '.join(fails)}{flag}")

    gr = lambda cid, k: summary[cid]['grid_range'][k]
    print("\n  Worst cases over the 9 configurations:")
    print(f"     C1 consent effect max = {gr('C1','max_consent_gap')['max']:.4f}   "
          f"API range min = {gr('C1','api_range')['min']:.4f}")
    print(f"     S1 session effect max = {gr('S1','max_mode_gap')['max']:.4f}   "
          f"API range min = {gr('S1','api_range')['min']:.4f}")
    print("     C2 max |median ALL - NONE| = "
          + ", ".join(f"{s}={gr('C2', s)['max']:.4f}" for s in ("cookie", "localStorage", "IndexedDB")))
    print(f"     C3 max |Q3 cookie ALL - NONE| = {gr('C3','delta_q3')['max']:.4f}")
    print("     D2 max IQR IDB = " + ", ".join(f"{p}={gr('D2', p)['max']:.4f}" for p in POLICIES))
    return summary


def latex_rows(summary: dict) -> str:
    """Rows for a table mirroring tab:ranking_stability (rate over 9 configs)."""
    lines, current = [], None
    headers = {'ordinal': 'Ordinal claims (storage ranking)',
               'distributional': 'Distributional claims',
               'consent': 'Consent invariance (ALL vs.\\ NONE)',
               'session': 'Session mode (ALL policy)'}
    for cid, _, level, _, _ in sa.CLAIMS:
        c = summary[cid]
        if level != current:
            if current is not None:
                lines.append(r"\midrule")
            lines.append(rf"\multicolumn{{5}}{{@{{}}l}}{{\textit{{{headers[level]}}}}} \\[2pt]")
            current = level
        base_tex = c['baseline_value'].replace('%', r'\%')
        row = f"{c['finding']} & {c['latex']} & {base_tex} & {c['ok']}/{c['total']} & {c['status']} " + r"\\"
        if c['failing_configs']:
            row += "  % fails at (z_W,z_S) = " + ", ".join(c['failing_configs'])
        lines.append(row)
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"
    out_dir   = data_root / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("  WITHIN-TIER ROBUSTNESS ANALYSIS — Level 1")
    print("  Grid: z_W ∈ {0.1,0.2,0.3} × z_S ∈ {0.5,0.6,0.7} → 9 configs")
    print("  Claims: same 13 claims as the alpha_k analysis (default alphas)")
    print("=" * 70)

    print("\n  [Audit] Checking TIER_MAP vs baseline Z^(0)...")
    audit = audit_tier_map()

    print("\n  [Load] Reading vectorized items...")
    ds, cat_sets = load_dataset(data_root)
    if ds.n == 0:
        print("  ERROR: no items loaded. Check data paths.")
        return

    # Sanity: with the baseline map, the claim inputs must reproduce the paper
    set_impact_map(ds, cat_sets, PII_IMPACT_MAP_BASELINE)
    stats_candidates = [out_dir / "risk_statistics.json",
                        Path(__file__).resolve().parent / "reports" / "risk_statistics.json"]
    stats_path = next((p for p in stats_candidates if p.exists()), stats_candidates[0])
    sanity = sa.stage0_sanity(ds, Path(__file__).resolve().parent / "reports" / "risk_statistics.json")


    print("\n  [Level 1] Tier-wide perturbation...")
    run = run_tier_robustness(ds, cat_sets)

    print("\n  [Summary] Robustness over the 9 configurations...")
    summary = summarize_robustness(run)

    output = {
        'metadata': {
            'analysis'   : 'within_tier_robustness_level1',
            'grid'       : {'z_W': Z_W_GRID, 'z_S': Z_S_GRID},
            'n_configs'  : len(TIER_GRID),
            'alphas_used': DEFAULT_ALPHAS,
            'n_items'    : int(ds.n),
            'claims_from': sa.__name__,
            'conventions': {'ref_policy': sa.REF_POLICY, 'tol': sa.TOL,
                            'robust_rate': sa.ROBUST_RATE,
                            'composition_share': sa.COMPOSITION_SHARE},
        },
        'audit'             : audit,
        'sanity'            : sanity,
        'baseline_claims'   : run['baseline'],
        'configurations'    : run['configs'],
        'robustness_summary': summary,
    }
    out_path = out_dir / "within_tier_robustness_level1.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, cls=sa._Encoder)
    tex_path = out_dir / "within_tier_claims_rows.tex"
    tex_path.write_text(latex_rows(summary), encoding="utf-8")

    print(f"\n  Saved: {out_path}")
    print(f"  Saved: {tex_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()