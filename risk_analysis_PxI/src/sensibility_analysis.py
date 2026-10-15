"""
SENSITIVITY ANALYSIS FRAMEWORK — PxI risk model (robustness of RQ4)

  Stage 0: Sanity check — the DEFAULT calibration must reproduce
           risk_statistics.json (the numbers used in the paper).
  Stage 1: One-at-a-time (OAT) perturbation, 6 dims x 10 values = 60 configs.
           Sensitivity index Delta_k = mean R(alpha_k=1.0) - mean R(alpha_k=0.1),
           globally, per storage API and per session mode.
  Stage 2: Bounds MIN / DEFAULT / MAX: median and IQR per storage API.
  Stage 3: Robustness of the RQ4 claims over the 60 OAT configurations.
  Stage 4: Global sensitivity analysis (Sobol indices).

Conventions :
  - Ordinal / distributional claims are evaluated under the reference
    policy REF_POLICY = "ALL", Auth + UnAuth pooled
  - Equality claims use a purely numerical tolerance TOL = 1e-3
    (quantile interpolation / rounding), not a substantive threshold.
  - "Small" effects (consent, session mode) are benchmarked against the
    size of the storage-API effect, i.e. the range (max - min) of the
    per-API mean risk, recomputed at each configuration.
    NOTE: a first version used the smallest gap between adjacent APIs.
    That benchmark degenerates whenever two APIs have equal means
    (cookie vs localStorage: 0.6183 vs 0.6176 -> gap 0.0007), whatever the
    effect being measured, so it was replaced by the range. Both values
    are still written to the JSON for transparency.  - Status: Invariant = 100 %, Robust >= 90 %, Conditional < 90 %.
"""

import json
from pathlib import Path

import numpy as np

# ════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════

USERS      = ["FR_0417", "FR_0446", "FR_0458"]
MODES      = ["Auth", "UnAuth"]
POLICIES   = ["ALL", "PARTIAL", "NONE"]
STORAGES   = ["cookie", "localStorage", "sessionStorage", "IndexedDB"]
ALPHA_KEYS = ['id', 'ato', 'link', 'loc', 'prof', 'env']
ALPHA_GRID = [round(x * 0.1, 1) for x in range(1, 11)]

DEFAULT_ALPHAS = {
    'id': 0.90, 'ato': 0.95, 'link': 0.85,
    'loc': 0.75, 'prof': 0.70, 'env': 0.50,
}

REF_POLICY         = "ALL"   # policy used for ranking / distributional claims
TOL                = 1e-3    # numerical tolerance for equality claims
ACTIVITY_THRESHOLD = 0.05    # OAT: a dimension is "active" if Delta_k > 0.05
ROBUST_RATE        = 0.90    # status threshold Robust / Conditional
COMPOSITION_SHARE  = 0.50    # S2: composition explains the majority of the gap
SOBOL_N            = 1024
SOBOL_SEED         = 42

PII_IMPACT_MAP = {
    "DIRECT_PII":                  [1.0, 0.0, 0.5, 0.0, 0.0, 0.0],
    "DIRECT_PII_KEYS":             [0.5, 0.0, 0.5, 0.0, 0.0, 0.0],
    "TECHNICAL_PASSWORDS":         [0.0, 1.0, 0.5, 0.0, 0.0, 0.0],
    "SESSION_MANAGEMENT":          [0.0, 0.5, 0.3, 0.0, 0.0, 0.0],
    "SECURITY_AND_BOT_MITIGATION": [0.0, 0.2, 0.2, 0.0, 0.0, 0.0],
    "IDENTITY_TRACKING":           [0.0, 0.0, 1.0, 0.0, 0.5, 0.0],
    "ID_SOLUTIONS_AND_EXCHANGES":  [0.0, 0.0, 1.0, 0.0, 0.5, 0.0],
    "SERVER_SIDE_TRACKING":        [0.0, 0.0, 0.7, 0.0, 0.3, 0.0],
    "BEHAVIORAL_DATA":             [0.0, 0.0, 0.5, 0.0, 1.0, 0.0],
    "NAVIGATION_HISTORY":          [0.0, 0.0, 0.5, 0.0, 1.0, 0.0],
    "USER_PREFERENCES":            [0.0, 0.0, 0.2, 0.0, 0.7, 0.0],
    "UX_AND_PERFORMANCE_ANALYTICS":[0.0, 0.0, 0.2, 0.0, 0.5, 0.0],
    "APP_STATE_STORAGE":           [0.0, 0.0, 0.1, 0.0, 0.3, 0.0],
    "SENSITIVE_LOCATION_PII":      [0.0, 0.0, 0.3, 1.0, 0.3, 0.0],
    "LOCATION_AND_DEMOGRAPHICS":   [0.0, 0.3, 0.3, 0.5, 0.3, 0.0],
    "FINGERPRINTING_ADVANCED":     [0.0, 0.0, 1.0, 0.0, 0.5, 1.0],
    "DEVICE_ENV":                  [0.0, 0.0, 0.7, 0.0, 0.2, 1.0],
    "INFRASTRUCTURE":              [0.0, 0.2, 0.2, 0.0, 0.0, 0.0],
    "TELEMETRY_AND_ERRORS":        [0.0, 0.0, 0.2, 0.0, 0.2, 0.2],
    "CONSENT_AND_PRIVACY":         [0.0, 0.0, 0.7, 0.0, 0.2, 0.0],
}

_STORAGE_CANON = {s.lower(): s for s in STORAGES}


# ════════════════════════════════════════════════════════════
# DATA (vectorised)
# ════════════════════════════════════════════════════════════

def _z_composite(categories: list) -> np.ndarray:
    z = np.zeros(6)
    for cat in categories:
        if cat in PII_IMPACT_MAP:
            z = np.maximum(z, PII_IMPACT_MAP[cat])
    return z


class Dataset:
    """All items as numpy arrays. I_i depends only on the z-vector, so it is
    computed once per distinct z-vector (a few dozen) and broadcast."""

    def __init__(self, data_root: Path):
        P, Z, st, md, po = [], [], [], [], []
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
                        s = _STORAGE_CANON.get(str(it.get('storage_type', '')).lower(), "other")
                        n_other += s == "other"
                        P.append(float(it['pi_exposure']))
                        Z.append(_z_composite(cats))
                        st.append(s)
                        md.append(mode)
                        po.append(policy)

        self.P       = np.asarray(P, dtype=float)
        self.storage = np.asarray(st)
        self.mode    = np.asarray(md)
        self.policy  = np.asarray(po)
        self.n       = len(self.P)
        self.Zu, inv = np.unique(np.vstack(Z), axis=0, return_inverse=True)
        self.z_inv   = inv.reshape(-1)
        self._masks  = {}
        print(f"  -> {self.n:,} items loaded "
              f"({len(self.Zu)} distinct z-vectors, {n_other} with unknown storage).")

    def mask(self, storage=None, policy=None, mode=None) -> np.ndarray:
        key = (storage, policy, mode)
        if key not in self._masks:
            m = np.ones(self.n, dtype=bool)
            if storage: m &= self.storage == storage
            if policy:  m &= self.policy == policy
            if mode:    m &= self.mode == mode
            self._masks[key] = m
        return self._masks[key]

    def impact_unique(self, alphas: dict) -> np.ndarray:
        a = np.array([alphas[k] for k in ALPHA_KEYS])
        return 1.0 - np.prod(1.0 - self.Zu * a, axis=1)

    def risk(self, alphas: dict) -> np.ndarray:
        return self.P * self.impact_unique(alphas)[self.z_inv]


# ════════════════════════════════════════════════════════════
# DESCRIPTIVE STATISTICS
# ════════════════════════════════════════════════════════════

def describe(v: np.ndarray):
    """No rounding here: rounding happens only at output time."""
    if v.size == 0:
        return None
    q1, med, q3 = np.percentile(v, [25, 50, 75])
    return {'n': int(v.size), 'mean': float(v.mean()), 'median': float(med),
            'q1': float(q1), 'q3': float(q3), 'iqr': float(q3 - q1),
            'max': float(v.max())}


def summarize(ds: Dataset, R: np.ndarray) -> dict:
    S = {'global': describe(R), 'storage': {}, 'mode': {}, 'policy': {},
         'storage_policy': {}, 'storage_policy_mode': {}, 'policy_mode': {}}
    for s in STORAGES:
        S['storage'][s] = describe(R[ds.mask(storage=s)])
        for p in POLICIES:
            S['storage_policy'][f"{s}|{p}"] = describe(R[ds.mask(storage=s, policy=p)])
            for m in MODES:
                S['storage_policy_mode'][f"{s}|{p}|{m}"] = describe(
                    R[ds.mask(storage=s, policy=p, mode=m)])
    for p in POLICIES:
        S['policy'][p] = describe(R[ds.mask(policy=p)])
        for m in MODES:
            S['policy_mode'][f"{p}|{m}"] = describe(R[ds.mask(policy=p, mode=m)])
    for m in MODES:
        S['mode'][m] = describe(R[ds.mask(mode=m)])
    return S


def _r(x, d=4):
    return None if x is None else round(float(x), d)


# ════════════════════════════════════════════════════════════
# RQ4 CLAIMS
# ════════════════════════════════════════════════════════════

CLAIMS = [
    # id,  finding, level,           description,                                                    LaTeX
    ("O1", "F5",    "ordinal",       "median IDB > median cookie (ALL)",
     r"$\tilde{R}_{\text{IDB}} > \tilde{R}_{\text{cookie}}$"),
    ("O2", "F5",    "ordinal",       "mean IDB > mean cookie (ALL)",
     r"$\bar{R}_{\text{IDB}} > \bar{R}_{\text{cookie}}$"),
    ("O3", "F1/F3", "ordinal",       "median cookie > median LS (ALL)",
     r"$\tilde{R}_{\text{cookie}} > \tilde{R}_{\text{LS}}$"),
    ("O4", "F1/F3", "ordinal",       "mean cookie > mean LS (ALL)",
     r"$\bar{R}_{\text{cookie}} > \bar{R}_{\text{LS}}$"),
    ("O5", "F3/F4", "ordinal",       "median LS > median SS (ALL)",
     r"$\tilde{R}_{\text{LS}} > \tilde{R}_{\text{SS}}$"),
    ("O6", "F3/F4", "ordinal",       "mean LS > mean SS (ALL)",
     r"$\bar{R}_{\text{LS}} > \bar{R}_{\text{SS}}$"),
    ("D1", "F1",    "distributional", "IQR cookie > max IQR of other APIs (ALL)",
     r"$\mathrm{IQR}_{\text{cookie}} > \max_{s \neq \text{cookie}} \mathrm{IQR}_s$"),
    ("D2", "F5",    "distributional", "IQR IDB = 0 (+-TOL) under ALL, PARTIAL, NONE",
     r"$\mathrm{IQR}_{\text{IDB}} = 0$ under all policies"),
    ("C1", "F2",    "consent",       "max_s |mean_ALL - mean_NONE| < range of API means (ALL)",
     r"$\max_s |\bar{R}_{s,\text{ALL}} - \bar{R}_{s,\text{NONE}}| < \max_s \bar{R}_s - \min_s \bar{R}_s$"),
    ("C2", "F2",    "consent",       "median_ALL = median_NONE (+-TOL) for cookie, LS, IDB",
     r"$\tilde{R}_{s,\text{ALL}} = \tilde{R}_{s,\text{NONE}}$, $s \in \{\text{cookie, LS, IDB}\}$"),
    ("C3", "F2",    "consent",       "Q3 cookie ALL = Q3 cookie NONE (+-TOL)",
     r"$Q_{3,\text{ALL}}^{\text{cookie}} = Q_{3,\text{NONE}}^{\text{cookie}}$"),
    ("S1", "F6",    "session",       "max_s |mean_Auth - mean_UnAuth| < range of API means (ALL)",
     r"$\max_s |\bar{R}^{\text{Auth}}_s - \bar{R}^{\text{UnAuth}}_s| < \max_s \bar{R}_s - \min_s \bar{R}_s$"),
    ("S2", "F6",    "session",       "composition explains >= 50% of the Auth/UnAuth mean gap (ALL)",
     r"Composition explains $\geq 50\%$ of $|\bar{R}^{\text{Auth}} - \bar{R}^{\text{UnAuth}}|$"),
]


def min_adjacent_gap(means: dict) -> float:
    """Former benchmark, kept only for reporting (degenerates when two APIs tie)."""
    v = sorted(means.values())
    return min(b - a for a, b in zip(v, v[1:]))


def api_range(means: dict) -> float:
    """Benchmark for 'small' effects: size of the storage-API effect."""
    return max(means.values()) - min(means.values())


def composition_share(S: dict, policy: str):
    """Share of the Auth/UnAuth mean gap removed when UnAuth per-API means are
    reweighted with the Auth API composition. None if the raw gap is <= TOL."""
    spm = S['storage_policy_mode']
    n_a = {s: spm[f"{s}|{policy}|Auth"]['n']   for s in STORAGES}
    n_u = {s: spm[f"{s}|{policy}|UnAuth"]['n'] for s in STORAGES}
    m_a = {s: spm[f"{s}|{policy}|Auth"]['mean']   for s in STORAGES}
    m_u = {s: spm[f"{s}|{policy}|UnAuth"]['mean'] for s in STORAGES}
    w_a = {s: n_a[s] / sum(n_a.values()) for s in STORAGES}
    w_u = {s: n_u[s] / sum(n_u.values()) for s in STORAGES}

    mean_auth   = sum(w_a[s] * m_a[s] for s in STORAGES)
    mean_unauth = sum(w_u[s] * m_u[s] for s in STORAGES)
    reweighted  = sum(w_a[s] * m_u[s] for s in STORAGES)

    raw = abs(mean_auth - mean_unauth)
    if raw <= TOL:
        return None, raw, abs(mean_auth - reweighted)
    residual = abs(mean_auth - reweighted)
    return 1.0 - residual / raw, raw, residual


def evaluate_claims(S: dict) -> dict:
    """Returns {claim_id: {'ok': bool|None, 'value': str, 'raw': dict}}."""
    sp  = lambda s, p, k: S['storage_policy'][f"{s}|{p}"][k]
    spm = lambda s, p, m, k: S['storage_policy_mode'][f"{s}|{p}|{m}"][k]
    ref = REF_POLICY

    med  = {s: sp(s, ref, 'median') for s in STORAGES}
    mean = {s: sp(s, ref, 'mean')   for s in STORAGES}
    iqr  = {s: sp(s, ref, 'iqr')    for s in STORAGES}
    bench   = api_range(mean)          # benchmark used by C1 / S1
    old_gap = min_adjacent_gap(mean)   # former benchmark, reported only

    out = {}

    def put(cid, ok, value, **raw):
        out[cid] = {'ok': None if ok is None else bool(ok), 'value': value,
                    'raw': {k: _r(v) for k, v in raw.items()}}

    # ── Ordinal ──────────────────────────────────────────────
    for cid, (a, b), stat in [("O1", ("IndexedDB", "cookie"), med),
                              ("O2", ("IndexedDB", "cookie"), mean),
                              ("O3", ("cookie", "localStorage"), med),
                              ("O4", ("cookie", "localStorage"), mean),
                              ("O5", ("localStorage", "sessionStorage"), med),
                              ("O6", ("localStorage", "sessionStorage"), mean)]:
        put(cid, stat[a] > stat[b], f"{stat[a]:.3f} > {stat[b]:.3f}",
            a=stat[a], b=stat[b])

    # ── Distributional ───────────────────────────────────────
    other_iqr = max(iqr[s] for s in STORAGES if s != "cookie")
    put("D1", iqr['cookie'] > other_iqr,
        f"{iqr['cookie']:.3f} > {other_iqr:.3f}",
        iqr_cookie=iqr['cookie'], max_other=other_iqr)

    idb_iqr = {p: sp("IndexedDB", p, 'iqr') for p in POLICIES}
    put("D2", max(idb_iqr.values()) <= TOL,
        " / ".join(f"{idb_iqr[p]:.3f}" for p in POLICIES), **idb_iqr)

    # ── Consent ──────────────────────────────────────────────
    d_cons = {s: abs(sp(s, "ALL", 'mean') - sp(s, "NONE", 'mean')) for s in STORAGES}
    worst  = max(d_cons, key=d_cons.get)
    put("C1", d_cons[worst] < bench,
        f"{d_cons[worst]:.3f} ({worst}) < {bench:.3f}",
        max_consent_gap=d_cons[worst], api_range=bench, min_adjacent_gap=old_gap)

    d_med = {s: abs(sp(s, "ALL", 'median') - sp(s, "NONE", 'median'))
             for s in ("cookie", "localStorage", "IndexedDB")}
    put("C2", max(d_med.values()) <= TOL,
        " / ".join(f"{d_med[s]:.3f}" for s in d_med), **d_med)

    d_q3 = abs(sp("cookie", "ALL", 'q3') - sp("cookie", "NONE", 'q3'))
    put("C3", d_q3 <= TOL, f"{d_q3:.3f}", delta_q3=d_q3)

    # ── Session mode ─────────────────────────────────────────
    d_mode = {s: abs(spm(s, ref, "Auth", 'mean') - spm(s, ref, "UnAuth", 'mean'))
              for s in STORAGES}
    worst  = max(d_mode, key=d_mode.get)
    put("S1", d_mode[worst] < bench,
        f"{d_mode[worst]:.3f} ({worst}) < {bench:.3f}",
        max_mode_gap=d_mode[worst], api_range=bench, min_adjacent_gap=old_gap)

    share, raw_gap, residual = composition_share(S, ref)
    put("S2", None if share is None else share >= COMPOSITION_SHARE,
        "n/a (gap <= TOL)" if share is None else f"{share * 100:.0f}%",
        share=share, raw_gap=raw_gap, residual_gap=residual)

    return out


def status_of(ok: int, total: int) -> str:
    if total == 0:
        return "n/a"
    if ok == total:
        return "Invariant"
    return "Robust" if ok / total >= ROBUST_RATE else "Conditional"


def failure_region(fails: dict) -> str:
    """{'prof': [0.1, 0.2]} -> 'alpha_prof <= 0.2'."""
    parts = []
    for dim, vals in fails.items():
        vals = sorted(vals)
        k = len(vals)
        if k == len(ALPHA_GRID):
            parts.append(f"alpha_{dim}: all values")
        elif vals == ALPHA_GRID[:k]:
            parts.append(f"alpha_{dim} <= {vals[-1]}")
        elif vals == ALPHA_GRID[-k:]:
            parts.append(f"alpha_{dim} >= {vals[0]}")
        else:
            parts.append(f"alpha_{dim} in {vals}")
    return "; ".join(parts)


# ════════════════════════════════════════════════════════════
# STAGE 0 — SANITY CHECK
# ════════════════════════════════════════════════════════════

def stage0_sanity(ds: Dataset, stats_path: Path) -> dict:
    print("\n  [Stage 0] Sanity check at DEFAULT calibration...")
    S = summarize(ds, ds.risk(DEFAULT_ALPHAS))
    if not stats_path.exists():
        print(f"     {stats_path} not found — skipped.")
        return {'checked': False}

    with open(stats_path, encoding="utf-8") as f:
        ref = json.load(f)

    mismatches = []
    for s in STORAGES:
        for p in POLICIES:
            r = ref['by_storage_policy'][s][p]['risk_i']
            mine = S['storage_policy'][f"{s}|{p}"]
            for k in ('n', 'mean', 'median', 'q1', 'q3'):
                tol = 0 if k == 'n' else TOL
                if abs(mine[k] - r[k]) > tol:
                    mismatches.append(f"{s}|{p}.{k}: script={mine[k]:.4f} json={r[k]}")
    for p in POLICIES:
        for m in MODES:
            r = ref['by_policy_mode'][p][m]['risk_i']
            mine = S['policy_mode'][f"{p}|{m}"]
            for k in ('n', 'mean', 'median', 'q1', 'q3'):
                tol = 0 if k == 'n' else TOL
                if abs(mine[k] - r[k]) > tol:
                    mismatches.append(f"{p}|{m}.{k}: script={mine[k]:.4f} json={r[k]}")

    if mismatches:
        print(f"     {len(mismatches)} MISMATCH(ES) with risk_statistics.json:")
        for line in mismatches[:20]:
            print(f"       {line}")
    else:
        print("     OK — DEFAULT calibration reproduces risk_statistics.json.")
    return {'checked': True, 'mismatches': mismatches}


# ════════════════════════════════════════════════════════════
# STAGE 1 — OAT
# ════════════════════════════════════════════════════════════

def stage1_oat(ds: Dataset):
    print("\n  [Stage 1] OAT sensitivity (60 configurations)...")
    curves, summaries = {d: {} for d in ALPHA_KEYS}, {}
    for dim in ALPHA_KEYS:
        for val in ALPHA_GRID:
            S = summarize(ds, ds.risk({**DEFAULT_ALPHAS, dim: val}))
            summaries[(dim, val)] = S
            curves[dim][str(val)] = {
                'global_mean'    : _r(S['global']['mean']),
                'mean_by_storage': {s: _r(S['storage'][s]['mean']) for s in STORAGES},
                'mean_by_mode'   : {m: _r(S['mode'][m]['mean'])    for m in MODES},
            }

    # Delta_k = mean R(alpha_k = 1.0) - mean R(alpha_k = 0.1)
    # (Noisy-OR is monotone in alpha, so this equals max - min.)
    lo, hi = str(ALPHA_GRID[0]), str(ALPHA_GRID[-1])
    delta_global = {d: _r(curves[d][hi]['global_mean'] - curves[d][lo]['global_mean'])
                    for d in ALPHA_KEYS}
    delta_storage = {s: {d: _r(curves[d][hi]['mean_by_storage'][s]
                               - curves[d][lo]['mean_by_storage'][s])
                         for d in ALPHA_KEYS} for s in STORAGES}
    delta_mode = {m: {d: _r(curves[d][hi]['mean_by_mode'][m]
                            - curves[d][lo]['mean_by_mode'][m])
                      for d in ALPHA_KEYS} for m in MODES}

    for d in ALPHA_KEYS:
        tag = "ACTIVE" if delta_global[d] > ACTIVITY_THRESHOLD else "inert"
        print(f"     {d:<6} Delta={delta_global[d]:.4f}  {tag}")
    for s in STORAGES:
        main = max(ALPHA_KEYS, key=lambda d: delta_storage[s][d])
        print(f"     {s:<16} link={delta_storage[s]['link']:.3f}  "
              f"prof={delta_storage[s]['prof']:.3f}  main={main}")
    for m in MODES:
        print(f"     {m:<16} link={delta_mode[m]['link']:.3f}  prof={delta_mode[m]['prof']:.3f}")

    result = {
        'curves'       : curves,
        'delta_global' : delta_global,
        'active_dims'  : [d for d in ALPHA_KEYS if delta_global[d] > ACTIVITY_THRESHOLD],
        'delta_storage': delta_storage,
        'delta_mode'   : delta_mode,
    }
    return result, summaries


# ════════════════════════════════════════════════════════════
# STAGE 2 — BOUNDS MIN / DEFAULT / MAX
# ════════════════════════════════════════════════════════════

def stage2_bounds(ds: Dataset) -> dict:
    print(f"\n  [Stage 2] Bounds MIN / DEFAULT / MAX (policy {REF_POLICY})...")
    configs = {
        'MIN'    : {k: 0.1 for k in ALPHA_KEYS},
        'DEFAULT': DEFAULT_ALPHAS,
        'MAX'    : {k: 1.0 for k in ALPHA_KEYS},
    }
    pick = lambda d: {k: _r(d[k]) for k in ('n', 'mean', 'median', 'q1', 'q3', 'iqr')}
    out = {}
    for label, alphas in configs.items():
        S = summarize(ds, ds.risk(alphas))
        out[label] = {
            'alphas'     : alphas,
            'global_mean': _r(S['global']['mean']),
            'ref_policy' : {s: pick(S['storage_policy'][f"{s}|{REF_POLICY}"]) for s in STORAGES},
            'pooled'     : {s: pick(S['storage'][s]) for s in STORAGES},
        }
    print(f"     {'API':<16}" + "".join(f"{l:>20}" for l in configs))
    for s in STORAGES:
        row = "".join(f"   med={out[l]['ref_policy'][s]['median']:.3f} "
                      f"iqr={out[l]['ref_policy'][s]['iqr']:.3f}" for l in configs)
        print(f"     {s:<16}{row}")
    return out


# ════════════════════════════════════════════════════════════
# STAGE 3 — ROBUSTNESS OF RQ4 CLAIMS
# ════════════════════════════════════════════════════════════

def stage3_claims(ds: Dataset, summaries: dict) -> dict:
    print("\n  [Stage 3] Robustness of RQ4 claims...")
    default = evaluate_claims(summarize(ds, ds.risk(DEFAULT_ALPHAS)))

    per_config = []
    for (dim, val), S in summaries.items():
        res = evaluate_claims(S)
        per_config.append({'dim': dim, 'alpha': val,
                           **{cid: res[cid]['ok'] for cid in res},
                           '_raw': {cid: res[cid]['raw'] for cid in res}})

    summary = {}
    print(f"\n  {'ID':<4}{'Finding':<8}{'Default':<30}{'Rate':>8}  {'Status':<12}Failures")
    print(f"  {'-' * 95}")
    for cid, finding, level, desc, latex in CLAIMS:
        valid = [r for r in per_config if r[cid] is not None]
        ok    = sum(r[cid] for r in valid)
        fails = {}
        for r in valid:
            if not r[cid]:
                fails.setdefault(r['dim'], []).append(r['alpha'])
        region = failure_region(fails)
        # Min / max of every audited quantity over the grid (for footnotes,
        # e.g. "the median shift never exceeds X").
        keys = default[cid]['raw'].keys()
        grid_range = {}
        for k in keys:
            vals = [r['_raw'][cid][k] for r in per_config if r['_raw'][cid][k] is not None]
            if vals:
                grid_range[k] = {'min': min(vals), 'max': max(vals)}
        summary[cid] = {
            'finding': finding, 'level': level, 'description': desc, 'latex': latex,
            'default_ok': default[cid]['ok'], 'default_value': default[cid]['value'],
            'ok': ok, 'total': len(valid), 'excluded': len(per_config) - len(valid),
            'rate': _r(ok / len(valid)) if valid else None,
            'status': status_of(ok, len(valid)),
            'failures': fails, 'failure_region': region,
            'grid_range': grid_range,
        }
        flag = "" if default[cid]['ok'] else "  <-- FAILS AT DEFAULT"
        print(f"  {cid:<4}{finding:<8}{default[cid]['value']:<30}"
              f"{ok:>3}/{len(valid):<4}  {summary[cid]['status']:<12}{region}{flag}")

    # Worst cases over the grid for the claims whose footnotes need them.
    gr = lambda cid, k: summary[cid]['grid_range'][k]
    print("\n  Worst cases over the 60 configurations:")
    print(f"     C1 consent effect max = {gr('C1','max_consent_gap')['max']:.4f}   "
          f"API range min = {gr('C1','api_range')['min']:.4f}")
    print(f"     S1 session effect max = {gr('S1','max_mode_gap')['max']:.4f}   "
          f"API range min = {gr('S1','api_range')['min']:.4f}")
    print("     C2 max |median ALL - NONE| = "
          + ", ".join(f"{s}={gr('C2', s)['max']:.4f}" for s in ("cookie", "localStorage", "IndexedDB")))
    print(f"     C3 max |Q3 cookie ALL - NONE| = {gr('C3','delta_q3')['max']:.4f}")
    print("     D2 max IQR IDB = "
          + ", ".join(f"{p}={gr('D2', p)['max']:.4f}" for p in POLICIES))
    print(f"     O4 mean cookie - mean LS ranges over "
          f"[{min(r['_raw']['O4']['a'] - r['_raw']['O4']['b'] for r in per_config):+.4f}, "
          f"{max(r['_raw']['O4']['a'] - r['_raw']['O4']['b'] for r in per_config):+.4f}]")

    return {'default': default, 'summary': summary, 'per_config': per_config}


def latex_rows(summary: dict) -> str:
    """Rows for tab:ranking_stability. Failure regions go to footnotes."""
    lines, current = [], None
    headers = {'ordinal': 'Ordinal claims (storage ranking)',
               'distributional': 'Distributional claims',
               'consent': 'Consent invariance (ALL vs.\\ NONE)',
               'session': 'Session mode (ALL policy)'}
    for cid, _, level, _, _ in CLAIMS:
        c = summary[cid]
        if level != current:
            if current is not None:
                lines.append(r"\midrule")
            lines.append(rf"\multicolumn{{5}}{{@{{}}l}}{{\textit{{{headers[level]}}}}} \\[2pt]")
            current = level
        default_tex = c['default_value'].replace('%', r'\%')   # outside the f-string (Python < 3.12)
        row = f"{c['finding']} & {c['latex']} & {default_tex} & {c['ok']}/{c['total']} & {c['status']} " + r"\\"
        if c['failure_region']:
            row += f"  % failures: {c['failure_region']}"
        lines.append(row)
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════
# STAGE 4 — SOBOL
# ════════════════════════════════════════════════════════════

def _sobol_sample(problem: dict, n: int):
    try:
        from SALib.sample import sobol as sampler          # SALib >= 1.4.6
    except ImportError:
        from SALib.sample import saltelli as sampler       # older SALib
    try:
        return sampler.sample(problem, n, calc_second_order=True, seed=SOBOL_SEED)
    except TypeError:
        return sampler.sample(problem, n, calc_second_order=True)


def stage4_sobol(ds: Dataset) -> dict:
    print("\n  [Stage 4] Sobol global sensitivity...")
    from SALib.analyze import sobol

    problem = {'num_vars': 6, 'names': ALPHA_KEYS, 'bounds': [[0.1, 1.0]] * 6}
    X = _sobol_sample(problem, SOBOL_N)
    print(f"     N={SOBOL_N}, second order -> {len(X):,} model evaluations")

    # Mean R = sum_u W[u] * I_u : exact and vectorised over all samples.
    U = len(ds.Zu)
    targets = {'global': np.ones(ds.n, dtype=bool)}
    targets.update({s: ds.mask(storage=s) for s in STORAGES})
    W = {t: np.bincount(ds.z_inv[m], weights=ds.P[m], minlength=U) / m.sum()
         for t, m in targets.items()}
    I_u = 1.0 - np.prod(1.0 - ds.Zu[None, :, :] * X[:, None, :], axis=2)   # (samples, U)

    out = {}
    for t, w in W.items():
        Y = I_u @ w
        try:
            Si = sobol.analyze(problem, Y, calc_second_order=True, seed=SOBOL_SEED)
        except TypeError:
            Si = sobol.analyze(problem, Y, calc_second_order=True)
        j_l, j_p = ALPHA_KEYS.index('link'), ALPHA_KEYS.index('prof')
        idx = {d: {'S1': _r(Si['S1'][j]), 'S1_conf': _r(Si['S1_conf'][j]),
                   'ST': _r(Si['ST'][j]), 'ST_conf': _r(Si['ST_conf'][j])}
               for j, d in enumerate(ALPHA_KEYS)}
        s2_lp = float(Si['S2'][j_l, j_p])
        out[t] = {
            'indices'             : idx,
            'S2_link_prof'        : _r(s2_lp),
            'S2_link_prof_conf'   : _r(Si['S2_conf'][j_l, j_p]),
            'sum_S1'              : _r(np.sum(Si['S1'])),
            'sum_S1_plus_S2_lp'   : _r(np.sum(Si['S1']) + s2_lp),
            'other_interactions'  : {f"{a}x{b}": _r(Si['S2'][i, k])
                                     for i, a in enumerate(ALPHA_KEYS)
                                     for k, b in enumerate(ALPHA_KEYS)
                                     if k > i and (a, b) != ('link', 'prof')
                                     and abs(Si['S2'][i, k]) > 0.01},
        }
        if t == 'global':
            for d in ALPHA_KEYS:
                print(f"     {d:<6} S1={idx[d]['S1']:.3f} ±{idx[d]['S1_conf']:.3f}  "
                      f"ST={idx[d]['ST']:.3f} ±{idx[d]['ST_conf']:.3f}")
            print(f"     S2(link,prof)={out[t]['S2_link_prof']:.3f}  "
                  f"sum S1 + S2(link,prof)={out[t]['sum_S1_plus_S2_lp']:.3f}")
    out['n_evaluations'] = int(len(X))
    return out


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

class _Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, np.bool_):    return bool(o)
        if isinstance(o, np.integer):  return int(o)
        if isinstance(o, np.floating): return float(o)
        if isinstance(o, np.ndarray):  return o.tolist()
        return super().default(o)


def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"
    out_dir   = data_root / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("  SENSITIVITY ANALYSIS — PxI risk model (RQ4 robustness)")
    print("=" * 70)

    ds = Dataset(data_root)

    s0      = stage0_sanity(ds, Path(__file__).resolve().parent / "reports" / "risk_statistics.json")
    s1, oat = stage1_oat(ds)
    s2      = stage2_bounds(ds)
    s3      = stage3_claims(ds, oat)
    s4      = stage4_sobol(ds)

    output = {
        'config': {'ref_policy': REF_POLICY, 'tol': TOL,
                   'activity_threshold': ACTIVITY_THRESHOLD,
                   'robust_rate': ROBUST_RATE, 'composition_share': COMPOSITION_SHARE,
                   'default_alphas': DEFAULT_ALPHAS, 'alpha_grid': ALPHA_GRID},
        'sanity'        : s0,
        'oat'           : s1,
        'bounds'        : s2,
        'claims'        : s3,
        'sobol'         : s4,
    }
    out_path = out_dir / "sensitivity_full_pipeline.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, cls=_Encoder)

    tex_path = out_dir / "claims_table_rows.tex"
    tex_path.write_text(latex_rows(s3['summary']), encoding="utf-8")

    print(f"\n  Saved: {out_path}")
    print(f"  Saved: {tex_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()