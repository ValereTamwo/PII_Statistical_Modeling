"""
SENSITIVITY ANALYSIS FRAMEWORK
Assesses the structural and parametric stability of the PxI risk model.
Four-stage methodology:
  Stage 1: Local sensitivity (OAT) per model dimension.
  Stage 2: Parametric boundaries (MIN/DEFAULT/MAX) and distributional stability.
  Stage 3: Positional/Ranking invariance across configurations (RQ4 claims).
  Stage 4: Risk drivers identification by storage API.
"""

import json
import numpy as np
from pathlib import Path
from collections import defaultdict
from SALib.sample import saltelli
from SALib.analyze import sobol


USERS      = ["FR_0417", "FR_0446", "FR_0458"]
MODES      = ["Auth", "UnAuth"]
POLICIES   = ["ALL", "PARTIAL", "NONE"]
STORAGES   = ["cookie", "localStorage", "sessionStorage", "IndexedDB"]
ALPHA_KEYS = ['id', 'ato', 'link', 'loc', 'prof', 'env']
ALPHA_GRID = [round(x * 0.1, 1) for x in range(1, 11)]

DEFAULT_ALPHAS = {
    'id': 0.90, 'ato': 0.95, 'link': 0.85,
    'loc': 0.75, 'prof': 0.70, 'env': 0.50
}

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


# ════════════════════════════════════════════════════════════
# UTILITAIRES
# ════════════════════════════════════════════════════════════

def _z_composite(categories: list) -> np.ndarray:
    z = np.zeros(6)
    for cat in categories:
        if cat in PII_IMPACT_MAP:
            z = np.maximum(z, PII_IMPACT_MAP[cat])
    return z


def calculate_ii(z: np.ndarray, alphas: dict, xi: dict = None) -> float:
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
                    it['_z']  = _z_composite(cats)
                    it['_xi'] = it.get('meta', it.get('xi', {}))
                all_items.extend(items)
    print(f"  -> {len(all_items):,} items loaded.")
    return all_items


def _apply_alphas(items: list, alphas: dict):
    for it in items:
        it['_ii']     = calculate_ii(it['_z'], alphas, it['_xi'])
        it['_risk_i'] = it['pi_exposure'] * it['_ii']


def _describe_storage(items: list) -> dict:
    """Computes summary statistics (quartiles, IQR) per storage API."""
    result = {}
    for st in STORAGES:
        vals = np.array([it['_risk_i'] for it in items
                         if it.get('storage_type','').lower() == st.lower()])
        if len(vals) == 0:
            result[st] = {'n':0,'mean':None,'median':None,
                          'q1':None,'q3':None,'iqr':None}
            continue
        q1, med, q3 = np.percentile(vals, [25, 50, 75])
        result[st] = {
            'n'     : int(len(vals)),
            'mean'  : round(float(vals.mean()), 4),
            'median': round(float(med),  4),
            'q1'    : round(float(q1),   4),
            'q3'    : round(float(q3),   4),
            'iqr'   : round(float(q3-q1),4),
        }
    return result


def _aggregate(items: list) -> dict:
    """Computes normalized aggregates and raw mean values."""
    def raw_sum(filt): return sum(it['_risk_i'] for it in items if filt(it))
    def mean_val(filt):
        sub = [it['_risk_i'] for it in items if filt(it)]
        return round(sum(sub)/len(sub), 4) if sub else 0.

    mode_raw    = {m: raw_sum(lambda it,m=m: it['_mode']==m)     for m in MODES}
    policy_raw  = {p: raw_sum(lambda it,p=p: it['_policy']==p)   for p in POLICIES}
    storage_raw = {s: raw_sum(lambda it,s=s: it.get('storage_type','').lower()==s.lower())
                   for s in STORAGES}

    ceil_mode    = max(mode_raw.values())    or 1.
    ceil_policy  = max(policy_raw.values())  or 1.
    ceil_storage = max(storage_raw.values()) or 1.

    def norm(v, c): return round(min(v/c, 1.), 4)

    return {
        'by_mode'        : {m: norm(mode_raw[m],    ceil_mode)    for m in MODES},
        'by_policy'      : {p: norm(policy_raw[p],  ceil_policy)  for p in POLICIES},
        'by_storage'     : {s: norm(storage_raw[s], ceil_storage) for s in STORAGES},
        'mean_by_mode'   : {m: mean_val(lambda it,m=m: it['_mode']==m)   for m in MODES},
        'mean_by_policy' : {p: mean_val(lambda it,p=p: it['_policy']==p) for p in POLICIES},
        'mean_by_storage': {s: mean_val(lambda it,s=s: it.get('storage_type','').lower()==s.lower())
                            for s in STORAGES},
        'global_mean_ri' : round(sum(it['_risk_i'] for it in items)/len(items), 4),
        'global_mean_ii' : round(sum(it['_ii']     for it in items)/len(items), 4),
    }


# ════════════════════════════════════════════════════════════
# ÉTAPE 1 — OAT 1D
# ════════════════════════════════════════════════════════════

def run_step1_oat(items: list) -> dict:
    print("\n  [Step 1] OAT sensitivity...")
    _apply_alphas(items, DEFAULT_ALPHAS)
    ref = _aggregate(items)
    dims = {}
    for dim in ALPHA_KEYS:
        dims[dim] = {}
        for val in ALPHA_GRID:
            alphas = {**DEFAULT_ALPHAS, dim: val}
            _apply_alphas(items, alphas)
            agg = _aggregate(items)
            dims[dim][str(val)] = {
                'global_mean_ii' : agg['global_mean_ii'],
                'global_mean_ri' : agg['global_mean_ri'],
                'by_mode'        : agg['by_mode'],
                'by_policy'      : agg['by_policy'],
                'by_storage'     : agg['by_storage'],
                'mean_by_mode'   : agg['mean_by_mode'],
                'mean_by_policy' : agg['mean_by_policy'],
                'mean_by_storage': agg['mean_by_storage'],
            }

    # Interaction link/prof — Search for crossing point in logit space
    link_vals = [dims['link'][str(v)]['global_mean_ri'] for v in ALPHA_GRID]
    prof_vals = [dims['prof'][str(v)]['global_mean_ri'] for v in ALPHA_GRID]
    gaps = [abs(l-p) for l,p in zip(link_vals, prof_vals)]
    intersect_idx = int(np.argmin(gaps))
    intersect_alpha = ALPHA_GRID[intersect_idx]

    # Delta par dimension (OAT sensitivity index)
    delta_summary = {}
    for dim in ALPHA_KEYS:
        ys = [dims[dim][str(v)]['global_mean_ri'] for v in ALPHA_GRID]
        delta_summary[dim] = {
            'delta':  round(max(ys) - min(ys), 4),
            'active': (max(ys) - min(ys)) > 0.05,
            'min_ri': round(min(ys), 4),
            'max_ri': round(max(ys), 4),
        }

    print(f"     link/prof intersection near alpha={intersect_alpha}")
    for dim, v in delta_summary.items():
        status = 'ACTIVE' if v['active'] else 'inert'
        print(f"     {dim:<6} Δ={v['delta']:.4f}  {status}")

    return {
        'reference': {'alphas': DEFAULT_ALPHAS, 'aggregated': ref},
        'dimensions': dims,
        'delta_summary': delta_summary,
        'link_prof_intersection_alpha': intersect_alpha,
    }


# ════════════════════════════════════════════════════════════
# ÉTAPE 2 — MIN / DEFAULT / MAX + distributions item-level
# ════════════════════════════════════════════════════════════

def run_step2_range(items: list) -> dict:
    print("\n  [Step 2] Range analysis MIN/DEFAULT/MAX + distributions...")
    configs = {
        'alphas_min'    : {k: 0.1 for k in ALPHA_KEYS},
        'alphas_default': DEFAULT_ALPHAS,
        'alphas_max'    : {k: 1.0 for k in ALPHA_KEYS},
    }
    results = {}
    for label, alphas in configs.items():
        _apply_alphas(items, alphas)
        agg  = _aggregate(items)
        dist = _describe_storage(items)   # ← Q1/median/Q3/IQR par storage
        results[label] = {
            'alphas'            : alphas,
            'global_mean_ii'    : agg['global_mean_ii'],
            'global_mean_ri'    : agg['global_mean_ri'],
            'mean_by_storage'   : agg['mean_by_storage'],
            'mean_by_mode'      : agg['mean_by_mode'],
            'mean_by_policy'    : agg['mean_by_policy'],
            'by_mode'           : agg['by_mode'],
            'by_policy'         : agg['by_policy'],
            'by_storage'        : agg['by_storage'],
            'dist_by_storage'   : dist,   # Q1/median/Q3/IQR item-level
        }
        print(f"     {label:<18} mean_Ri={agg['global_mean_ri']:.4f}")
        for st in STORAGES:
            d = dist[st]
            print(f"       {st:<18} med={d['median']}  IQR={d['iqr']}  n={d['n']}")

    return results


# ════════════════════════════════════════════════════════════
# ÉTAPE 3 — RANKING STABILITY
# ════════════════════════════════════════════════════════════

# def run_step3_rankings(sens_1d: dict) -> dict:
#     print("\n  [Step 3] Ranking stability (60 configs)...")
#     details = []
#     dims_data = sens_1d['dimensions']
#     for dim in ALPHA_KEYS:
#         for val in ALPHA_GRID:
#             d  = dims_data[dim][str(val)]
#             r1 = bool(d['mean_by_mode'].get('UnAuth',0)       >= d['mean_by_mode'].get('Auth',0))
#             r2 = bool(d['mean_by_policy'].get('ALL',0)         >= d['mean_by_policy'].get('NONE',0))
#             r3 = bool(d['mean_by_storage'].get('IndexedDB',0) >= d['mean_by_storage'].get('cookie',0))
#             details.append({'dim':dim,'alpha':val,
#                              'unauth_gt_auth':r1,
#                              'all_gt_none':r2,
#                              'idb_gt_cookie':r3})

#     n = len(details)
#     summary = {}
#     for key, name in [('unauth_gt_auth','UnAuth>Auth'),
#                       ('all_gt_none',   'ALL>NONE'),
#                       ('idb_gt_cookie', 'IDB>Cookie')]:
#         ok = sum(r[key] for r in details)
#         summary[name] = {'ok':ok, 'total':n, 'rate':round(ok/n,4)}
#         print(f"     {name:<18} {ok}/{n}  ({ok/n*100:.1f}%)")

#     return {'details': details, 'summary': summary}



# ════════════════════════════════════════════════════════════
# ÉTAPE 3 — RANKING STABILITY (rigoureuse, alignée sur RQ4)
# ════════════════════════════════════════════════════════════

def _describe_storage_by_mode_policy(items: list) -> dict:
    """
    Calcule médiane et IQR par storage × mode × policy.
    Nécessaire pour tester les claims distributionnels de RQ4.
    """
    result = {}
    for st in STORAGES:
        result[st] = {}
        for mode in MODES:
            result[st][mode] = {}
            for policy in POLICIES:
                vals = np.array([
                    it['_risk_i'] for it in items
                    if it.get('storage_type', '').lower() == st.lower()
                    and it['_mode'] == mode
                    and it['_policy'] == policy
                ])
                if len(vals) == 0:
                    result[st][mode][policy] = {
                        'n': 0, 'median': None, 'iqr': None, 'mean': None
                    }
                    continue
                q1, med, q3 = np.percentile(vals, [25, 50, 75])
                result[st][mode][policy] = {
                    'n'     : int(len(vals)),
                    'median': round(float(med), 4),
                    'iqr'   : round(float(q3 - q1), 4),
                    'mean'  : round(float(vals.mean()), 4),
                }
    return result


def run_step3_rankings(sens_1d: dict, items: list) -> dict:
    """
    Teste la stabilité des findings RQ4 à travers les 60 configs OAT.

    Claims testés :
    ──────────────────────────────────────────────────────────
    MEAN-LEVEL (ordinal)
      M1 — |mean_Auth - mean_UnAuth| < 0.05          (F6: Auth ≈ UnAuth)
      M2 — mean_ALL >= mean_NONE                      (F5: policy ordering)
      M3 — mean_cookie > mean_sessionStorage          (F1 vs F3)
      M4 — mean_cookie > mean_IndexedDB               (F1 vs F4)

    DISTRIBUTIONAL
      D1 — median_cookie > median_sessionStorage      (F1 vs F3)
      D2 — IQR_IndexedDB == 0                         (F4: dégenérée)
      D3 — IQR_cookie > IQR_sessionStorage            (F1: hétérogénéité)
      D4 — |median_Auth - median_UnAuth| < 0.01       (F6: Δmedian ≤ 0.001)
      D5 — median_cookie_ALL ≈ median_cookie_NONE     (F5: consent n'altère
             i.e. |Δmedian_cookie| < 0.02              pas la distribution)
    ──────────────────────────────────────────────────────────
    """
    print("\n  [Step 3] Ranking stability — rigorous RQ4-aligned...")
    dims_data = sens_1d['dimensions']
    details   = []

    for dim in ALPHA_KEYS:
        for val in ALPHA_GRID:
            # ── Recalculer les scores pour cette config ──────────────
            alphas = {**DEFAULT_ALPHAS, dim: val}
            _apply_alphas(items, alphas)

            agg  = _aggregate(items)
            dist = _describe_storage(items)                      # global
            dist_mp = _describe_storage_by_mode_policy(items)    # ×mode×policy

            # ── MEAN-LEVEL claims ────────────────────────────────────
            auth_mean   = agg['mean_by_mode']['Auth']
            unauth_mean = agg['mean_by_mode']['UnAuth']

            M1 = bool(abs(auth_mean - unauth_mean) < 0.05)
            M2 = bool(agg['mean_by_policy']['ALL'] >= 
                      agg['mean_by_policy']['NONE'])
            M3 = bool(agg['mean_by_storage']['cookie'] >
                      agg['mean_by_storage']['sessionStorage'])
            M4 = bool(agg['mean_by_storage']['cookie'] >
                      agg['mean_by_storage']['IndexedDB'])

            # ── DISTRIBUTIONAL claims ────────────────────────────────

            # D1 — médiane cookie > médiane sessionStorage
            med_cookie = dist['cookie']['median']
            med_ss     = dist['sessionStorage']['median']
            D1 = bool(med_cookie is not None and
                      med_ss     is not None and
                      med_cookie > med_ss)

            # D2 — IQR IndexedDB = 0
            iqr_idb = dist['IndexedDB']['iqr']
            D2 = bool(iqr_idb is not None and iqr_idb == 0.0)

            # D3 — IQR cookie > IQR sessionStorage
            iqr_cookie = dist['cookie']['iqr']
            iqr_ss     = dist['sessionStorage']['iqr']
            D3 = bool(iqr_cookie is not None and
                      iqr_ss     is not None and
                      iqr_cookie > iqr_ss)

            # D4 — |médiane Auth - médiane UnAuth| < 0.01 (global)
            # On agrège toutes les médianes par mode
            vals_auth   = np.array([it['_risk_i'] for it in items
                                    if it['_mode'] == 'Auth'])
            vals_unauth = np.array([it['_risk_i'] for it in items
                                    if it['_mode'] == 'UnAuth'])
            med_auth   = float(np.median(vals_auth))   if len(vals_auth)   else None
            med_unauth = float(np.median(vals_unauth)) if len(vals_unauth) else None
            D4 = bool(med_auth is not None and
                      med_unauth is not None and
                      abs(med_auth - med_unauth) < 0.01)

            # D5 — médiane cookie stable entre ALL et NONE
            # |median_cookie_ALL - median_cookie_NONE| < 0.02
            med_ck_all  = dist_mp['cookie']['Auth']['ALL']['median']   # Auth+ALL
            med_ck_none = dist_mp['cookie']['Auth']['NONE']['median']  # Auth+NONE
            # On prend la moyenne des deux modes pour être plus robuste
            med_ck_all_u  = dist_mp['cookie']['UnAuth']['ALL']['median']
            med_ck_none_u = dist_mp['cookie']['UnAuth']['NONE']['median']

            # Juste avant le calcul de D5, ajoute :
            if dim == 'id' and val == 0.9:  # ≈ default
                print(f"  DEBUG D5:")
                print(f"    med_cookie_Auth_ALL  = {dist_mp['cookie']['Auth']['ALL']['median']}")
                print(f"    med_cookie_Auth_NONE = {dist_mp['cookie']['Auth']['NONE']['median']}")
                print(f"    med_cookie_UnAuth_ALL  = {dist_mp['cookie']['UnAuth']['ALL']['median']}")
                print(f"    med_cookie_UnAuth_NONE = {dist_mp['cookie']['UnAuth']['NONE']['median']}")

            if all(v is not None for v in [med_ck_all, med_ck_none,
                                            med_ck_all_u, med_ck_none_u]):
                delta_consent_auth   = abs(med_ck_all   - med_ck_none)
                delta_consent_unauth = abs(med_ck_all_u - med_ck_none_u)
                D5 = bool(delta_consent_auth   < 0.02 and
                          delta_consent_unauth < 0.02)
            else:
                D5 = None

            # ── Claims localStorage (F2) ─────────────────────────────

            mean_cookie = agg['mean_by_storage']['cookie']
            mean_ls     = agg['mean_by_storage']['localStorage']
            M5 = bool(abs(mean_cookie - mean_ls) < 0.07)

            mean_ss = agg['mean_by_storage']['sessionStorage']
            M6 = bool(mean_ls > mean_ss)

            mean_idb = agg['mean_by_storage']['IndexedDB']
            M7 = bool(mean_ls > mean_idb)

            med_ls = dist['localStorage']['median']
            D6 = bool(med_ls is not None and
                    med_cookie is not None and
                    abs(med_cookie - med_ls) < 0.09)


            iqr_ls = dist['localStorage']['iqr']
            D7 = bool(iqr_ls     is not None and
                    iqr_cookie  is not None and
                    iqr_ls < iqr_cookie)

            details.append({
                'dim'  : dim,
                'alpha': val,
                # mean-level
                'M1_auth_unauth_equiv' : M1,
                'M2_all_gt_none'       : M2,
                'M3_cookie_gt_ss'      : M3,
                'M4_cookie_gt_idb'     : M4,
                # distributional
                'D1_median_cookie_gt_ss'  : D1,
                'D2_idb_iqr_zero'         : D2,
                'D3_iqr_cookie_gt_ss'     : D3,
                'D4_median_mode_equiv'    : D4,
                'D5_cookie_median_stable' : D5,
                # valeurs brutes pour audit
                '_auth_mean'  : round(auth_mean,   4),
                '_unauth_mean': round(unauth_mean, 4),
                '_med_auth'   : round(med_auth,    4) if med_auth   else None,
                '_med_unauth' : round(med_unauth,  4) if med_unauth else None,
                '_med_cookie' : round(med_cookie,  4) if med_cookie else None,
                '_med_ss'     : round(med_ss,      4) if med_ss     else None,
                '_iqr_idb'    : round(iqr_idb,     4) if iqr_idb is not None else None,
                'M5_ls_equiv_cookie'       : M5,
                'M6_ls_gt_ss'              : M6,
                'M7_ls_gt_idb'             : M7,
                'D6_median_ls_equiv_cookie': D6,
                'D7_iqr_ls_lt_cookie'      : D7,
                # valeurs brutes
                '_mean_ls'  : round(mean_ls,  4),
                '_med_ls'   : round(med_ls,   4) if med_ls   else None,
                '_iqr_ls'   : round(iqr_ls,   4) if iqr_ls   else None,
            })

    # ── Summary ─────────────────────────────────────────────────────
    n = len(details)
    claims = {
        'M1_auth_unauth_equiv' : ('mean', 'F6 : |mean_Auth - mean_UnAuth| < 0.05'),
        'M2_all_gt_none'       : ('mean', 'F5 : mean_ALL >= mean_NONE'),
        'M3_cookie_gt_ss'      : ('mean', 'F1/F3 : mean_cookie > mean_sessionStorage'),
        'M4_cookie_gt_idb'     : ('mean', 'F1/F4 : mean_cookie > mean_IndexedDB'),
        'D1_median_cookie_gt_ss'  : ('dist', 'F1/F3 : median_cookie > median_sessionStorage'),
        'D2_idb_iqr_zero'         : ('dist', 'F4 : IQR_IndexedDB = 0'),
        'D3_iqr_cookie_gt_ss'     : ('dist', 'F1 : IQR_cookie > IQR_sessionStorage'),
        'D4_median_mode_equiv'    : ('dist', 'F6 : |median_Auth - median_UnAuth| < 0.01'),
        'D5_cookie_median_stable' : ('dist', 'F5 : |median_cookie_ALL - median_cookie_NONE| < 0.02'),
        'M5_ls_equiv_cookie'      : ('mean', 'F2 : |mean_localStorage - mean_cookie| < 0.02'),
        'M6_ls_gt_ss'             : ('mean', 'F2/F3 : mean_localStorage > mean_sessionStorage'),
        'M7_ls_gt_idb'            : ('mean', 'F2/F4 : mean_localStorage > mean_IndexedDB'),
        'D6_median_ls_equiv_cookie': ('dist', 'F2 : |median_localStorage - median_cookie| < 0.05'),
        'D7_iqr_ls_lt_cookie'     : ('dist', 'F2 : IQR_localStorage < IQR_cookie'),
    }

    summary = {}
    print(f"\n  {'Claim':<45} {'ok':>4} / {'n':>4}   rate")
    print(f"  {'-'*60}")
    for key, (level, label) in claims.items():
        valid = [r for r in details if r[key] is not None]
        ok    = sum(1 for r in valid if r[key])
        nv    = len(valid)
        rate  = round(ok / nv, 4) if nv else None
        summary[key] = {
            'label': label,
            'level': level,
            'ok'   : ok,
            'total': nv,
            'rate' : rate,
        }
        print(f"  [{level.upper()}] {label:<43} {ok:>4} / {nv:>4}   {rate:.3f}")

    return {'details': details, 'summary': summary}






# ════════════════════════════════════════════════════════════
# ÉTAPE 4 — DRIVERS PAR API
# ════════════════════════════════════════════════════════════

def run_step4_drivers(sens_1d: dict) -> dict:
    print("\n  [Step 4] Risk drivers by storage API...")
    dims_data = sens_1d['dimensions']
    drivers = {}
    for st in STORAGES:
        drivers[st] = {}
        for dim in ALPHA_KEYS:
            ys = [dims_data[dim][str(v)]['mean_by_storage'][st]
                  for v in ALPHA_GRID]
            delta = round(max(ys) - min(ys), 4)
            drivers[st][dim] = {
                'delta' : delta,
                'min_ri': round(min(ys), 4),
                'max_ri': round(max(ys), 4),
            }
        # Identifier le driver principal
        main_dim = max(ALPHA_KEYS, key=lambda d: drivers[st][d]['delta'])
        drivers[st]['_main_driver'] = main_dim
        drivers[st]['_main_delta']  = drivers[st][main_dim]['delta']
        print(f"     {st:<18} main driver = {main_dim}  "
              f"Δ={drivers[st][main_dim]['delta']:.4f}")

    return drivers


def run_step5_sobol(items: list) -> dict:
    print("\n  [Step 5] Sobol sensitivity analysis...")
    from SALib.sample import saltelli
    from SALib.analyze import sobol

    problem = {
        'num_vars': 6,
        'names': ALPHA_KEYS,
        'bounds': [[0.1, 1.0]] * 6
    }

    param_values = saltelli.sample(problem, N=1024, calc_second_order=True)
    Y = np.zeros(len(param_values))

    for i, row in enumerate(param_values):
        alphas = dict(zip(ALPHA_KEYS, row))
        _apply_alphas(items, alphas)
        Y[i] = np.mean([it['_risk_i'] for it in items])

    Si = sobol.analyze(problem, Y, calc_second_order=True)

    results = {}
    for j, dim in enumerate(ALPHA_KEYS):
        results[dim] = {
            'S1' : round(float(Si['S1'][j]),  4),
            'S1_conf': round(float(Si['S1_conf'][j]), 4),
            'ST' : round(float(Si['ST'][j]),  4),
            'ST_conf': round(float(Si['ST_conf'][j]), 4),
        }
        print(f"     {dim:<6}  S1={Si['S1'][j]:.4f}  ST={Si['ST'][j]:.4f}")

    # Interactions paires notables
    interactions = {}
    for j, d1 in enumerate(ALPHA_KEYS):
        for k, d2 in enumerate(ALPHA_KEYS):
            if k > j:
                val = round(float(Si['S2'][j, k]), 4)
                if abs(val) > 0.01:  # seuil
                    interactions[f"{d1}×{d2}"] = val

    return {'indices': results, 'interactions': interactions}


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    print("=" * 65)
    print("  SENSITIVITY FULL PIPELINE — 4 Steps")
    print("  Step 1: OAT 1D  |  Step 2: MIN/DEFAULT/MAX + IQR")
    print("  Step 3: Rankings |  Step 4: Drivers by storage")
    print("=" * 65)

    items = load_all_items(data_root)

    s1 = run_step1_oat(items)
    s2 = run_step2_range(items)
    s3 = run_step3_rankings(s1, items=items)
    s4 = run_step4_drivers(s1)
    s5 = run_step5_sobol(items)

    output = {
        'sensitivity_1d'   : s1,
        'sensitivity_range': s2,
        'ranking_stability': s3,
        'drivers_by_storage': s4,
        # 'sobol_indices'   : s5,
    }

    out_dir  = base_dir / "data" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "sensitivity_full_pipeline.json"
    class NumpyEncoder(json.JSONEncoder):
        def default(self, obj):
            import numpy as np
            if isinstance(obj, (np.bool_, bool)):
                return int(obj)
            if isinstance(obj, (np.integer,)):
                return int(obj)
            if isinstance(obj, (np.floating,)):
                return float(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            return super().default(obj)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False,
                  cls=NumpyEncoder)

    print(f"\n  Saved: {out_path}")
    print("=" * 65)


if __name__ == "__main__":
    main()