#!/usr/bin/env python3
"""
WITHIN-TIER ROBUSTNESS -- MONTE CARLO (Level 1: cardinal uncertainty, fixed order)
===================================================================================

What it adds
------------
The 9-point grid gives ONE value to every cell of a tier. The real baseline Z(0) is
heterogeneous inside a tier (e.g. W cells are 0.1, 0.2 or 0.3). Here the value of every
non-boundary cell is DRAWN at random inside an interval, N times, the ordinal structure
(which cell belongs to which tier) being kept fixed. For each draw the 13 RQ4 claims
(O1-O6, D1-D2, C1-C3, S1-S2) are re-evaluated with EXACTLY the same code as the alpha_k
and grid analyses (imported, not copied). We report how often each claim holds, with a
Wilson 95% interval, and how far from its threshold it stays (margin).

Scenarios (name = <ranges>-<granularity>)
    granularity  tier : one value for all W cells, one for all S cells    (2 parameters)
                 dim  : one value per (tier, dimension)                   (12 parameters)
                 cell : one independent value per cell                    (36 parameters)
    ranges       within   : W~U[0.10,0.30]  S~U[0.50,0.70]   (the intervals of the paper)
                 wide     : W~U[0.05,0.45]  S~U[0.40,0.90]   (stress test, W<S enforced)
                 extremes : within + A~U[0,0.05] and C~U[0.90,1.00] (boundary tiers not exact)
    A draw is kept only if the ordinal order is respected: max(A)<min(W)<=max(W)<min(S)
    <=max(S)<min(C) over all cells. The acceptance rate is reported.

Margins (margin > 0  <=>  claim holds), computed from the audited values of each claim:
    O1-O6  a - b                              D1  IQR_cookie - max other IQR
    D2     TOL - max IQR_IDB over policies    C1  API range - max consent effect
    C2     TOL - max |median ALL - NONE|      C3  TOL - |Q3 cookie ALL - NONE|
    S1     API range - max session effect     S2  composition share - 0.5
    (audited values are rounded to 1e-4, so margins have a 1e-4 resolution)

Usage
    python within_tier_monte_carlo.py --selftest              # fast evaluator vs reference code
    python within_tier_monte_carlo.py --n 500                 # quick run
    python within_tier_monte_carlo.py --n 10000 --seed 42     # full run
    python within_tier_monte_carlo.py --scenarios within-cell wide-cell
"""

import argparse
import json
import math
import platform
import sys
import time
import zlib
from pathlib import Path

import numpy as np

# ── Shared code: claims (alpha_k script) and tier map / loader (grid script) ──
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import sensitivity_analysis as sa
except ImportError:
    import sensibility_analysis as sa
try:
    import within_tier_robustness as wt
except ImportError:
    import within_tier_analysis as wt

MODES, POLICIES, STORAGES = sa.MODES, sa.POLICIES, sa.STORAGES
ALPHA_KEYS, DEFAULT_ALPHAS = sa.ALPHA_KEYS, sa.DEFAULT_ALPHAS
REF_POLICY, TOL, COMPOSITION_SHARE = sa.REF_POLICY, sa.TOL, sa.COMPOSITION_SHARE
CLAIM_IDS = [c[0] for c in sa.CLAIMS]
CLAIM_META = {c[0]: dict(finding=c[1], level=c[2], description=c[3]) for c in sa.CLAIMS}

# ════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════

CATEGORIES = list(wt.PII_TIER_MAP)
NCAT, NDIM = len(CATEGORIES), 6
DIMS = ['ID', 'ATO', 'LINK', 'LOC', 'PROF', 'ENV']
TIER_NAME = 'AWSC'
_CODE = {'A': 0, 'W': 1, 'S': 2, 'C': 3}
T = np.array([[_CODE[t] for t in wt.PII_TIER_MAP[c]] for c in CATEGORIES])   # (NCAT, 6)
ALPHA = np.array([DEFAULT_ALPHAS[k] for k in ALPHA_KEYS])
Z_BASELINE = np.array([wt.PII_IMPACT_MAP_BASELINE[c] for c in CATEGORIES], dtype=float)

_WITHIN = dict(W=(0.10, 0.30), S=(0.50, 0.70), A=(0.0, 0.0), C=(1.0, 1.0))
_WIDE = dict(W=(0.05, 0.45), S=(0.40, 0.90), A=(0.0, 0.0), C=(1.0, 1.0))
_EXTREMES = dict(W=(0.10, 0.30), S=(0.50, 0.70), A=(0.0, 0.05), C=(0.90, 1.0))

SCENARIOS = {
    'within-tier':   dict(_WITHIN, gran='tier'),
    'within-dim':    dict(_WITHIN, gran='dim'),
    'within-cell':   dict(_WITHIN, gran='cell'),
    'wide-tier':     dict(_WIDE, gran='tier'),
    'wide-cell':     dict(_WIDE, gran='cell'),
    'extremes-cell': dict(_EXTREMES, gran='cell'),
}


# ════════════════════════════════════════════════════════════
# ITEMS -> COMPACT TABLE
# An item's risk depends only on (P_i, category set), so items are grouped by
# (mode, policy, storage, category set, P_i); each row carries a count.
# ════════════════════════════════════════════════════════════

class Compiled:
    pass


def compile_rows(ds, cat_sets: list) -> Compiled:
    st_i = {s: i for i, s in enumerate(STORAGES)}
    sto = np.array([st_i.get(s, -1) for s in ds.storage])
    mode = np.array([MODES.index(m) for m in ds.mode])
    pol = np.array([POLICIES.index(p) for p in ds.policy])
    rows = np.column_stack([mode, pol, sto, ds.z_inv, ds.P])
    uniq, counts = np.unique(rows, axis=0, return_counts=True)

    C = Compiled()
    C.n_items, C.n_rows, C.n_sigs = int(ds.n), len(uniq), len(cat_sets)
    C.w = counts.astype(np.int64)
    C.pi = uniq[:, 4].copy()
    C.sig = uniq[:, 3].astype(int)
    cat_idx = {c: i for i, c in enumerate(CATEGORIES)}
    lmax = max(1, max((len(s) for s in cat_sets), default=1))
    C.sigcat = np.full((len(cat_sets), lmax), NCAT, dtype=int)      # NCAT -> zero row
    for s, cats in enumerate(cat_sets):
        known = [cat_idx[c] for c in cats if c in cat_idx]
        C.sigcat[s, :len(known)] = known

    m_, p_, s_ = uniq[:, 0].astype(int), uniq[:, 1].astype(int), uniq[:, 2].astype(int)

    def sub(mask):
        ix = np.flatnonzero(mask)
        return ix, C.w[ix], int(C.w[ix].sum())

    # Only the subsets the claims read (see sa.evaluate_claims / sa.composition_share)
    C.sp = {f"{s}|{p}": sub((s_ == si) & (p_ == pi))
            for si, s in enumerate(STORAGES) for pi, p in enumerate(POLICIES)}
    rp = POLICIES.index(REF_POLICY)
    C.spm = {f"{s}|{REF_POLICY}|{m}": sub((s_ == si) & (p_ == rp) & (m_ == mi))
             for si, s in enumerate(STORAGES) for mi, m in enumerate(MODES)}
    return C


# ════════════════════════════════════════════════════════════
# IMPACT: Z (cells) -> I per category set -> R per row
# ════════════════════════════════════════════════════════════

def impacts(Z: np.ndarray, C: Compiled) -> np.ndarray:
    """Z: (B, NCAT, 6) -> I: (B, n_sigs). Max-pooling over categories, then Noisy-OR."""
    Zp = np.concatenate([Z, np.zeros((Z.shape[0], 1, NDIM))], axis=1)
    Zs = Zp[:, C.sigcat, :].max(axis=2)
    return 1.0 - np.prod(1.0 - ALPHA * Zs, axis=2)


# ════════════════════════════════════════════════════════════
# WEIGHTED STATISTICS (identical to np.percentile 'linear' on the expanded sample)
# ════════════════════════════════════════════════════════════

def _kth(vs, cum, k):
    return vs[np.searchsorted(cum, k, side='right')]


def _percentile(vs, cum, n, q):
    pos = (n - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = min(lo + 1, n - 1)
    a, b = _kth(vs, cum, lo), _kth(vs, cum, hi)
    t, d = pos - lo, b - a
    return float(b - d * (1 - t)) if t >= 0.5 else float(a + d * t)


def _wdescribe(R, sub):
    """Same fields as sa.describe(), computed on the weighted rows."""
    ix, w, tot = sub
    if tot == 0:
        return None
    v = R[ix]
    o = np.argsort(v, kind='stable')
    vs, cum = v[o], np.cumsum(w[o])
    q1, med, q3 = (_percentile(vs, cum, tot, q) for q in (25, 50, 75))
    return {'n': tot, 'mean': float(np.dot(w, v)) / tot, 'median': med,
            'q1': q1, 'q3': q3, 'iqr': q3 - q1, 'max': float(vs[-1])}


def lean_summary(R, C: Compiled) -> dict:
    """The part of sa.summarize() that sa.evaluate_claims() reads."""
    return {'storage_policy': {k: _wdescribe(R, s) for k, s in C.sp.items()},
            'storage_policy_mode': {k: _wdescribe(R, s) for k, s in C.spm.items()}}


# ════════════════════════════════════════════════════════════
# CLAIMS + MARGINS
# ════════════════════════════════════════════════════════════

def margins_from(res: dict) -> dict:
    """margin > 0 <=> claim holds (NaN when the claim is undefined)."""
    nan = float('nan')
    g = {}
    for cid in ('O1', 'O2', 'O3', 'O4', 'O5', 'O6'):
        g[cid] = res[cid]['raw']['a'] - res[cid]['raw']['b']
    r = res['D1']['raw'];  g['D1'] = r['iqr_cookie'] - r['max_other']
    g['D2'] = TOL - max(res['D2']['raw'].values())
    r = res['C1']['raw'];  g['C1'] = r['api_range'] - r['max_consent_gap']
    g['C2'] = TOL - max(res['C2']['raw'].values())
    g['C3'] = TOL - res['C3']['raw']['delta_q3']
    r = res['S1']['raw'];  g['S1'] = r['api_range'] - r['max_mode_gap']
    share = res['S2']['raw']['share']
    g['S2'] = nan if share is None else share - COMPOSITION_SHARE
    return g


def evaluate_R(R, C: Compiled):
    res = sa.evaluate_claims(lean_summary(R, C))
    return {cid: res[cid]['ok'] for cid in CLAIM_IDS}, margins_from(res), res


def evaluate_Z(Z: np.ndarray, C: Compiled):
    I = impacts(Z[None], C)[0]
    return evaluate_R(C.pi * I[C.sig], C)


# ════════════════════════════════════════════════════════════
# SAMPLING
# ════════════════════════════════════════════════════════════

def build_layout(spec: dict) -> dict:
    """Which cells are random, and which shared parameter drives each of them."""
    names, lo, hi, key_to_pid = [], [], [], {}
    pid = -np.ones((NCAT, NDIM), dtype=int)
    fixed = np.zeros((NCAT, NDIM))
    for c in range(NCAT):
        for k in range(NDIM):
            t = int(T[c, k])
            a, b = spec[TIER_NAME[t]]
            if a == b:
                fixed[c, k] = a
                continue
            key = {'cell': (c, k), 'dim': (t, k), 'tier': (t,)}[spec['gran']]
            if key not in key_to_pid:
                key_to_pid[key] = len(names)
                names.append({'cell': f"{TIER_NAME[t]}:{CATEGORIES[c]}.{DIMS[k]}",
                              'dim': f"{TIER_NAME[t]}:{DIMS[k]}",
                              'tier': TIER_NAME[t]}[spec['gran']])
                lo.append(a)
                hi.append(b)
            pid[c, k] = key_to_pid[key]
    return dict(names=names, lo=np.array(lo), hi=np.array(hi), pid=pid, fixed=fixed)


def draw_Z(rng, B: int, L: dict):
    P = rng.uniform(L['lo'], L['hi'], size=(B, len(L['lo'])))
    Z = np.where(L['pid'] >= 0, P[:, np.maximum(L['pid'], 0)], L['fixed'])
    return P, Z


def ordinal_ok(Z: np.ndarray) -> np.ndarray:
    """True where every A cell < every W cell < every S cell < every C cell."""
    mx = [Z[:, T == k].max(axis=1) for k in range(4)]
    mn = [Z[:, T == k].min(axis=1) for k in range(4)]
    return (mx[0] < mn[1]) & (mx[1] < mn[2]) & (mx[2] < mn[3])


# ════════════════════════════════════════════════════════════
# SUMMARY HELPERS
# ════════════════════════════════════════════════════════════

def wilson(k: int, n: int, z: float = 1.96):
    """95% Wilson score interval for a proportion (valid also when k = 0 or k = n)."""
    if n == 0:
        return float('nan'), float('nan')
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, centre - half), min(1.0, centre + half)


def top_drivers(P: np.ndarray, names: list, margins: dict, k: int = 3) -> dict:
    """Pearson r between each drawn parameter and each claim's margin."""
    Pz = (P - P.mean(0)) / (P.std(0) + 1e-12)
    out = {}
    for cid, m in margins.items():
        m = np.asarray(m, float)
        keep = ~np.isnan(m)
        if keep.sum() < 3 or m[keep].std() < 1e-12:
            out[cid] = []
            continue
        mz = (m[keep] - m[keep].mean()) / m[keep].std()
        r = Pz[keep].T @ mz / keep.sum()
        out[cid] = [{'param': names[i], 'r': round(float(r[i]), 3)}
                    for i in np.argsort(-np.abs(r))[:k]]
    return out


def run_scenario(name, spec, C, n, seed, batch_budget=6e7, verbose=True):
    L = build_layout(spec)
    rng = np.random.default_rng(np.random.SeedSequence([seed, zlib.crc32(name.encode())]))
    per_draw = max(1, C.n_sigs * C.sigcat.shape[1] * NDIM * 8)
    B = int(max(8, min(512, batch_budget // per_draw)))

    truth = {k: [] for k in CLAIM_IDS}
    marg = {k: [] for k in CLAIM_IDS}
    Ps = []
    drawn = valid_seen = accepted = 0
    t0, next_print = time.time(), 0.1
    while accepted < n:
        P, Z = draw_Z(rng, B, L)
        drawn += B
        ok = ordinal_ok(Z)
        valid_seen += int(ok.sum())
        if drawn > 500 * max(n, B) and accepted == 0:
            raise RuntimeError(f"{name}: no draw respects the ordinal order.")
        take = min(int(ok.sum()), n - accepted)
        if take == 0:
            continue
        P, Z = P[ok][:take], Z[ok][:take]
        I = impacts(Z, C)
        for b in range(take):
            f, g, _ = evaluate_R(C.pi * I[b][C.sig], C)
            for k in CLAIM_IDS:
                truth[k].append(f[k])
                marg[k].append(g[k])
        Ps.append(P)
        accepted += take
        if verbose and accepted / n >= next_print:
            print(f"    {name}: {accepted:,}/{n:,} draws ({time.time() - t0:.0f}s)", flush=True)
            next_print += 0.1
    return dict(L=L, truth=truth, marg=marg, P=np.vstack(Ps),
                acceptance=valid_seen / drawn, seconds=time.time() - t0)


def summarize(res: dict, base_f: dict, base_g: dict) -> dict:
    claims = {}
    for cid in CLAIM_IDS:
        t = [x for x in res['truth'][cid] if x is not None]
        n, k = len(t), int(sum(t))
        lo, hi = wilson(k, n)
        m = np.asarray(res['marg'][cid], float)
        m = m[~np.isnan(m)]
        entry = dict(**CLAIM_META[cid], n=n, holds=k, excluded=len(res['truth'][cid]) - n,
                     p_hat=(k / n if n else None),
                     wilson95=([lo, hi] if n else None),
                     fail_bound_95=(3.0 / n if (n and k == n) else None),   # rule of three
                     status=sa.status_of(k, n),
                     holds_at_baseline=base_f[cid])
        if len(m):
            bm = base_g[cid]
            has_bm = not (isinstance(bm, float) and math.isnan(bm))
            entry.update(margin_min=float(m.min()), margin_p1=float(np.percentile(m, 1)),
                         margin_median=float(np.median(m)),
                         margin_baseline=(float(bm) if has_bm else None),
                         baseline_margin_percentile=(float((m < bm).mean()) if has_bm else None))
        claims[cid] = entry
    return claims


def print_scenario(name, spec, res, claims):
    print(f"\n  ── {name}  (granularity={spec['gran']}, {len(res['L']['names'])} parameters, "
          f"acceptance={res['acceptance']:.1%}, {res['seconds']:.0f}s)")
    print(f"  {'ID':<4}{'Finding':<8}{'holds':>15}{'p_hat':>8}{'Wilson 95%':>20}"
          f"{'min margin':>12}{'baseline':>10}  Status")
    print(f"  {'-' * 92}")
    for cid, c in claims.items():
        if c['n'] == 0:
            print(f"  {cid:<4}{c['finding']:<8}{'n/a (undefined in every draw)':>45}")
            continue
        w = f"[{c['wilson95'][0]:.4f},{c['wilson95'][1]:.4f}]"
        mn = f"{c['margin_min']:+.4f}" if 'margin_min' in c else "n/a"
        bm = f"{c['margin_baseline']:+.4f}" if c.get('margin_baseline') is not None else "n/a"
        print(f"  {cid:<4}{c['finding']:<8}{c['holds']:>7,}/{c['n']:<7,}{c['p_hat']:>8.4f}"
              f"{w:>20}{mn:>12}{bm:>10}  {c['status']}")


# ════════════════════════════════════════════════════════════
# SELF-TEST: fast evaluator vs reference code (full sa.summarize on every item)
# ════════════════════════════════════════════════════════════

def selftest(ds, cat_sets, C, n_random=12) -> bool:
    def reference(Z):
        wt.set_impact_map(ds, cat_sets, {c: list(Z[i]) for i, c in enumerate(CATEGORIES)})
        return sa.evaluate_claims(sa.summarize(ds, ds.risk(DEFAULT_ALPHAS)))

    cases = [('baseline Z(0)', Z_BASELINE)]
    for zw, zs in [(0.1, 0.5), (0.3, 0.7), (0.2, 0.6)]:
        tv = {0: 0.0, 1: zw, 2: zs, 3: 1.0}
        cases.append((f"grid ({zw},{zs})", np.vectorize(tv.get)(T).astype(float)))
    rng = np.random.default_rng(123)
    for name in ('within-cell', 'wide-cell', 'extremes-cell'):
        L = build_layout(SCENARIOS[name])
        got = 0
        while got < n_random // 3:
            _, Z = draw_Z(rng, 16, L)
            for z in Z[ordinal_ok(Z)][:n_random // 3 - got]:
                cases.append((f"random {name}", z))
                got += 1

    bad = 0
    for label, Z in cases:
        ref = reference(Z)
        _, _, fast = evaluate_Z(Z, C)
        problems = []
        for cid in CLAIM_IDS:
            if ref[cid]['ok'] != fast[cid]['ok']:
                problems.append(f"{cid}: ok ref={ref[cid]['ok']} fast={fast[cid]['ok']}")
            for k, v in ref[cid]['raw'].items():
                u = fast[cid]['raw'][k]
                if (v is None) != (u is None) or (v is not None and abs(v - u) > 1.5e-4):
                    problems.append(f"{cid}.{k}: ref={v} fast={u}")
        if problems:
            bad += 1
            print(f"  [selftest] MISMATCH on {label}: {problems[:4]}")
    wt.set_impact_map(ds, cat_sets, wt.PII_IMPACT_MAP_BASELINE)   # restore
    print(f"  [selftest] {len(cases) - bad}/{len(cases)} cases identical to the reference code "
          f"({'PASS' if bad == 0 else 'FAIL'})")
    return bad == 0


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

class _Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, np.bool_):    return bool(o)
        if isinstance(o, np.integer):  return int(o)
        if isinstance(o, np.floating): return float(o)
        if isinstance(o, np.ndarray):  return o.tolist()
        return super().default(o)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--n', type=int, default=10000, help='valid draws per scenario (default 10000)')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--scenarios', nargs='+', default=list(SCENARIOS), choices=list(SCENARIOS))
    ap.add_argument('--data-root', type=Path, default=None,
                    help='folder containing user/<Mode>/<User>/<Policy>/... (default: <repo>/data)')
    ap.add_argument('--out', type=Path, default=None, help='output json (default: <data-root>/reports/...)')
    ap.add_argument('--save-draws', action='store_true', help='also save per-draw parameters and margins (.npz)')
    ap.add_argument('--selftest', action='store_true', help='compare with the reference code and exit')
    a = ap.parse_args()

    if a.data_root is None:
        try:
            a.data_root = Path(__file__).resolve().parents[2] / 'data'
        except IndexError:
            a.data_root = Path.cwd() / 'data'
    out_path = a.out or (a.data_root / 'reports' / 'within_tier_monte_carlo.json')

    print('=' * 72)
    print('  WITHIN-TIER ROBUSTNESS -- MONTE CARLO  (Level 1: cardinal, fixed order)')
    print(f'  N={a.n:,} draws/scenario   seed={a.seed}   scenarios={len(a.scenarios)}')
    print(f'  Claims: {", ".join(CLAIM_IDS)} (shared with {sa.__name__})')
    print('=' * 72)

    print('\n  [Load] Reading vectorized items...')
    ds, cat_sets = wt.load_dataset(a.data_root)
    if ds.n == 0:
        sys.exit('  ERROR: no items loaded. Check --data-root.')
    C = compile_rows(ds, cat_sets)
    print(f'  {C.n_items:,} items -> {C.n_rows:,} distinct rows, {C.n_sigs} category sets')

    print('\n  [Check] Fast evaluator vs reference code...')
    if not selftest(ds, cat_sets, C):
        sys.exit('  Aborting: fast evaluator does not reproduce the reference code.')
    if a.selftest:
        sys.exit(0)

    base_f, base_g, base_res = evaluate_Z(Z_BASELINE, C)
    print(f"\n  [Baseline Z(0)] claims that hold: {sum(1 for v in base_f.values() if v)}/{len(base_f)}  "
          f"(must match the default column of the alpha_k table)")

    out = {'metadata': dict(analysis='within_tier_monte_carlo_level1', n_per_scenario=a.n, seed=a.seed,
                            alphas=DEFAULT_ALPHAS, n_items=C.n_items, n_rows=C.n_rows,
                            claims_from=sa.__name__,
                            conventions=dict(ref_policy=REF_POLICY, tol=TOL,
                                             robust_rate=sa.ROBUST_RATE,
                                             composition_share=COMPOSITION_SHARE),
                            numpy=np.__version__, python=platform.python_version()),
           'baseline': {k: dict(holds=base_f[k], margin=base_g[k], value=base_res[k]['value'])
                        for k in CLAIM_IDS},
           'scenarios': {}}
    for name in a.scenarios:
        spec = SCENARIOS[name]
        print(f'\n  [Scenario] {name}')
        res = run_scenario(name, spec, C, a.n, a.seed)
        claims = summarize(res, base_f, base_g)
        print_scenario(name, spec, res, claims)
        drivers = top_drivers(res['P'], res['L']['names'], res['marg'])
        for cid, c in claims.items():
            if c['n'] and c['holds'] < c['n'] and drivers.get(cid):
                d = ', '.join(f"{x['param']} (r={x['r']:+.2f})" for x in drivers[cid])
                print(f"     ! [{cid}] fails in {1 - c['p_hat']:.2%} of draws; main drivers: {d}")
        out['scenarios'][name] = dict(spec={k: v for k, v in spec.items()},
                                      n_parameters=len(res['L']['names']),
                                      acceptance_rate=res['acceptance'],
                                      claims=claims, drivers=drivers)
        if a.save_draws:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            np.savez_compressed(out_path.with_name(f'within_tier_mc_draws_{name}.npz'),
                                params=res['P'], param_names=np.array(res['L']['names']),
                                **{f'margin_{k}': np.asarray(res['marg'][k], float) for k in CLAIM_IDS},
                                **{f'truth_{k}': np.array([-1 if x is None else int(x) for x in res['truth'][k]],
                                                          dtype=np.int8) for k in CLAIM_IDS})

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2, ensure_ascii=False, cls=_Enc)
    print(f'\n  Saved -> {out_path}')
    print('=' * 72)


if __name__ == '__main__':
    main()