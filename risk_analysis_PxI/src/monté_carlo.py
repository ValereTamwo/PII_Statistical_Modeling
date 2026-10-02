#!/usr/bin/env python3
"""
WITHIN-TIER ROBUSTNESS -- MONTE CARLO (Level 1: cardinal uncertainty, fixed order)
===================================================================================

What it adds
------------
The 9-point grid gives ONE value to every cell of a tier. The real baseline Z(0) is
heterogeneous inside a tier (e.g. W cells are 0.1, 0.2 or 0.3). Here the value of every
non-boundary cell is DRAWN at random inside an interval, N times, the ordinal structure
(which cell belongs to which tier) being kept fixed. For each draw the 14 claims are
re-evaluated, and we report how often each one holds, with a confidence interval, and
HOW FAR from its threshold it stays (margin).

Scenarios (name = <ranges>-<granularity>)
    granularity  tier : one value for all W cells, one for all S cells    (2 parameters)
                 dim  : one value per (tier, dimension)                   (12 parameters)
                 cell : one independent value per cell                    (36 parameters)
    ranges       within   : W~U[0.10,0.30]  S~U[0.50,0.70]   (the intervals of the paper)
                 wide     : W~U[0.05,0.45]  S~U[0.40,0.90]   (stress test, W<S enforced)
                 extremes : within + A~U[0,0.05] and C~U[0.90,1.00] (boundary tiers not exact)
    A draw is kept only if the ordinal order is respected: max(A)<min(W)<=max(W)<min(S)
    <=max(S)<min(C) over all cells. The acceptance rate is reported.

Usage
    python within_tier_monte_carlo.py --selftest              # check vs reference code
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from within_tier_analysis import (  # noqa: E402
    MODES, POLICIES, STORAGES, ALPHA_KEYS, DEFAULT_ALPHAS,
    PII_TIER_MAP, PII_IMPACT_MAP_BASELINE, FINDING_LABELS,
    load_all_items,
    _z_composite, _calculate_ii, _aggregate, _describe_storage, _evaluate_findings,
)

# ════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════

CATEGORIES = list(PII_TIER_MAP)
NCAT, NDIM = len(CATEGORIES), 6
DIMS = ['ID', 'ATO', 'LINK', 'LOC', 'PROF', 'ENV']
TIER_NAME = 'AWSC'
_CODE = {'A': 0, 'W': 1, 'S': 2, 'C': 3}
T = np.array([[_CODE[t] for t in PII_TIER_MAP[c]] for c in CATEGORIES])   # (NCAT, 6)
ALPHA = np.array([DEFAULT_ALPHAS[k] for k in ALPHA_KEYS])
KEYS = list(FINDING_LABELS)

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
# An item's impact depends only on its SET of categories (max-pooling), so items are
# grouped by (mode, policy, storage, category-set, pi). Each row carries a count.
# ════════════════════════════════════════════════════════════

class Compiled:
    pass


def compile_items(items: list) -> Compiled:
    cat_idx = {c: i for i, c in enumerate(CATEGORIES)}
    st_idx = {s.lower(): i for i, s in enumerate(STORAGES)}
    md_idx = {m: i for i, m in enumerate(MODES)}
    pl_idx = {p: i for i, p in enumerate(POLICIES)}
    sig_ids, sigs = {}, []
    rows = np.empty((len(items), 5))
    for n, it in enumerate(items):
        sig = tuple(sorted({cat_idx[c] for c in it['_cats'] if c in cat_idx}))
        sid = sig_ids.get(sig)
        if sid is None:
            sid = sig_ids[sig] = len(sigs)
            sigs.append(sig)
        rows[n] = (md_idx[it['_mode']], pl_idx[it['_policy']],
                   st_idx.get(it.get('storage_type', '').lower(), -1),
                   sid, it['pi_exposure'])
    uniq, counts = np.unique(rows, axis=0, return_counts=True)

    C = Compiled()
    C.n_items, C.n_rows, C.n_sigs = len(items), len(uniq), len(sigs)
    C.w = counts.astype(np.int64)
    C.pi = uniq[:, 4].copy()
    C.sig = uniq[:, 3].astype(int)
    lmax = max(1, max((len(s) for s in sigs), default=1))
    C.sigcat = np.full((len(sigs), lmax), NCAT, dtype=int)      # NCAT = padding -> zero row
    for s, cats in enumerate(sigs):
        C.sigcat[s, :len(cats)] = cats

    mode, pol, sto = uniq[:, 0].astype(int), uniq[:, 1].astype(int), uniq[:, 2].astype(int)

    def sub(mask):
        ix = np.flatnonzero(mask)
        return ix, C.w[ix], int(C.w[ix].sum())

    C.by_mode = {m: sub(mode == i) for i, m in enumerate(MODES)}
    C.by_policy = {p: sub(pol == i) for i, p in enumerate(POLICIES)}
    C.by_storage = {s: sub(sto == i) for i, s in enumerate(STORAGES)}
    ck = STORAGES.index('cookie')
    C.ck_all = sub((sto == ck) & (pol == POLICIES.index('ALL')))
    C.ck_none = sub((sto == ck) & (pol == POLICIES.index('NONE')))
    return C


# ════════════════════════════════════════════════════════════
# IMPACT: Z (cells) -> I per category-set -> R per row
# ════════════════════════════════════════════════════════════

def impacts(Z: np.ndarray, C: Compiled) -> np.ndarray:
    """Z: (B, NCAT, 6) -> I: (B, n_sigs). Max-pooling over categories, then Noisy-OR."""
    Zp = np.concatenate([Z, np.zeros((Z.shape[0], 1, NDIM))], axis=1)
    Zs = Zp[:, C.sigcat, :].max(axis=2)
    return 1.0 - np.prod(1.0 - ALPHA * Zs, axis=2)


# ════════════════════════════════════════════════════════════
# STATISTICS ON A WEIGHTED SAMPLE (same conventions as numpy on the expanded sample)
# ════════════════════════════════════════════════════════════

def _wmean(R, sub):
    ix, w, tot = sub
    return round(float(np.dot(w, R[ix])) / tot, 4) if tot else 0.0


def _sorted(R, sub):
    ix, w, tot = sub
    if tot == 0:
        return None
    v = R[ix]
    o = np.argsort(v, kind='stable')
    return v[o], np.cumsum(w[o]), tot


def _kth(vs, cum, k):
    return vs[np.searchsorted(cum, k, side='right')]


def _percentile(sw, q):
    """np.percentile(..., q) with the default 'linear' method."""
    vs, cum, n = sw
    pos = (n - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = min(lo + 1, n - 1)
    a, b = _kth(vs, cum, lo), _kth(vs, cum, hi)
    t, d = pos - lo, b - a
    return float(b - d * (1 - t)) if t >= 0.5 else float(a + d * t)


def _median(sw):
    """np.median."""
    vs, cum, n = sw
    if n % 2:
        return float(_kth(vs, cum, n // 2))
    return float((_kth(vs, cum, n // 2 - 1) + _kth(vs, cum, n // 2)) / 2.0)


# ════════════════════════════════════════════════════════════
# CLAIMS  (same predicates as _evaluate_findings; margin > 0  <=>  claim holds)
# ════════════════════════════════════════════════════════════

def evaluate(R: np.ndarray, C: Compiled):
    """R: (n_rows,) risk of each row for ONE draw. Returns (stats, findings, margins)."""
    mm = {m: _wmean(R, C.by_mode[m]) for m in MODES}
    mp = {p: _wmean(R, C.by_policy[p]) for p in POLICIES}
    ms = {s: _wmean(R, C.by_storage[s]) for s in STORAGES}

    dist = {}
    for s in STORAGES:
        sw = _sorted(R, C.by_storage[s])
        if sw is None:
            dist[s] = dict(median=None, iqr=None, iqr_raw=None)
            continue
        q1, med, q3 = _percentile(sw, 25), _percentile(sw, 50), _percentile(sw, 75)
        dist[s] = dict(median=round(med, 4), iqr=round(q3 - q1, 4), iqr_raw=q3 - q1)

    def med_of(sub):
        sw = _sorted(R, sub)
        return _median(sw) if sw is not None else None

    med_auth, med_unauth = med_of(C.by_mode['Auth']), med_of(C.by_mode['UnAuth'])
    med_ck_all, med_ck_none = med_of(C.ck_all), med_of(C.ck_none)

    nan = float('nan')
    ck, ss, ls, idb = 'cookie', 'sessionStorage', 'localStorage', 'IndexedDB'
    f, g = {}, {}

    d = abs(mm.get('Auth', 0) - mm.get('UnAuth', 0))
    f['M1_auth_unauth_equiv'], g['M1_auth_unauth_equiv'] = bool(d < 0.05), 0.05 - d
    f['M2_all_gt_none'] = bool(mp.get('ALL', 0) >= mp.get('NONE', 0))
    g['M2_all_gt_none'] = mp.get('ALL', 0) - mp.get('NONE', 0)
    f['M3_cookie_gt_ss'], g['M3_cookie_gt_ss'] = bool(ms[ck] > ms[ss]), ms[ck] - ms[ss]
    f['M4_cookie_gt_idb'], g['M4_cookie_gt_idb'] = bool(ms[ck] > ms[idb]), ms[ck] - ms[idb]
    d = abs(ms[ck] - ms[ls])
    f['M5_ls_equiv_cookie'], g['M5_ls_equiv_cookie'] = bool(d < 0.07), 0.07 - d
    f['M6_ls_gt_ss'], g['M6_ls_gt_ss'] = bool(ms[ls] > ms[ss]), ms[ls] - ms[ss]
    f['M7_ls_gt_idb'], g['M7_ls_gt_idb'] = bool(ms[ls] > ms[idb]), ms[ls] - ms[idb]

    mc, mss, mls = dist[ck]['median'], dist[ss]['median'], dist[ls]['median']
    ic, iss, ils, iidb = dist[ck]['iqr'], dist[ss]['iqr'], dist[ls]['iqr'], dist[idb]['iqr']

    f['D1_median_cookie_gt_ss'] = bool(mc is not None and mss is not None and mc > mss)
    g['D1_median_cookie_gt_ss'] = (mc - mss) if (mc is not None and mss is not None) else nan
    f['D2_idb_iqr_zero'] = bool(iidb is not None and iidb == 0.0)
    g['D2_idb_iqr_zero'] = (5e-5 - dist[idb]['iqr_raw']) if iidb is not None else nan
    f['D3_iqr_cookie_gt_ss'] = bool(ic is not None and iss is not None and ic > iss)
    g['D3_iqr_cookie_gt_ss'] = (ic - iss) if (ic is not None and iss is not None) else nan
    ok4 = med_auth is not None and med_unauth is not None
    f['D4_median_mode_equiv'] = bool(ok4 and abs(med_auth - med_unauth) < 0.01)
    g['D4_median_mode_equiv'] = (0.01 - abs(med_auth - med_unauth)) if ok4 else nan
    if med_ck_all is not None and med_ck_none is not None:
        f['D5_cookie_median_stable'] = bool(abs(med_ck_all - med_ck_none) < 0.02)
        g['D5_cookie_median_stable'] = 0.02 - abs(med_ck_all - med_ck_none)
    else:
        f['D5_cookie_median_stable'], g['D5_cookie_median_stable'] = None, nan
    ok6 = mls is not None and mc is not None
    f['D6_median_ls_equiv_cookie'] = bool(ok6 and abs(mc - mls) < 0.09)
    g['D6_median_ls_equiv_cookie'] = (0.09 - abs(mc - mls)) if ok6 else nan
    ok7 = ils is not None and ic is not None
    f['D7_iqr_ls_lt_cookie'] = bool(ok7 and ils < ic)
    g['D7_iqr_ls_lt_cookie'] = (ic - ils) if ok7 else nan

    stats = dict(mean_by_mode=mm, mean_by_policy=mp, mean_by_storage=ms, dist=dist,
                 med_auth=med_auth, med_unauth=med_unauth,
                 med_ck_all=med_ck_all, med_ck_none=med_ck_none)
    return stats, f, g


def evaluate_Z(Z: np.ndarray, C: Compiled):
    """Evaluate ONE impact map Z (NCAT, 6)."""
    I = impacts(Z[None], C)[0]
    return evaluate(C.pi * I[C.sig], C)


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
    for key, m in margins.items():
        m = np.asarray(m, float)
        if np.isnan(m).any() or m.std() < 1e-12:
            out[key] = []
            continue
        r = Pz.T @ ((m - m.mean()) / m.std()) / len(m)
        out[key] = [{'param': names[i], 'r': round(float(r[i]), 3)}
                    for i in np.argsort(-np.abs(r))[:k]]
    return out


def run_scenario(name, spec, C, n, seed, batch_budget=6e7, verbose=True):
    L = build_layout(spec)
    rng = np.random.default_rng(np.random.SeedSequence([seed, zlib.crc32(name.encode())]))
    per_draw = max(1, C.n_sigs * C.sigcat.shape[1] * NDIM * 8)
    B = int(max(8, min(512, batch_budget // per_draw)))

    truth = {k: [] for k in KEYS}
    marg = {k: [] for k in KEYS}
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
            _, f, g = evaluate(C.pi * I[b][C.sig], C)
            for k in KEYS:
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
    for key, (level, label) in FINDING_LABELS.items():
        t = [x for x in res['truth'][key] if x is not None]
        n, k = len(t), int(sum(t))
        lo, hi = wilson(k, n)
        m = np.asarray(res['marg'][key], float)
        m = m[~np.isnan(m)]
        entry = dict(label=label, level=level, n=n, holds=k,
                     p_hat=(k / n if n else None),
                     wilson95=([lo, hi] if n else None),
                     fail_bound_95=(3.0 / n if (n and k == n) else None),
                     holds_at_baseline=base_f[key])
        if len(m):
            bm = base_g[key]
            has_bm = not (isinstance(bm, float) and math.isnan(bm))
            entry.update(margin_min=float(m.min()), margin_p1=float(np.percentile(m, 1)),
                         margin_median=float(np.median(m)),
                         margin_baseline=(float(bm) if has_bm else None),
                         baseline_margin_percentile=(float((m < bm).mean()) if has_bm else None))
        claims[key] = entry
    return claims


def print_scenario(name, spec, res, claims):
    print(f"\n  ── {name}  (granularity={spec['gran']}, {len(res['L']['names'])} parameters, "
          f"acceptance={res['acceptance']:.1%}, {res['seconds']:.0f}s)")
    print(f"  {'claim':<58}{'holds':>15}{'p_hat':>8}{'Wilson 95%':>20}{'min margin':>12}")
    print(f"  {'-' * 113}")
    for key, c in claims.items():
        if c['n'] == 0:
            print(f"  {c['label']:<58}{'n/a (undefined on this data)':>55}")
            continue
        w = f"[{c['wilson95'][0]:.4f},{c['wilson95'][1]:.4f}]"
        mn = f"{c['margin_min']:+.5f}" if 'margin_min' in c else "n/a"
        print(f"  {c['label']:<58}{c['holds']:>7,}/{c['n']:<7,}{c['p_hat']:>8.4f}{w:>20}{mn:>12}")


# ════════════════════════════════════════════════════════════
# SELF-TEST: fast implementation vs. reference code of within_tier_analysis.py
# ════════════════════════════════════════════════════════════

def _synthetic_items(n=4000, seed=7):
    rng = np.random.default_rng(seed)
    pool = CATEGORIES + ['NOT_IN_MAP']
    st_names = ['cookie', 'localStorage', 'sessionStorage', 'IndexedDB', 'Cookie', 'other']
    items = []
    for _ in range(n):
        k = int(rng.choice([0, 1, 1, 2, 3]))
        items.append({
            '_cats': [str(c) for c in rng.choice(pool, size=k, replace=False)] if k else [],
            'pi_exposure': float(rng.choice([0.4681, 0.6739, 0.7528, 0.8751, 0.95])),
            '_mode': str(rng.choice(MODES)), '_policy': str(rng.choice(POLICIES)),
            'storage_type': str(rng.choice(st_names)),
        })
    return items


def selftest(n_random=30) -> bool:
    items = _synthetic_items()
    C = compile_items(items)
    print(f"  [selftest] {C.n_items:,} synthetic items -> {C.n_rows:,} rows, {C.n_sigs} category-sets")

    def reference(Zmap):
        impact = {c: [float(x) for x in Zmap[i]] for i, c in enumerate(CATEGORIES)}
        for it in items:
            it['_z'] = _z_composite(it['_cats'], impact)
            it['_ii'] = _calculate_ii(it['_z'], DEFAULT_ALPHAS)
            it['_risk_i'] = it['pi_exposure'] * it['_ii']
        agg, dist = _aggregate(items), _describe_storage(items)
        f = _evaluate_findings(agg, dist, items)
        med = lambda sel: float(np.median([i['_risk_i'] for i in items if sel(i)]))  # noqa: E731
        extra = dict(
            med_auth=med(lambda i: i['_mode'] == 'Auth'),
            med_unauth=med(lambda i: i['_mode'] == 'UnAuth'),
            med_ck_all=med(lambda i: i['storage_type'].lower() == 'cookie' and i['_policy'] == 'ALL'),
            med_ck_none=med(lambda i: i['storage_type'].lower() == 'cookie' and i['_policy'] == 'NONE'))
        return agg, dist, f, extra

    cases = [('baseline Z(0)', np.array([PII_IMPACT_MAP_BASELINE[c] for c in CATEGORIES]))]
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
        agg, dist, f_ref, extra = reference(Z)
        stats, f_fast, _ = evaluate_Z(Z, C)
        problems = []
        for grp, key in (('mean_by_mode', MODES), ('mean_by_policy', POLICIES), ('mean_by_storage', STORAGES)):
            for x in key:
                if agg[grp][x] != stats[grp][x]:
                    problems.append(f"{grp}[{x}] {agg[grp][x]} != {stats[grp][x]}")
        for s in STORAGES:
            for fld in ('median', 'iqr'):
                if dist[s][fld] != stats['dist'][s][fld]:
                    problems.append(f"dist[{s}].{fld} {dist[s][fld]} != {stats['dist'][s][fld]}")
        for k, v in extra.items():
            if abs(v - stats[k]) > 1e-12:
                problems.append(f"{k} {v} != {stats[k]}")
        for k in KEYS:
            if f_ref[k] != f_fast[k]:
                problems.append(f"claim {k}: ref={f_ref[k]} fast={f_fast[k]}")
        if problems:
            bad += 1
            print(f"  [selftest] MISMATCH on {label}: {problems[:4]}")
    print(f"  [selftest] {len(cases) - bad}/{len(cases)} cases identical to the reference code "
          f"({'PASS' if bad == 0 else 'FAIL'})")
    return bad == 0


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

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

    if a.selftest:
        sys.exit(0 if selftest() else 1)

    if a.data_root is None:
        try:
            a.data_root = Path(__file__).resolve().parents[2] / 'data'
        except IndexError:
            a.data_root = Path.cwd() / 'data'
    out_path = a.out or (a.data_root / 'reports' / 'within_tier_monte_carlo.json')

    print('=' * 72)
    print('  WITHIN-TIER ROBUSTNESS -- MONTE CARLO  (Level 1: cardinal, fixed order)')
    print(f'  N={a.n:,} draws/scenario   seed={a.seed}   scenarios={len(a.scenarios)}')
    print('=' * 72)

    print('\n  [Load] Reading vectorized items...')
    items = load_all_items(a.data_root)
    if not items:
        sys.exit('  ERROR: no items loaded. Check --data-root.')
    C = compile_items(items)
    print(f'  {C.n_items:,} items -> {C.n_rows:,} distinct rows, {C.n_sigs} category-sets')

    print('\n  [Check] Fast evaluator vs reference code...')
    if not selftest(n_random=15):
        sys.exit('  Aborting: fast evaluator does not reproduce the reference code.')

    Zb = np.array([PII_IMPACT_MAP_BASELINE[c] for c in CATEGORIES])
    _, base_f, base_g = evaluate_Z(Zb, C)
    print('\n  [Baseline Z(0), heterogeneous within tiers] claims that hold: '
          f"{sum(1 for v in base_f.values() if v)}/{len(base_f)}")

    out = {'metadata': dict(analysis='within_tier_monte_carlo_level1', n_per_scenario=a.n, seed=a.seed,
                            alphas=DEFAULT_ALPHAS, n_items=C.n_items, n_rows=C.n_rows,
                            numpy=np.__version__, python=platform.python_version()),
           'baseline': {k: dict(holds=base_f[k], margin=base_g[k]) for k in KEYS},
           'scenarios': {}}
    for name in a.scenarios:
        spec = SCENARIOS[name]
        print(f'\n  [Scenario] {name}')
        res = run_scenario(name, spec, C, a.n, a.seed)
        claims = summarize(res, base_f, base_g)
        print_scenario(name, spec, res, claims)
        drivers = top_drivers(res['P'], res['L']['names'], res['marg'])
        for key, c in claims.items():
            if c['n'] and c['holds'] < c['n'] and drivers.get(key):
                d = ', '.join(f"{x['param']} (r={x['r']:+.2f})" for x in drivers[key])
                print(f"     ⚠ [{c['label']}] fails in {1 - c['p_hat']:.2%} of draws; main drivers: {d}")
        out['scenarios'][name] = dict(spec={k: v for k, v in spec.items()},
                                      n_parameters=len(res['L']['names']),
                                      acceptance_rate=res['acceptance'],
                                      claims=claims, drivers=drivers)
        if a.save_draws:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            np.savez_compressed(out_path.with_name(f'within_tier_mc_draws_{name}.npz'),
                                params=res['P'], param_names=np.array(res['L']['names']),
                                **{f'margin_{k}': np.asarray(res['marg'][k], float) for k in KEYS},
                                **{f'truth_{k}': np.array([-1 if x is None else int(x) for x in res['truth'][k]],
                                                          dtype=np.int8) for k in KEYS})

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f'\n  Saved -> {out_path}')
    print('=' * 72)


if __name__ == '__main__':
    main()