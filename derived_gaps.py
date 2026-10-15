#!/usr/bin/env python3
"""
Compute derived gaps and composition effects from the risk_statistics.json files.

Usage
-----
  python derived_gaps.py --main reports/risk_statistics.json \
                         --countries reports/risk_statistics_13countries.json \
                         --out reports/derived_gaps.json
Either input may be omitted.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

APIS = ["cookie", "localStorage", "sessionStorage", "IndexedDB"]
SHORT = {"cookie": "cookie", "localStorage": "LS", "sessionStorage": "SS", "IndexedDB": "IDB"}
EPS = 1e-9  # stats are rounded to 4 decimals in the json; ties are exact
MIN_GAP = 0.01  # below this |mean gap|, the composition share is noise (ratio of two tiny numbers)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def r4(x):
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return None
    return round(float(x), 4)


def risk(node):
    """Return the risk_i stats dict of a node, or None if empty."""
    if node is None:
        return None
    s = node.get("risk_i")
    if not s or not s.get("n"):
        return None
    return s


def mode_labels(d):
    """Detect the (authenticated, unauthenticated) labels used in the file."""
    pol = next(iter(d["by_policy_mode"].values()))
    keys = list(pol)
    auth = next(k for k in keys if k.upper() == "AUTH")
    unauth = next(k for k in keys if k.upper() in ("UNAUTH", "NOTAUTH"))
    return auth, unauth


def pooled_mean(stats_list):
    stats_list = [s for s in stats_list if s]
    n = sum(s["n"] for s in stats_list)
    if n == 0:
        return None, 0
    return sum(s["n"] * s["mean"] for s in stats_list) / n, n


def api_spread(means):
    """Range of per-API means (max - min) and the two APIs involved."""
    m = {k: v for k, v in means.items() if v is not None}
    hi = max(m, key=m.get)
    lo = min(m, key=m.get)
    return m[hi] - m[lo], hi, lo


def composition(per_api_A, per_api_U, min_gap=None):
    """
    Composition reweighting.
    per_api_X: {api: stats} for mode X (A = authenticated, U = unauthenticated).
    Counterfactual = sum_s w_s^A * mean_s^U  (U per-API means, A API mix).
    share_explained = 1 - |cf - mean_A| / |mean_U - mean_A|
    """
    apis = [a for a in APIS if per_api_A.get(a) and per_api_U.get(a)]
    nA = sum(per_api_A[a]["n"] for a in apis)
    nU = sum(per_api_U[a]["n"] for a in apis)
    mean_A = sum(per_api_A[a]["n"] * per_api_A[a]["mean"] for a in apis) / nA
    mean_U = sum(per_api_U[a]["n"] * per_api_U[a]["mean"] for a in apis) / nU
    wA = {a: per_api_A[a]["n"] / nA for a in apis}
    wU = {a: per_api_U[a]["n"] / nU for a in apis}
    cf = sum(wA[a] * per_api_U[a]["mean"] for a in apis)
    gap = mean_U - mean_A
    resid = cf - mean_A
    min_gap = MIN_GAP if min_gap is None else min_gap
    raw = (1 - abs(resid) / abs(gap)) if abs(gap) > EPS else None
    if abs(gap) < min_gap:
        reliable, note = False, f"|gap| < {min_gap}: share not computed (ratio of two near-zero numbers)"
    elif raw is None or not (0 <= raw <= 1):
        reliable, note = False, "mix and within-API effects go in opposite directions: a 'share explained' is not defined"
    else:
        reliable, note = True, None
    share = raw if reliable else None
    return {
        "mean_auth": r4(mean_A),
        "mean_unauth": r4(mean_U),
        "gap_unauth_minus_auth": r4(gap),
        "counterfactual_unauth_with_auth_mix": r4(cf),
        "residual_gap": r4(resid),
        "share_explained_by_composition": r4(share),
        "share_reliable": reliable,
        "share_raw": r4(raw),
        "share_note": note,
        "api_share_auth": {a: r4(wA[a]) for a in apis},
        "api_share_unauth": {a: r4(wU[a]) for a in apis},
        "formula": "cf = sum_s w_s^AUTH * mean_s^UNAUTH ; share = 1 - |cf - mean_AUTH| / |mean_UNAUTH - mean_AUTH|",
    }


def within_api_mode_effects(per_api_A, per_api_U):
    out = {}
    for a in APIS:
        A, U = per_api_A.get(a), per_api_U.get(a)
        if not (A and U):
            continue
        out[a] = {
            "mean_auth": r4(A["mean"]), "mean_unauth": r4(U["mean"]),
            "abs_mean_gap": r4(abs(A["mean"] - U["mean"])),
            "median_auth": r4(A["median"]), "median_unauth": r4(U["median"]),
            "abs_median_gap": r4(abs(A["median"] - U["median"])),
        }
    worst = max(out, key=lambda k: out[k]["abs_mean_gap"])
    return out, worst


def pearson(x, y):
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(x, y))
    sx = math.sqrt(sum((a - mx) ** 2 for a in x))
    sy = math.sqrt(sum((b - my) ** 2 for b in y))
    return sxy / (sx * sy)


# --------------------------------------------------------------------------
# RQ4 (main dataset: several consent policies, two modes)
# --------------------------------------------------------------------------
def analyze_main(d):
    A, U = mode_labels(d)
    policies = list(d["by_policy_mode"])
    ref = "ALL" if "ALL" in policies else policies[0]
    bsp, bspm, bpm = d["by_storage_policy"], d["by_storage_policy_mode"], d["by_policy_mode"]
    res = {"mode_labels": {"auth": A, "unauth": U}, "policies": policies, "reference_policy": ref}

    # --- per-API stats (modes pooled) and API spread, per policy
    per_policy = {}
    for p in policies:
        means = {a: bsp[a][p]["risk_i"]["mean"] for a in APIS if risk(bsp[a].get(p))}
        spread, hi, lo = api_spread(means)
        n_tot = sum(bsp[a][p]["risk_i"]["n"] for a in means)
        per_policy[p] = {
            "n_total": n_tot,
            "api_share": {a: r4(bsp[a][p]["risk_i"]["n"] / n_tot) for a in means},
            "api_mean": {a: r4(v) for a, v in means.items()},
            "api_spread_of_means": r4(spread), "api_spread_between": [hi, lo],
            "mean_gap_cookie_minus_LS": r4(means["cookie"] - means["localStorage"]),
        }
    res["per_policy"] = per_policy

    # --- consent effect: every policy vs reference, per API and overall
    consent = {}
    for p in policies:
        if p == ref:
            continue
        block = {}
        for a in APIS:
            s0, s1 = risk(bsp[a].get(ref)), risk(bsp[a].get(p))
            if not (s0 and s1):
                continue
            block[a] = {
                "n_ref": s0["n"], "n_policy": s1["n"],
                "count_change_pct": r4(100 * (s1["n"] - s0["n"]) / s0["n"]),
                "mean_ref": r4(s0["mean"]), "mean_policy": r4(s1["mean"]),
                "mean_change_abs": r4(s1["mean"] - s0["mean"]),
                "mean_change_rel_pct": r4(100 * (s1["mean"] - s0["mean"]) / s0["mean"]),
                "median_shift": r4(s1["median"] - s0["median"]),
                "q1_shift": r4(s1["q1"] - s0["q1"]),
                "q3_shift": r4(s1["q3"] - s0["q3"]),
                "iqr_shift": r4(s1["iqr"] - s0["iqr"]),
                "max_shift": r4(s1["max"] - s0["max"]),
            }
        n0 = per_policy[ref]["n_total"]
        n1 = per_policy[p]["n_total"]
        block["_overall"] = {
            "n_ref": n0, "n_policy": n1,
            "count_change_pct": r4(100 * (n1 - n0) / n0),
            "max_abs_mean_change": r4(max(abs(block[a]["mean_change_abs"]) for a in APIS if a in block)),
            "max_abs_rel_mean_change_pct": r4(max(abs(block[a]["mean_change_rel_pct"]) for a in APIS if a in block)),
            "count_change_pct_range": [
                r4(min(block[a]["count_change_pct"] for a in APIS if a in block)),
                r4(max(block[a]["count_change_pct"] for a in APIS if a in block)),
            ],
        }
        consent[f"{ref}_to_{p}"] = block
    res["consent_effect"] = consent

    # --- session mode, per policy
    session = {}
    for p in policies:
        pa = {a: risk(bspm[a].get(p, {}).get(A)) for a in APIS}
        pu = {a: risk(bspm[a].get(p, {}).get(U)) for a in APIS}
        effects, worst = within_api_mode_effects(pa, pu)
        spread = per_policy[p]["api_spread_of_means"]
        gA, gU = bpm[p][A]["risk_i"], bpm[p][U]["risk_i"]
        session[p] = {
            "aggregate": {
                "auth": {k: r4(gA[k]) for k in ("n", "q1", "median", "q3", "iqr", "mean")},
                "unauth": {k: r4(gU[k]) for k in ("n", "q1", "median", "q3", "iqr", "mean")},
                "volume_ratio_unauth_over_auth": r4(gU["n"] / gA["n"]),
            },
            "within_api": effects,
            "max_within_api_mean_gap": effects[worst]["abs_mean_gap"],
            "max_within_api_mean_gap_api": worst,
            "max_within_api_median_gap": r4(max(e["abs_median_gap"] for e in effects.values())),
            "api_spread_of_means": spread,
            "ratio_spread_over_max_gap": r4(spread / effects[worst]["abs_mean_gap"]) if effects[worst]["abs_mean_gap"] else None,
            "composition": composition(pa, pu),
            "idb_count": {"auth": pa["IndexedDB"]["n"] if pa["IndexedDB"] else 0,
                          "unauth": pu["IndexedDB"]["n"] if pu["IndexedDB"] else 0},
        }
    res["session_mode"] = session

    # --- IndexedDB count across policies within each mode
    idb = {}
    for m in (A, U):
        c = {p: (risk(bspm["IndexedDB"].get(p, {}).get(m)) or {"n": 0})["n"] for p in policies}
        idb[m] = {"counts": c,
                  "change_pct_vs_ref": {p: r4(100 * (c[p] - c[ref]) / c[ref]) for p in policies if p != ref and c[ref]}}
    res["idb_counts_by_mode_policy"] = idb
    return res


# --------------------------------------------------------------------------
# 13 countries (single policy, two modes, per country)
# --------------------------------------------------------------------------
def analyze_countries(d):
    A, U = mode_labels(d)
    policy = next(iter(d["by_policy_mode"]))
    bsp, bspm, bpm, bscm = (d["by_storage_policy"], d["by_storage_policy_mode"],
                             d["by_policy_mode"], d["by_storage_country_mode"])
    res = {"mode_labels": {"auth": A, "unauth": U}, "policy": policy}

    # --- pooled (all countries)
    means = {a: bsp[a][policy]["risk_i"]["mean"] for a in APIS}
    spread, hi, lo = api_spread(means)
    pa = {a: risk(bspm[a][policy].get(A)) for a in APIS}
    pu = {a: risk(bspm[a][policy].get(U)) for a in APIS}
    effects, worst = within_api_mode_effects(pa, pu)
    gA, gU = bpm[policy][A]["risk_i"], bpm[policy][U]["risk_i"]
    res["pooled"] = {
        "api_mean_modes_pooled": {a: r4(v) for a, v in means.items()},
        "api_median_modes_pooled": {a: r4(bsp[a][policy]["risk_i"]["median"]) for a in APIS},
        "api_spread_of_means": r4(spread), "api_spread_between": [hi, lo],
        "aggregate": {
            "auth": {k: r4(gA[k]) for k in ("n", "q1", "median", "q3", "iqr", "mean")},
            "unauth": {k: r4(gU[k]) for k in ("n", "q1", "median", "q3", "iqr", "mean")},
            "q1_gap": r4(gU["q1"] - gA["q1"]), "median_gap": r4(gU["median"] - gA["median"]),
            "q3_gap": r4(gU["q3"] - gA["q3"]), "mean_gap": r4(gU["mean"] - gA["mean"]),
        },
        "within_api": effects,
        "max_within_api_mean_gap": effects[worst]["abs_mean_gap"],
        "max_within_api_mean_gap_api": worst,
        "composition": composition(pa, pu),
    }

    # --- per country
    countries = sorted(bscm["cookie"])
    per_country, cells = {}, []
    for c in countries:
        cA = {a: risk(bscm[a].get(c, {}).get(A)) for a in APIS}
        cU = {a: risk(bscm[a].get(c, {}).get(U)) for a in APIS}
        eff, w = within_api_mode_effects(cA, cU)
        pooled = {}
        for a in APIS:
            m, _ = pooled_mean([cA[a], cU[a]])
            if m is not None:
                pooled[a] = m
        sp, h, l = api_spread(pooled)
        comp = composition(cA, cU)
        modes = {}
        for lab, cm in ((A, cA), (U, cU)):
            mean, n = pooled_mean(list(cm.values()))
            modes[lab] = {
                "n": n, "mean": r4(mean),
                "api_share": {a: r4(cm[a]["n"] / n) if cm[a] else 0.0 for a in APIS},
            }
            cells.append((c, lab, cm, mean, (cm["IndexedDB"]["n"] / n) if cm["IndexedDB"] else 0.0))
        per_country[c] = {
            "modes": modes,
            "api_mean_modes_pooled": {a: r4(v) for a, v in pooled.items()},
            "api_spread_of_means": r4(sp), "api_spread_between": [h, l],
            "within_api": eff,
            "max_within_api_mean_gap": eff[w]["abs_mean_gap"], "max_within_api_mean_gap_api": w,
            "F6_mode_effect_below_api_spread": eff[w]["abs_mean_gap"] < sp,
            "ratio_max_gap_over_spread": r4(eff[w]["abs_mean_gap"] / sp),
            "composition": comp,
        }
    res["per_country"] = per_country

    gaps = [v["max_within_api_mean_gap"] for v in per_country.values()]
    spreads = [v["api_spread_of_means"] for v in per_country.values()]
    tight = min(per_country, key=lambda k: per_country[k]["api_spread_of_means"] - per_country[k]["max_within_api_mean_gap"])
    worst_ratio = max(per_country, key=lambda k: per_country[k]["ratio_max_gap_over_spread"])
    res["F6_across_countries"] = {
        "holds_in": f"{sum(v['F6_mode_effect_below_api_spread'] for v in per_country.values())}/{len(per_country)}",
        "max_within_api_mode_gap_range": [min(gaps), max(gaps)],
        "max_within_api_mode_gap_argmin": min(per_country, key=lambda k: per_country[k]["max_within_api_mean_gap"]),
        "max_within_api_mode_gap_argmax": max(per_country, key=lambda k: per_country[k]["max_within_api_mean_gap"]),
        "api_spread_range": [min(spreads), max(spreads)],
        "api_spread_argmin": min(per_country, key=lambda k: per_country[k]["api_spread_of_means"]),
        "api_spread_argmax": max(per_country, key=lambda k: per_country[k]["api_spread_of_means"]),
        "tightest_country_absolute": tight,
        "worst_ratio_country": worst_ratio,
        "worst_ratio_gap_over_spread": per_country[worst_ratio]["ratio_max_gap_over_spread"],
        "composition_share_by_country": {c: v["composition"]["share_explained_by_composition"] for c, v in per_country.items()},
        "composition_share_note": f"per-country shares are reported only when |gap| >= {MIN_GAP}; cite the pooled share, and S1 for the per-country test",
    }

    # --- replication of RQ4 properties over the 26 country x mode cells
    def check(name, fn):
        ok, exc = 0, []
        for c, lab, cm, _, _ in cells:
            r = fn(cm)
            if r is None:
                exc.append({"cell": f"{c} ({lab})", "detail": "API missing"})
            elif r[0]:
                ok += 1
            else:
                exc.append({"cell": f"{c} ({lab})", "detail": r[1]})
        return {"property": name, "holds": f"{ok}/{len(cells)}", "exceptions": exc}

    def cmp(a, b, key):
        def f(cm):
            if not (cm[a] and cm[b]):
                return None
            x, y = cm[a][key], cm[b][key]
            return x > y + EPS, f"{SHORT[a]} {x:.3f} vs {SHORT[b]} {y:.3f}" + (" (tie)" if abs(x - y) <= EPS else "")
        return f

    def widest_cookie(cm):
        if not cm["cookie"]:
            return None
        others = {a: cm[a]["iqr"] for a in APIS if a != "cookie" and cm[a]}
        top = max(others, key=others.get)
        return cm["cookie"]["iqr"] > others[top] + EPS, f"cookie {cm['cookie']['iqr']:.3f} vs {SHORT[top]} {others[top]:.3f}"

    def idb_iqr0(cm):
        if not cm["IndexedDB"]:
            return None
        s = cm["IndexedDB"]
        return s["iqr"] <= EPS, f"IQR {s['iqr']:.3f} (Q1 {s['q1']:.3f}, median {s['median']:.3f})"

    def idb_median_common(cm):
        if not cm["IndexedDB"]:
            return None
        return abs(cm["IndexedDB"]["median"] - 0.724) <= 5e-4, f"median {cm['IndexedDB']['median']:.3f}"

    def ls_ss_both(cm):
        if not (cm["localStorage"] and cm["sessionStorage"]):
            return None
        a, b = cm["localStorage"], cm["sessionStorage"]
        ok = a["median"] > b["median"] + EPS and a["mean"] > b["mean"] + EPS
        return ok, f"median {a['median']:.3f} vs {b['median']:.3f}; mean {a['mean']:.3f} vs {b['mean']:.3f}"

    res["replication_26_cells"] = [
        check("median IDB > median cookie (F5)", cmp("IndexedDB", "cookie", "median")),
        check("mean IDB > mean cookie (F5)", cmp("IndexedDB", "cookie", "mean")),
        check("median cookie > median LS (F1/F3)", cmp("cookie", "localStorage", "median")),
        check("median and mean LS > SS (F3/F4)", ls_ss_both),
        check("cookie has the widest IQR (F1)", widest_cookie),
        check("IQR IDB = 0 (F5)", idb_iqr0),
        check("median IDB = 0.724", idb_median_common),
    ]
    idb_q1 = sorted(((f"{c} ({lab})", cm["IndexedDB"]["q1"]) for c, lab, cm, _, _ in cells if cm["IndexedDB"]),
                    key=lambda t: t[1])
    res["idb_q1_lowest_cells"] = [{"cell": k, "q1": r4(v)} for k, v in idb_q1[:6]]

    # --- country mean vs IDB share
    xs = [s for *_, s in cells]
    ys = [m for *_, m, _ in cells]
    res["corr_idb_share_vs_cell_mean"] = {
        "pearson_r": r4(pearson(xs, ys)), "n_cells": len(cells),
        "cells": [{"cell": f"{c} ({lab})", "idb_share": r4(s), "mean": r4(m)} for c, lab, _, m, s in cells],
    }
    return res


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--main", type=Path, help="risk_statistics.json of the main (RQ4) dataset")
    ap.add_argument("--countries", type=Path, help="risk_statistics.json of the 13-country dataset")
    ap.add_argument("--out", type=Path, default=Path("derived_gaps.json"))
    ap.add_argument("--min-gap", type=float, default=MIN_GAP,
                    help="minimum |Auth-UnAuth mean gap| to report a composition share (default 0.01)")
    args = ap.parse_args()
    globals()["MIN_GAP"] = args.min_gap
    if not (args.main or args.countries):
        ap.error("give --main and/or --countries")

    out = {"generated_by": "derived_gaps.py", "inputs": {}}
    if args.main:
        out["inputs"]["main"] = str(args.main)
        out["rq4_main"] = analyze_main(json.loads(args.main.read_text()))
    if args.countries:
        out["inputs"]["countries"] = str(args.countries)
        out["countries13"] = analyze_countries(json.loads(args.countries.read_text()))
    args.out.write_text(json.dumps(out, indent=2))

    # ---- short console summary
    if "rq4_main" in out:
        m = out["rq4_main"]; ref = m["reference_policy"]; s = m["session_mode"][ref]
        print(f"[RQ4] policy {ref}: API spread {m['per_policy'][ref]['api_spread_of_means']}, "
              f"max within-API mode gap {s['max_within_api_mean_gap']} ({s['max_within_api_mean_gap_api']}), "
              f"composition {s['composition']['gap_unauth_minus_auth']} -> {s['composition']['residual_gap']} "
              f"({s['composition']['share_explained_by_composition']})")
        for k, v in m["consent_effect"].items():
            o = v["_overall"]
            print(f"[RQ4] {k}: items {o['count_change_pct']}%, max |rel mean change| {o['max_abs_rel_mean_change_pct']}%")
    if "countries13" in out:
        c = out["countries13"]; p = c["pooled"]; f6 = c["F6_across_countries"]
        print(f"[13C] API spread {p['api_spread_of_means']}, max within-API mode gap {p['max_within_api_mean_gap']}, "
              f"composition {p['composition']['gap_unauth_minus_auth']} -> {p['composition']['residual_gap']} "
              f"({p['composition']['share_explained_by_composition']})")
        print(f"[13C] F6 {f6['holds_in']}: gaps {f6['max_within_api_mode_gap_range']}, spreads {f6['api_spread_range']}, "
              f"worst ratio {f6['worst_ratio_country']} {f6['worst_ratio_gap_over_spread']}")
        for r in c["replication_26_cells"]:
            print(f"[13C] {r['property']}: {r['holds']}  " + "; ".join(e["cell"] for e in r["exceptions"]))
        print(f"[13C] corr(IDB share, cell mean) r = {c['corr_idb_share_vs_cell_mean']['pearson_r']}")
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()