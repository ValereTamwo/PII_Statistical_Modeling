"""
Ridge Regression in Logit Space — Beta Calibration for Pi exposure model.

Model : eta = b0 + b_ho*ho + b_se*se + b_ss*ss + b_tp*tp + b_pe*pe + b_ho_pe*(ho*pe)
        Pi  = sigmoid(eta)

Method : beta = (X'X + lambda*I)^-1 X' logit(p*)
         lambda = 0.15 — smallest value satisfying all ordinal sanity checks.
"""

import json
import numpy as np
from pathlib import Path


BETA_KEYS = ["intercept", "ho", "se", "ss", "tp", "pe", "ho_pe"]

LAM = 0.15


def make_row(ho, se, ss, tp, pe):
    return np.array([1, ho, se, ss, tp, pe, ho * pe], dtype=float)


X = np.array([
    make_row(0, 0, 0, 0, 0),   # S01 — no flags
    make_row(1, 0, 0, 0, 0),   # S02 — ho only
    make_row(1, 1, 0, 0, 1),   # S03 — ho + se + pe  (localStorage)
    make_row(0, 0, 1, 1, 1),   # S04 — ss + tp + pe  (3rd-party SameSite=None pers.)
    make_row(1, 1, 0, 0, 0),   # S05 — ho + se
    make_row(0, 1, 0, 0, 1),   # S06 — se + pe
    make_row(0, 0, 0, 1, 1),   # S07 — tp + pe
    make_row(1, 1, 1, 1, 1),   # S08 — all flags (worst case)
    make_row(1, 0, 0, 0, 1),   # S09 — ho + pe  (evercookie)
    make_row(0, 1, 0, 0, 0),   # S10 — se only
    make_row(0, 0, 0, 0, 1),   # S11 — pe only
    make_row(0, 0, 1, 1, 0),   # S12 — ss + tp
    make_row(0, 0, 1, 1, 1),   # S13 — ss + tp + pe
], dtype=float)

P_TARGET = np.array([
    0.02,   # S01
    0.55,   # S02
    0.88,   # S03
    0.72,   # S04
    0.75,   # S05
    0.65,   # S06
    0.45,   # S07
    0.97,   # S08
    0.82,   # S09
    0.30,   # S10
    0.08,   # S11
    0.68,   # S12
    0.75,   # S13
])

SANITY_CHECKS = [
    ("beta_ho > beta_se",  lambda b: b["ho"]        > b["se"]),
    ("beta_se > beta_pe",  lambda b: b["se"]        > b["pe"]),
    ("beta_tp >= beta_ss", lambda b: b["tp"]        >= b["ss"]),
    ("beta_ho_pe > 0",     lambda b: b["ho_pe"]     > 0),
    ("beta_intercept < 0", lambda b: b["intercept"] < 0),
]


def sigmoid(eta):
    return 1.0 / (1.0 + np.exp(-np.clip(eta, -500, 500)))


def calibrate(p_tgt=P_TARGET, lam=LAM):
    logit_y = np.log(p_tgt / (1 - p_tgt))
    return np.linalg.inv(X.T @ X + lam * np.eye(X.shape[1])) @ X.T @ logit_y


def predict(betas):
    return sigmoid(X @ betas)


def compute_exposure(xi: dict, betas: np.ndarray) -> float:
    ho = int(xi.get("js_accessible",  0))
    se = int(xi.get("network_exposed", 0))
    ss = int(xi.get("cross_site",      0))
    tp = int(xi.get("thirdparty",      0))
    pe = int(xi.get("persistent",      0))
    x  = make_row(ho, se, ss, tp, pe)
    return round(float(sigmoid(float(np.dot(betas, x)))), 4)


def stability_analysis(lam=LAM, n=21, delta=0.10):
    runs = [calibrate(np.clip(P_TARGET + p, 0.01, 0.99), lam)
            for p in np.linspace(-delta, delta, n)]
    stds = np.array(runs).std(axis=0)
    return {k: round(float(s), 5) for k, s in zip(BETA_KEYS, stds)}


def lambda_selection(grid=None):
    """
    Selects the minimum lambda satisfying all ordinal validity checks.
    For lambda < 0.15: beta_ho_pe < 0  (violates domain-specific monotonicity).
    For lambda > 0.30: beta_ho_pe -> 0 (interaction effects are over-regularized).
    Selection follows the parsimony principle (min viable lambda).
    """
    if grid is None:
        grid = [0.00, 0.01, 0.05, 0.10, 0.15, 0.20, 0.30, 0.50, 1.00]

    rows = []
    for lam in grid:
        b_arr = calibrate(lam=lam)
        b     = dict(zip(BETA_KEYS, b_arr))
        pred  = sigmoid(X @ b_arr)
        rmse  = float(np.sqrt(np.mean((P_TARGET - pred) ** 2)))
        ok    = all(fn(b) for _, fn in SANITY_CHECKS)
        mstd  = float(np.array([
            calibrate(np.clip(P_TARGET + p, 0.01, 0.99), lam)
            for p in np.linspace(-0.10, 0.10, 21)
        ]).std(axis=0).mean())
        rows.append({"lambda": lam, "rmse": round(rmse, 5),
                     "mean_std": round(mstd, 5), "sanity_ok": ok})

    viable   = [r for r in rows if r["sanity_ok"]]
    selected = min(viable, key=lambda r: r["lambda"]) if viable else None
    return rows, selected


def main():
    # Lambda selection
    lam_rows, lam_selected = lambda_selection()

    print("=" * 55)
    print("  BETA CALIBRATION")
    print("=" * 55)

    print(f"\n  Lambda selection grid :")
    print(f"  {'lam':>6}  {'RMSE':>7}  {'mean_std':>9}  {'sanity':>7}")
    print("  " + "-" * 36)
    for r in lam_rows:
        marker = "  <-- selected" if r["lambda"] == lam_selected["lambda"] else ""
        print(f"  {r['lambda']:>6.2f}  {r['rmse']:>7.4f}  {r['mean_std']:>9.5f}"
              f"  {'OK' if r['sanity_ok'] else 'FAIL':>7}{marker}")

    print(f"\n  Selected lambda : {lam_selected['lambda']}"
          f"  (min viable — parsimony principle)")

    # Calibration
    betas  = calibrate()
    b_dict = dict(zip(BETA_KEYS, betas))
    pred   = predict(betas)
    rmse   = float(np.sqrt(np.mean((P_TARGET - pred) ** 2)))

    print(f"\n  {'param':<16} {'value':>8}")
    print("  " + "-" * 26)
    for k, v in b_dict.items():
        print(f"  beta_{k:<11} {v:>+8.4f}")

    print(f"\n  RMSE : {rmse:.4f}")

    print(f"\n  Fit per scenario :")
    print(f"  {'S':>3}  {'p*':>5}  {'p^':>6}  {'err':>7}")
    print("  " + "-" * 28)
    for i, (pt, pp) in enumerate(zip(P_TARGET, pred), 1):
        flag = "" if abs(pp - pt) <= 0.08 else "  !!"
        print(f"  S{i:02d}  {pt:>5.2f}  {pp:>6.3f}  {pp-pt:>+7.3f}{flag}")

    print(f"\n  Sanity checks :")
    for desc, fn in SANITY_CHECKS:
        print(f"    {'OK' if fn(b_dict) else 'FAIL'}  {desc}")

    print(f"\n  Stability std (p* perturbed +-0.10) :")
    stab = stability_analysis()
    for k, s in stab.items():
        print(f"    beta_{k:<11} std={s:.5f}")

    # Export
    out_dir  = Path(__file__).resolve().parents[1] / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "calibrated_betas.json"

    with open(out_path, "w") as f:
        json.dump({
            "method"          : "Ridge_LogitSpace",
            "lambda"          : LAM,
            "lambda_selection": {
                "criterion" : "minimum lambda satisfying all sanity checks",
                "grid"      : lam_rows,
                "selected"  : lam_selected,
            },
            "rmse"            : round(rmse, 5),
            "betas"           : {k: round(float(v), 4) for k, v in b_dict.items()},
            "stability"       : stab,
            "sanity"          : {d: bool(fn(b_dict)) for d, fn in SANITY_CHECKS},
        }, f, indent=2)

    print(f"\n  Saved : {out_path}")
    print("=" * 55)
    return b_dict


if __name__ == "__main__":
    main()