"""
RISK STATISTICS (Aggregation)
Computes item-level descriptive statistics (quartiles, dispersion, central tendency)
aggregated by storage, policy, and session mode.
"""

import json
import numpy as np
from pathlib import Path
from collections import defaultdict

USERS    = ["FR_0417", "FR_0446", "FR_0458"]
MODES    = ["Auth", "UnAuth"]
POLICIES = ["ALL", "PARTIAL", "NONE"]
STORAGES = ["cookie", "localStorage", "sessionStorage", "IndexedDB"]
METRICS  = ["pi_exposure", "ii_impact", "risk_i"]


def describe(values: list) -> dict:
    """Computes a standard set of descriptive statistics for a distribution."""
    if not values:
        return {"n": 0, "mean": None, "std": None,
                "min": None, "q1": None, "median": None,
                "q3": None, "max": None, "iqr": None}
    a  = np.array(values, dtype=float)
    q1, med, q3 = np.percentile(a, [25, 50, 75])
    return {
        "n"     : int(len(a)),
        "mean"  : round(float(a.mean()), 4),
        "std"   : round(float(a.std()),  4),
        "min"   : round(float(a.min()),  4),
        "q1"    : round(float(q1),       4),
        "median": round(float(med),      4),
        "q3"    : round(float(q3),       4),
        "max"   : round(float(a.max()),  4),
        "iqr"   : round(float(q3 - q1),  4),
    }


def load_items(data_root: Path, mode: str, policy: str) -> list:
    all_items = []
    user_dir  = data_root / "user" / mode
    if not user_dir.exists():
        return all_items
    for user_folder in sorted(user_dir.iterdir()):
        if not user_folder.is_dir():
            continue
        path = (user_folder / policy / "_vector_data"
                / "vectorized_items_risk_score.json")
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                all_items.extend(json.load(f))
    return all_items


def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    print("=" * 55)
    print("  RISK STATISTICS ENGINE")
    print("  Q1 / Median / Q3 / IQR / min / max / mean / std")
    print("=" * 55)

    stats = {
        "by_storage_policy_mode": {},   # Primary granularity
        "by_policy_mode":         {},   # Cross-storage aggregation
        "by_storage_policy":      {},   # Mode-agnostic aggregation
    }

    # ── 1. by_storage × policy × mode ───────────────────────
    for st in STORAGES:
        stats["by_storage_policy_mode"][st] = {}
        stats["by_storage_policy"][st]      = {}

        for policy in POLICIES:
            stats["by_storage_policy_mode"][st][policy] = {}
            merged = defaultdict(list)   # Accumulator for mode fusion

            for mode in MODES:
                items    = load_items(data_root, mode, policy)
                st_items = [it for it in items
                            if it.get("storage_type","").lower() == st.lower()]

                mode_stats = {}
                for metric in METRICS:
                    vals = [it.get(metric, 0.) for it in st_items
                            if it.get(metric) is not None]
                    mode_stats[metric] = describe(vals)
                    merged[metric].extend(vals)

                stats["by_storage_policy_mode"][st][policy][mode] = mode_stats
                print(f"  {st:<18} {policy:<8} {mode:<8} "
                      f"n={mode_stats['risk_i']['n']:>6}  "
                      f"med={mode_stats['risk_i']['median']}  "
                      f"IQR={mode_stats['risk_i']['iqr']}")

            # Mode fusion (Auth + UnAuth)
            merged_stats = {m: describe(list(v)) for m, v in merged.items()}
            stats["by_storage_policy"][st][policy] = merged_stats

    # ── 2. by_policy × mode (tous storages) ─────────────────
    for policy in POLICIES:
        stats["by_policy_mode"][policy] = {}
        for mode in MODES:
            items = load_items(data_root, mode, policy)
            mode_stats = {}
            for metric in METRICS:
                vals = [it.get(metric, 0.) for it in items
                        if it.get(metric) is not None]
                mode_stats[metric] = describe(vals)
            stats["by_policy_mode"][policy][mode] = mode_stats

    # ── Export ───────────────────────────────────────────────
    out_dir  =  Path(__file__).resolve().parent / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "risk_statistics.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"\n  Saved : {out_path}")
    print("=" * 55)


if __name__ == "__main__":
    main()