import json
import numpy as np
from pathlib import Path
from collections import defaultdict


USERS    = ["FR_0417", "FR_0446", "FR_0458"]
MODES    = ["Auth", "UnAuth"]
POLICIES = ["ALL", "PARTIAL", "NONE"]
STORAGES = ["cookie", "localStorage", "sessionStorage", "IndexedDB"]


class RiskAggregator:
    def __init__(self, data_root):
        self.data_root = Path(data_root)
        self.all_items = []

    def load_data(self):
        for mode in MODES:
            for user in USERS:
                for policy in POLICIES:
                    file_path = (
                        self.data_root / "user" / mode / user / policy
                        / "_vector_data" / "vectorized_items_risk_score.json"
                    )
                    if file_path.exists():
                        with open(file_path, "r", encoding="utf-8") as f:
                            items = json.load(f)
                            for it in items:
                                it['mode']   = mode
                                it['user']   = user
                                it['policy'] = policy
                            self.all_items.extend(items)

        print(f"  -> {len(self.all_items)} items loaded.")

    @staticmethod
    def _raw_sum(items_list: list) -> float:
        return sum(it['risk_i'] for it in items_list)

    @staticmethod
    def _norm(raw: float, ceiling: float) -> float:
        if ceiling == 0:
            return 0.0
        return round(min(raw / ceiling, 1.0), 4)

    @staticmethod
    def _mean_risk(items_list: list) -> float:
        if not items_list:
            return 0.0
        return round(sum(it['risk_i'] for it in items_list) / len(items_list), 4)

    def aggregate(self) -> dict:
        session_sums = defaultdict(float)
        for it in self.all_items:
            sid = f"{it['mode']}|{it['user']}|{it['policy']}"
            session_sums[sid] += it['risk_i']

        max_session = max(session_sums.values()) if session_sums else 1.0
        print(f"  -> Max session risk sum (info only): {max_session:.4f}")

        mode_raw = {
            m: self._raw_sum([it for it in self.all_items if it['mode'] == m])
            for m in MODES
        }
        policy_raw = {
            p: self._raw_sum([it for it in self.all_items if it['policy'] == p])
            for p in POLICIES
        }
        storage_raw = {
            s: self._raw_sum([
                it for it in self.all_items
                if it['storage_type'].lower() == s.lower()
            ])
            for s in STORAGES
        }

        ceil_mode    = max(mode_raw.values())    if mode_raw    else 1.0
        ceil_policy  = max(policy_raw.values())  if policy_raw  else 1.0
        ceil_storage = max(storage_raw.values()) if storage_raw else 1.0

        mode_policy_raw = {
            m: {
                p: self._raw_sum([
                    it for it in self.all_items
                    if it['mode'] == m and it['policy'] == p
                ])
                for p in POLICIES
            }
            for m in MODES
        }
        ceil_mode_policy = max(
            v for mp in mode_policy_raw.values() for v in mp.values()
        ) or 1.0

        policy_storage_raw = {
            p: {
                s: self._raw_sum([
                    it for it in self.all_items
                    if it['policy'] == p and it['storage_type'].lower() == s.lower()
                ])
                for s in STORAGES
            }
            for p in POLICIES
        }
        ceil_policy_storage = max(
            v for ps in policy_storage_raw.values() for v in ps.values()
        ) or 1.0

        mode_mean = {
            m: self._mean_risk([it for it in self.all_items if it['mode'] == m])
            for m in MODES
        }
        policy_mean = {
            p: self._mean_risk([it for it in self.all_items if it['policy'] == p])
            for p in POLICIES
        }
        storage_mean = {
            s: self._mean_risk([
                it for it in self.all_items
                if it['storage_type'].lower() == s.lower()
            ])
            for s in STORAGES
        }
        mode_policy_mean = {
            m: {
                p: self._mean_risk([
                    it for it in self.all_items
                    if it['mode'] == m and it['policy'] == p
                ])
                for p in POLICIES
            }
            for m in MODES
        }
        policy_storage_mean = {
            p: {
                s: self._mean_risk([
                    it for it in self.all_items
                    if it['policy'] == p and it['storage_type'].lower() == s.lower()
                ])
                for s in STORAGES
            }
            for p in POLICIES
        }

        stats = {
            "ceilings": {
                "session_max"    : round(max_session, 4),
                "mode"           : round(ceil_mode, 4),
                "policy"         : round(ceil_policy, 4),
                "storage"        : round(ceil_storage, 4),
                "mode_policy"    : round(ceil_mode_policy, 4),
                "policy_storage" : round(ceil_policy_storage, 4),
            },
            "by_mode"                : {},
            "by_policy"              : {},
            "by_storage"             : {},
            "by_mode_policy"         : {m: {} for m in MODES},
            "by_policy_storage"      : {p: {} for p in POLICIES},
            "by_mode_mean"           : {},
            "by_policy_mean"         : {},
            "by_storage_mean"        : {},
            "by_mode_policy_mean"    : {m: {} for m in MODES},
            "by_policy_storage_mean" : {p: {} for p in POLICIES},
        }

        for m in MODES:
            stats["by_mode"][m] = self._norm(mode_raw[m], ceil_mode)

        for p in POLICIES:
            stats["by_policy"][p] = self._norm(policy_raw[p], ceil_policy)

        for s in STORAGES:
            stats["by_storage"][s] = self._norm(storage_raw[s], ceil_storage)

        for m in MODES:
            for p in POLICIES:
                stats["by_mode_policy"][m][p] = self._norm(
                    mode_policy_raw[m][p], ceil_mode_policy
                )

        for p in POLICIES:
            for s in STORAGES:
                stats["by_policy_storage"][p][s] = self._norm(
                    policy_storage_raw[p][s], ceil_policy_storage
                )

        for m in MODES:
            stats["by_mode_mean"][m] = mode_mean[m]

        for p in POLICIES:
            stats["by_policy_mean"][p] = policy_mean[p]

        for s in STORAGES:
            stats["by_storage_mean"][s] = storage_mean[s]

        for m in MODES:
            for p in POLICIES:
                stats["by_mode_policy_mean"][m][p] = mode_policy_mean[m][p]

        for p in POLICIES:
            for s in STORAGES:
                stats["by_policy_storage_mean"][p][s] = policy_storage_mean[p][s]

        print(f"  -> Ceilings used:")
        for k, v in stats["ceilings"].items():
            print(f"       {k:<20} = {v:.4f}")

        return stats

    def save_json(self, stats: dict):
        output_dir = self.data_root / "reports"
        output_dir.mkdir(exist_ok=True)
        path = output_dir / "aggregated_risk_data.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        print(f"  ✓ Aggregated data saved: {path}")


def main():
    base_dir  = Path(__file__).resolve().parents[2]
    data_root = base_dir / "data"

    aggregator = RiskAggregator(data_root)

    print("=" * 65)
    print("  RISK AGGREGATOR ENGINE")
    print("  Normalization: min-max per view (sum + mean per item)")
    print("=" * 65)

    aggregator.load_data()
    results = aggregator.aggregate()
    aggregator.save_json(results)

    print("=" * 65)
    print("  Done.")
    print("=" * 65)


if __name__ == "__main__":
    main()