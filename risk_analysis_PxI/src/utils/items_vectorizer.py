"""
STORAGE ITEM VECTORIZER
Transforms raw storage artifacts (cookies, storage, IndexedDB) into structured feature vectors (xi).
Features include technical flags, entropy estimations, and modification frequencies.
"""
import json
import math
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "analysis"))
from analyze_by_category import is_third_party, calculate_lifetime_category



USERS         = ["FR_0417", "FR_0446", "FR_0458"]
AUTH_STATUSES = ["Auth", "UnAuth"]
POLICIES      = ["ALL", "PARTIAL", "NONE"]

COOKIE_LIFECYCLES  = ["added", "modified", "removed"]
STORAGE_LIFECYCLES = ["added", "modified", "removed"]
IDB_LIFECYCLE      = "static"

THIRD_PARTY_CATEGORIES = {
    "ID_SOLUTIONS_AND_EXCHANGES",
    "IDENTITY_TRACKING",
    "SERVER_SIDE_TRACKING",
    "UX_AND_PERFORMANCE_ANALYTICS",
}



def _shannon_entropy_normalized(value) -> float:
    if value is None:
        return 0.0
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return 0.0
    if len(value) < 4:
        return 0.0

    freq = defaultdict(int)
    for c in value:
        freq[c] += 1

    total       = len(value)
    entropy     = -sum((count / total) * math.log2(count / total)
                       for count in freq.values())
    alphabet    = len(freq)
    max_entropy = math.log2(alphabet) if alphabet > 1 else 1.0

    return round(entropy / max_entropy, 4) if max_entropy > 0 else 0.0


def _is_json_value(value) -> int:
    if value is None:
        return 0
    if isinstance(value, (dict, list)):
        return 1
    if not isinstance(value, str) or len(value) < 2:
        return 0
    try:
        parsed = json.loads(value)
        return 1 if isinstance(parsed, (dict, list)) else 0
    except Exception:
        return 0



def _is_samesite_none(samesite_value) -> bool:
    if samesite_value is None:
        return True
    s = str(samesite_value).strip().lower()
    return s in ("none", "")

def _parse_timestamp(ts) -> Optional[float]:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except Exception:
        try:
            return float(ts)
        except Exception:
            return None

def _is_persistent_cookie(expires: float, timestamp=None) -> int:
    SIX_MONTHS_SECONDS = 180 * 86400
    if expires is None or expires <= 0:
        return 0
    reference = _parse_timestamp(timestamp) if timestamp else datetime.now().timestamp()
    lifetime  = expires - reference
    if lifetime <= 0:
        return 0
    return 1 if lifetime >= SIX_MONTHS_SECONDS else 0



def _extract_domain_from_source_file(source_file: str) -> Optional[str]:
    if not source_file:
        return None
    name  = source_file.replace(".indexeddb.leveldb.json", "").replace(".json", "")
    parts = name.split("_", 1)
    if len(parts) == 2:
        domain_part = parts[1].rsplit("_", 1)[0]
        return domain_part
    return None


def _load_json(path: Path) -> List[Dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f"  [WARN] Cannot load {path}: {e}")
        return []

def _iter_category_files(directory: Path):
    if not directory.exists():
        return
    for p in sorted(directory.glob("*.json")):
        yield p.stem, p



def _item_identity(item: Dict) -> Optional[tuple]:
    storage = item.get("storage_type", "")
    if storage == "cookie":
        name   = item.get("name") or item.get("cookie_key") or item.get("key")
        domain = item.get("domain", "")
        if not name:
            return None
        return ("cookie", name, domain)
    else:
        key = item.get("key") or item.get("name")
        url = item.get("initial_url", "")
        if not key:
            return None
        return (storage, key, url)

def track_modification_frequency(items_by_lifecycle: Dict[str, List[Dict]]) -> Dict[tuple, float]:
    """
    Computes the normalized modification frequency for each item.
    Computed as: |modified_tasks| / |observed_tasks|
    """
    tasks_modified = defaultdict(set)
    tasks_observed = defaultdict(set)

    for lifecycle, items in items_by_lifecycle.items():
        if lifecycle not in ("added", "modified"):
            continue
        for item in items:
            identity = _item_identity(item)
            task     = item.get("task_id")
            if not identity or task is None:
                continue
            tasks_observed[identity].add(task)
            if lifecycle == "modified":
                tasks_modified[identity].add(task)

    freq_map = {}
    for identity, observed in tasks_observed.items():
        nb_observed = len(observed)
        nb_modified = len(tasks_modified.get(identity, set()))
        freq_map[identity] = round(nb_modified / nb_observed, 4) if nb_observed > 0 else 0.0

    return freq_map



def detect_cross_storage_tracking(all_items: List[Dict]) -> set:
    value_map = defaultdict(set)
    for item in all_items:
        value   = item.get("value")
        storage = item.get("storage_type")
        if not value or not isinstance(value, str) or len(value) < 8:
            continue
        value_map[value].add(storage)
    return {value for value, storages in value_map.items() if len(storages) > 1}



def vectorize_cookie(item: Dict, category: str, lifecycle: str, idx: int,
                     modfreq: Dict, cross_values: set) -> Dict:

    httponly_flag = bool(item.get("httpOnly", False)) if lifecycle == "added" or lifecycle == "removed" else bool(item.get("httpOnly_to", False))
    samesite_val  = item.get("sameSite") if lifecycle == "added" or lifecycle == "removed" else item.get("sameSite_to")
    expires       = item.get("expires", -1) if lifecycle == "added" or lifecycle == "removed" else item.get("expires_to", -1)
    timestamp     = item.get("timestamp")
    domain        = item.get("domain", "")
    initial_url   = item.get("initial_url", "")
    key           = item.get("key") or item.get("cookie_key") or item.get("name")
    value         = item.get("value", "") if lifecycle == "added" or lifecycle == "removed" else item.get("value_to", "")
    secure_flag   = bool(item.get("secure", False)) if lifecycle == "added" or lifecycle == "removed" else bool(item.get("secure_to", False))

    xi = {
        "js_accessible"         : 0 if httponly_flag else 1,
        "cross_site"            : 1 if _is_samesite_none(samesite_val) else 0,
        "network_exposed"       : 0 if secure_flag else 1,
        "thirdparty"            : 1 if is_third_party(domain, initial_url) else 0,
        "persistent"            : _is_persistent_cookie(expires, timestamp),
        "is_json_value"         : _is_json_value(value),
        "entropy"               : _shannon_entropy_normalized(value),
        "modification_frequency": modfreq.get(_item_identity(item), 0.0),
        "cross_storage_tracking": 1 if value in cross_values else 0,
    }

    return {
        "task_id"     : item.get("task_id"),
        "name"        : key,
        "value"       : value,
        "storage_type": "cookie",
        "lifecycle"   : lifecycle,
        "category"    : category,
        "domain"      : domain,
        "initial_url" : initial_url,
        "xi"          : xi,
    }


def vectorize_localstorage(item: Dict, category: str, lifecycle: str, idx: int,
                            modfreq: Dict, cross_values: set) -> Dict:

    key   = item.get("key") or item.get("name")
    value = item.get("value", "") if lifecycle == "added" or lifecycle == "removed" else item.get("value_to", "")
    tp = 1 if category in THIRD_PARTY_CATEGORIES else 0

    xi = {
        "js_accessible"         : 1,
        "network_exposed"       : 0,
        "cross_site"            : 0,
        "thirdparty"            : tp,
        "persistent"            : 1,
        "is_json_value"         : _is_json_value(value),
        "entropy"               : _shannon_entropy_normalized(value),
        "modification_frequency": modfreq.get(_item_identity(item), 0.0),
        "cross_storage_tracking": 1 if value in cross_values else 0,
    }

    return {
        "task_id"     : item.get("task_id"),
        "name"        : key,
        "value"       : value,
        "storage_type": "localStorage",
        "lifecycle"   : lifecycle,
        "category"    : category,
        "initial_url" : item.get("initial_url", ""),
        "xi"          : xi,
    }


def vectorize_sessionstorage(item: Dict, category: str, lifecycle: str, idx: int,
                              modfreq: Dict, cross_values: set) -> Dict:

    key   = item.get("key") or item.get("name")
    value = item.get("value", "") if lifecycle == "added" or lifecycle == "removed" else item.get("value_to", "")
    tp = 1 if category in THIRD_PARTY_CATEGORIES else 0

    xi = {
        "js_accessible"         : 1,
        "network_exposed"       : 0,
        "cross_site"            : 0,
        "thirdparty"            : tp,
        "persistent"            : 0,
        "is_json_value"         : _is_json_value(value),
        "entropy"               : _shannon_entropy_normalized(value),
        "modification_frequency": modfreq.get(_item_identity(item), 0.0),
        "cross_storage_tracking": 1 if value in cross_values else 0,
    }

    return {
        "task_id"     : item.get("task_id"),
        "name"        : key,
        "value"       : value,
        "storage_type": "sessionStorage",
        "lifecycle"   : lifecycle,
        "category"    : category,
        "initial_url" : item.get("initial_url", ""),
        "xi"          : xi,
    }


def vectorize_indexeddb(item: Dict, category: str, idx: int,
                         cross_values: set, nb_entries: int = 1,
                         k: int = 1) -> Dict:

    key         = item.get("name") or item.get("key")
    value       = item.get("value", "") 
    source_file = item.get("source_file", "")
    domain      = _extract_domain_from_source_file(source_file) or ""
    tp          = 1 if category in THIRD_PARTY_CATEGORIES else 0
    store_density = round(nb_entries / (nb_entries + k), 4)

    xi = {
        "js_accessible"         : 1,
        "network_exposed"       : 0,
        "cross_site"            : 0,
        "thirdparty"            : tp,
        "persistent"            : 1,
        "is_json_value"         : _is_json_value(value),
        "entropy"               : _shannon_entropy_normalized(value),
        "modification_frequency": store_density,
        "cross_storage_tracking": 1 if value in cross_values else 0,
    }

    return {
        "task_id"     : item.get("task_id", "static"),
        "name"        : key,
        "value"       : value,
        "storage_type": "IndexedDB",
        "lifecycle"   : IDB_LIFECYCLE,
        "category"    : category,
        "initial_url" : domain,
        "xi"          : xi,
    }



def vectorize_user_policy(data_root: Path, auth_status: str, user: str,
                           policy: str, output_root: Path) -> int:

    base = data_root / "user" / auth_status / user / policy
    if not base.exists():
        print(f"  [SKIP] {auth_status}/{user}/{policy} – directory not found")
        return 0

    all_items: List[Dict] = []

    # --- Cookies ---
    cookie_items_by_lifecycle: Dict[str, List[Dict]] = {}
    for lifecycle in COOKIE_LIFECYCLES:
        cookie_dir = base / "cookies" / lifecycle
        cookie_items_by_lifecycle[lifecycle] = []
        for category, path in _iter_category_files(cookie_dir):
            items = _load_json(path)
            for item in items: item["storage_type"] = "cookie"
            cookie_items_by_lifecycle[lifecycle].extend(items)
            all_items.extend(items)

    modfreq_cookies = track_modification_frequency(cookie_items_by_lifecycle)

    # --- localStorage ---
    ls_items_by_lifecycle: Dict[str, List[Dict]] = {}
    for lifecycle in STORAGE_LIFECYCLES:
        ls_dir = base / "localstorage" / lifecycle
        ls_items_by_lifecycle[lifecycle] = []
        for category, path in _iter_category_files(ls_dir):
            items = _load_json(path)
            for item in items: item["storage_type"] = "localStorage"
            ls_items_by_lifecycle[lifecycle].extend(items)
            all_items.extend(items)

    modfreq_localstorage = track_modification_frequency(ls_items_by_lifecycle)

    # --- sessionStorage ---
    ss_items_by_lifecycle: Dict[str, List[Dict]] = {}
    for lifecycle in STORAGE_LIFECYCLES:
        ss_dir = base / "sessionstorage" / lifecycle
        ss_items_by_lifecycle[lifecycle] = []
        for category, path in _iter_category_files(ss_dir):
            items = _load_json(path)
            for item in items: item["storage_type"] = "sessionStorage"
            ss_items_by_lifecycle[lifecycle].extend(items)
            all_items.extend(items)

    modfreq_sessionstorage = track_modification_frequency(ss_items_by_lifecycle)

    # --- IndexedDB ---
    idb_dir = base / "indexeddb"
    idb_items_by_source: Dict[str, List[Dict]] = defaultdict(list)
    for category, path in _iter_category_files(idb_dir):
        items = _load_json(path)
        for item in items:
            item["storage_type"] = "IndexedDB"
            idb_items_by_source[item.get("source_file", "")].append(item)
        all_items.extend(items)

    idb_store_counts: Dict[str, int] = {src: len(its) for src, its in idb_items_by_source.items()}
    k_idb = max(sorted(idb_store_counts.values())[len(idb_store_counts)//4], 1) if idb_store_counts else 1

    cross_values = detect_cross_storage_tracking(all_items)

    # ----------------------------------------------------------
    # STEP 3: Vectorization with Category Fusion
    # ----------------------------------------------------------
    # Items are grouped by physical identity (TaskID, StorageType, Name, Value)
    physical_items = {}

    # 3.1 Cookie Vectorization
    for lifecycle in COOKIE_LIFECYCLES:
        for category, path in _iter_category_files(base / "cookies" / lifecycle):
            items = _load_json(path)
            for idx, item in enumerate(items):
                v = vectorize_cookie(item, category, lifecycle, idx, modfreq_cookies, cross_values)
                pid = (v['task_id'], v['storage_type'], v['name'], str(v['value']))
                if pid not in physical_items:
                    v['categories'] = [v.pop('category')]
                    physical_items[pid] = v
                else:
                    if v['category'] not in physical_items[pid]['categories']:
                        physical_items[pid]['categories'].append(v['category'])

    # 3.2 Traitement LocalStorage
    for lifecycle in STORAGE_LIFECYCLES:
        for category, path in _iter_category_files(base / "localstorage" / lifecycle):
            items = _load_json(path)
            for idx, item in enumerate(items):
                v = vectorize_localstorage(item, category, lifecycle, idx, modfreq_localstorage, cross_values)
                pid = (v['task_id'], v['storage_type'], v['name'], str(v['value']))
                if pid not in physical_items:
                    v['categories'] = [v.pop('category')]
                    physical_items[pid] = v
                else:
                    if v['category'] not in physical_items[pid]['categories']:
                        physical_items[pid]['categories'].append(v['category'])

    # 3.3 Traitement SessionStorage
    for lifecycle in STORAGE_LIFECYCLES:
        for category, path in _iter_category_files(base / "sessionstorage" / lifecycle):
            items = _load_json(path)
            for idx, item in enumerate(items):
                v = vectorize_sessionstorage(item, category, lifecycle, idx, modfreq_sessionstorage, cross_values)
                pid = (v['task_id'], v['storage_type'], v['name'], str(v['value']))
                if pid not in physical_items:
                    v['categories'] = [v.pop('category')]
                    physical_items[pid] = v
                else:
                    if v['category'] not in physical_items[pid]['categories']:
                        physical_items[pid]['categories'].append(v['category'])

    # 3.4 Traitement IndexedDB
    for category, path in _iter_category_files(idb_dir):
        items = _load_json(path)
        for idx, item in enumerate(items):
            v = vectorize_indexeddb(item, category, idx, cross_values, idb_store_counts.get(item.get("source_file", ""), 1), k_idb)
            pid = (v['task_id'], v['storage_type'], v['name'], str(v['value']))
            if pid not in physical_items:
                v['categories'] = [v.pop('category')]
                physical_items[pid] = v
            else:
                if v['category'] not in physical_items[pid]['categories']:
                    physical_items[pid]['categories'].append(v['category'])


    final_vectors = list(physical_items.values())
    out_dir = output_root / "user" / auth_status / user / policy / "_vector_data"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "vectorized_items.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(final_vectors, f, indent=2, ensure_ascii=False)

    print(f"   {auth_status}/{user}/{policy} → {len(final_vectors):,} physical items → {out_path}")
    return len(final_vectors)

def main():
    base_dir    = Path(__file__).resolve().parents[3]
    data_root   = base_dir / "data"
    output_root = data_root

    print("=" * 65)
    print("  ITEMS VECTORIZER (Physical Grouping)")
    print("=" * 65)

    total = 0
    for auth_status in AUTH_STATUSES:
        for user in USERS:
            for policy in POLICIES:
                total += vectorize_user_policy(data_root, auth_status, user, policy, output_root)

    print("=" * 65)
    print(f"  TOTAL vectorized items : {total:,}")
    print("=" * 65)

if __name__ == "__main__":
    main()