


"""
INDEXEDDB PRE-FILTERING
V2: Static resource noise removal (JS, CSS, Cache)
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any


# Structural Regex & Resource Patterns (Anti-Noise)

# postBody.<num> (payload binaire / protobuf)
POSTBODY_INDEX_RE = re.compile(r"\.postbody\.\d+$")

# .<num> final (properties.63, entries[12], etc.)
# GENERIC_NUMERIC_INDEX_RE = re.compile(r"(\[\d+\]|\.\d+)$")

# entries[12], values[3], etc.
ARRAY_INDEX_RE = re.compile(r"\[\d+\]")

# entries numériques avec .version
VERSION_INDEX_RE = re.compile(r"\[\d+\]\.version$")

# Détection des ressources web statiques (js, css, images, etc.)
# Capture les extensions classiques, même avec des paramtres de requête (?v=1.2)
WEB_RESOURCE_RE = re.compile(
    r"\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ttf|otf|ico|map|webmanifest)(\?.*)?$", 
    re.IGNORECASE
)

# Technical IndexedDB Key Detection

def is_idb_internal_key(item: Dict[str, Any]) -> bool:
    """
    Detects if an item corresponds to:
    - a technical IndexedDB key
    - a static web resource (JS/CSS/Images)
    - an application cache artifact
    - a binary buffer or numeric index
    """

    field_path = item.get("field_path", "").lower()
    name = item.get("name", "").lower()
    value = item.get("value")
    value_str = str(value).lower()
    
    if name.isdigit() and isinstance(value, (int, float)):
        return True
    # --------------------------------------------------------
    # Filter static web resources and technical assets
    is_web_resource = bool(WEB_RESOURCE_RE.search(value_str))
    
    # Filter cache entries (e.g., "my-app-scripts-v1")
    is_cache_related = (
        "cache" in name 
        or "cachename" in name 
        or "version" in name
    ) and (len(value_str) < 50)

    if is_web_resource or is_cache_related:
        return True

    # --------------------------------------------------------
    # Explicit technical IndexedDB keys
    # --------------------------------------------------------
    internal_suffixes = (
        ".key",
        ".value.key",
        ".name",
        ".propertyname",
         "._id",
        ".objectstorename",
        ".indexname",
    )

    is_internal_key_path = any(field_path.endswith(s) for s in internal_suffixes)

    # Technical identifier values (short, no spaces)
    is_technical_value = (
        str(value).isidentifier()
        or (len(value_str) < 60 and " " not in value_str)
    )

    if is_internal_key_path and is_technical_value:
        return True

    # --------------------------------------------------------
    # Structural payloads (postBody, indices)
    # --------------------------------------------------------
    is_postbody_index = bool(POSTBODY_INDEX_RE.search(field_path))
    # is_numeric_suffix = bool(GENERIC_NUMERIC_INDEX_RE.search(field_path))
    # is_array_index = bool(ARRAY_INDEX_RE.search(field_path))

    # is_numeric_value = isinstance(value, (int, float))
    is_version_index = bool(VERSION_INDEX_RE.search(field_path))

    if (is_postbody_index or is_version_index) :
        return True

    # --------------------------------------------------------
    # 4. Valeurs manifestement non sémantiques (ID profonds)
    # --------------------------------------------------------
    if isinstance(value, (int, float)) and value >= 0 and len(field_path.split(".")) > 4:
        return True

    return False


# ============================================================
# DÉCOUVERTE DES TÂCHES INDEXEDDB
# ============================================================

def discover_uncategorized_tasks(base_path: Path) -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    if not base_path.exists():
        return tasks

    # Parcours récursif pour trouver UNCATEGORIZED.json dans les dossiers indexeddb
    for uncategorized in base_path.glob("**/indexeddb/UNCATEGORIZED.json"):
        tasks.append({
            "path": uncategorized,
            "dir": uncategorized.parent,
        })

    return tasks


# ============================================================
# FILTRAGE PRINCIPAL
# ============================================================

def filter_idb_internal_keys(base_path: Path) -> None:
    """
    Sépare le bruit technique et les ressources web
    de la donnée réellement exploitable.
    """

    tasks = discover_uncategorized_tasks(base_path)
    print(f"--- Analyse de {len(tasks)} dossiers IndexedDB ---")

    for task in tasks:
        file_path = task["path"]
        storage_dir = task["dir"]

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                items = json.load(f)

            if not isinstance(items, list):
                continue

            real_data: List[Dict[str, Any]] = []
            internal_data: List[Dict[str, Any]] = []

            for item in items:
                if is_idb_internal_key(item):
                    item["_internal_reason"] = "TECHNICAL_ASSET_OR_IDB_NOISE"
                    internal_data.append(item)
                else:
                    real_data.append(item)

            if not internal_data:
                continue

            # ------------------------------------------------
            # Sauvegarde des éléments techniques/assets
            # ------------------------------------------------
            internal_file = storage_dir / "INTERNAL_IDB_KEYS.json"

            existing: List[Dict[str, Any]] = []
            if internal_file.exists():
                try:
                    with open(internal_file, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except Exception:
                    existing = []

            with open(internal_file, "w", encoding="utf-8") as f:
                json.dump(
                    existing + internal_data,
                    f,
                    indent=4,
                    ensure_ascii=False,
                )

            # ------------------------------------------------
            # Mise  jour de UNCATEGORIZED (Data propre)
            # ------------------------------------------------
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(
                    real_data,
                    f,
                    indent=4,
                    ensure_ascii=False,
                )

            print(f"[NETTOYÉ] {storage_dir.relative_to(base_path.parent)} : {len(internal_data)} bruits supprimés.")

        except Exception as e:
            print(f"[ERREUR] {file_path} : {e}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    # Ajuste le chemin vers ton dossier data/user
    base_path = Path(__file__).resolve().parent.parent / "data" / "user"

    filter_idb_internal_keys(base_path)

    print("--- Fin du filtrage des ressources et bruits techniques ---")