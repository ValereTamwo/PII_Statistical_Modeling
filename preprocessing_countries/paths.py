#!/usr/bin/env python3
"""
Path resolution for the country-extension preprocessing stage.

Mirrors preprocessing/extract_*.py, but reads from data/Countries_data/Users/
instead of data/raw/, covers the country personas (see
countries_config.USERS), and only the PARTIAL policy (the only one
collected for these users). Kept fully separate from the existing FR
pipeline (preprocessing/, data/raw/, data/preprocessing/) so the original
data and results are never touched.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from countries_config import USERS, AUTH_STATUSES

POLICY = 'PARTIAL'

PROJECT_ROOT = Path(__file__).resolve().parent.parent
COUNTRIES_ROOT = PROJECT_ROOT / 'data' / 'Countries_data' / 'Users'
OUTPUT_ROOT = PROJECT_ROOT / 'data' / 'preprocessing_countries'

# Where the real (non-leftover) storage_state captures live for
# cookies/localStorage/sessionStorage.
# AUTH: the collector merges the login-page + post-login state into
#   partial/login/ - that is the complete per-task capture to use.
#   The top-level partial/*.json (small, 7-57 files) is a leftover subset
#   already folded into login/ and must NOT be used.
# NOTAUTH: no login flow applies; partial/login/ is irrelevant/inconsistent
#   across users - use the top-level partial/*.json files directly.
_STORAGE_STATE_SUBDIR = {
    'AUTH': 'AUTH/AUTH/partial/login',
    'NOTAUTH': 'NOTAUTH/NotAUTH/partial',
}

# IndexedDB dumps have no login/no-login split - used as-is for both branches.
_IDB_SUBDIR = {
    'AUTH': 'AUTH/indexeddb/{user}/indexedDB/partial',
    'NOTAUTH': 'NOTAUTH/indexeddb/{user}/indexedDB/partial',
}


def storage_state_dir(user: str, auth_status: str) -> Path:
    return COUNTRIES_ROOT / user / _STORAGE_STATE_SUBDIR[auth_status]


def indexeddb_dir(user: str, auth_status: str) -> Path:
    return COUNTRIES_ROOT / user / _IDB_SUBDIR[auth_status].format(user=user)


def output_dir(auth_status: str, user: str, storage_type: str) -> Path:
    return OUTPUT_ROOT / auth_status / user / POLICY / storage_type
