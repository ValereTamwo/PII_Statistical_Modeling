"""
Centralized country-pipeline configuration.

The single source of truth for which country personas are in scope,
shared by every stage: preprocessing_countries/, scripts_countries/,
analysis_countries/, analysis_gdpr_profiles_countries/, and
risk_analysis_PxI_countries/. No script in any of those trees hardcodes
its own copy of this list - they all import USERS / USER_ID_TO_INDEX
from here.

Onboarding a new persona:
  1. Add their regex_merged_v3.py DIRECT_PII block index to
     USER_ID_TO_INDEX below.
  2. Add their user_id to USERS below.
  3. Add their profile to scripts_countries/user_profiles_countries.json.
  4. Nothing else changes. A full pipeline run with no --users override
     will pick them up automatically, on this machine or a fresh one.

Incremental runs (--users):
  Every stage script accepts --users (see add_users_arg/resolve_users
  below) to scope a single run to a subset of USERS - typically just the
  persona(s) just added in step 1-3 above. This matters because several
  early pipeline stages (regex categorization, cleaning) OVERWRITE a
  persona's category files from scratch on every run: re-running them for
  an already-finalized persona would destroy the AI-categorization and
  correction-pass work layered on top since. Omitting --users processes
  the full USERS list - the mode a fresh setup with empty data
  directories should always use.
"""

USERS = [
    "IT_0573",
    "LU_0634",
    "PT_0838",
    "SE_0964",
    "ES_0290",
    "DE_0018",
    "FR_0429",
    "IE_0504",
    "NL_0694",
    "PL_0742",
    "AT_0077",
    "DK_0199",
    "FI_0373",
]

# Index of each user's block within regex_merged_v3.py's
# TRACKING_PATTERNS_COMPLETE['DIRECT_PII'] list.
USER_ID_TO_INDEX = {
    'IT_0573': 4,
    'LU_0634': 5,
    'PT_0838': 8,
    'SE_0964': 10,
    'ES_0290': 14,
    'DE_0018': 17,
    'FR_0429': 16,
    'IE_0504': 3,
    'NL_0694': 6,
    'PL_0742': 7,
    'AT_0077': 11,
    'DK_0199': 13,
    'FI_0373': 15,
}

AUTH_STATUSES = ["AUTH", "NOTAUTH"]
POLICIES = ["PARTIAL"]


def add_users_arg(parser):
    """Adds the standard --users override to an argparse.ArgumentParser."""
    parser.add_argument(
        "--users",
        default=None,
        help=(
            "Comma-separated subset of users to process "
            f"(default: all of {USERS}). Use this to process only newly "
            "added personas without reprocessing already-finalized ones."
        ),
    )


def resolve_users(users_arg):
    """
    Resolves a --users CLI value (comma-separated string, list, or None)
    against USERS, preserving USERS' canonical order and validating every
    requested id is known. None/empty -> the full USERS list.
    """
    if not users_arg:
        return list(USERS)

    if isinstance(users_arg, str):
        requested = [u.strip() for u in users_arg.split(",") if u.strip()]
    else:
        requested = list(users_arg)

    unknown = [u for u in requested if u not in USERS]
    if unknown:
        raise ValueError(f"Unknown user id(s): {unknown}. Known users: {USERS}")

    # Preserve USERS' canonical order, not whatever order the CLI gave.
    return [u for u in USERS if u in requested]
