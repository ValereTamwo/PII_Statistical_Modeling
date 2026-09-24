#!/usr/bin/env bash
#
# Onboards ONE new-country persona through the whole country-extension
# pipeline (categorization -> AI correction -> post-AI regex correction),
# then regenerates the downstream analysis/risk outputs for ALL countries
# so the new persona shows up in every comparison.
#
# Usage:
#   OPENAI_API_KEY=sk-... ./run_new_country_pipeline.sh [USER_ID]
#
# USER_ID defaults to FR_0429. Every categorization stage below is scoped
# to --users "$USER_ID" ONLY: it will never re-run, overwrite, or duplicate
# data for the countries already finalized in countries_config.py's USERS
# list. The final "downstream analysis" section is the one deliberate
# exception - those stages are pure derived computation (they recompute
# their own output from scratch each run), so they run unscoped to refresh
# comparisons across every country, including the new one.
#
# Safe to re-run: every stage here is either idempotent (AI categorize
# scripts skip items already marked ai_processed) or, for the correction
# passes, safely re-runnable (already-resolved fields are skipped - see
# scripts_countries/README.md, Stage 7).

set -euo pipefail

USER_ID="${1:-FR_0429}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

LOG_DIR="$ROOT_DIR/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/onboard_${USER_ID}_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

section() {
    echo
    echo "################################################################################"
    echo "# $1"
    echo "################################################################################"
}

section "ONBOARDING $USER_ID - $(date)"
echo "Log file: $LOG_FILE"

# --------------------------------------------------------------------------
# Sanity checks
# --------------------------------------------------------------------------
section "SANITY CHECKS"

if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "ERROR: OPENAI_API_KEY is not set. Stage 5 and Stage 7 need it."
    echo "Run as: OPENAI_API_KEY=sk-... $0 $USER_ID"
    exit 1
fi
echo "OK: OPENAI_API_KEY is set."

RAW_AUTH_IDB="data/Countries_data/Users/$USER_ID/AUTH/indexeddb"
RAW_NOTAUTH_IDB="data/Countries_data/Users/$USER_ID/NOTAUTH/indexeddb"
if [ ! -d "$RAW_AUTH_IDB" ] || [ ! -d "$RAW_NOTAUTH_IDB" ]; then
    echo "ERROR: Raw IndexedDB capture missing for $USER_ID."
    echo "  Expected: $RAW_AUTH_IDB"
    echo "  Expected: $RAW_NOTAUTH_IDB"
    echo "Re-collect the IndexedDB data for this persona before running this script."
    exit 1
fi
echo "OK: Raw IndexedDB capture found for $USER_ID (AUTH + NOTAUTH)."

python3 -c "
import sys
sys.path.insert(0, '.')
from countries_config import resolve_users
resolve_users('$USER_ID')
print('OK: \"$USER_ID\" is a known user in countries_config.py')
"

# --------------------------------------------------------------------------
# Stage 1 - Preprocessing (extraction), scoped to USER_ID only
# --------------------------------------------------------------------------
section "STAGE 1 - PREPROCESSING (extraction) - $USER_ID only"
python3 preprocessing_countries/run_all.py --users "$USER_ID"

# --------------------------------------------------------------------------
# Stages 2-6 - Regex categorization, cleaning, aggregation, AI categorization,
# redistribution & finalization - scoped to USER_ID only
# --------------------------------------------------------------------------
section "STAGES 2-6 - CATEGORIZATION PIPELINE - $USER_ID only"
python3 scripts_countries/run_all.py --users "$USER_ID"

# --------------------------------------------------------------------------
# Stage 7 - AI IndexedDB truncation correction - scoped to USER_ID only
# --------------------------------------------------------------------------
section "STAGE 7 - AI INDEXEDDB TRUNCATION CORRECTION - $USER_ID only"
python3 scripts_countries/ai_indexeddb_correction.py --users "$USER_ID"
python3 scripts_countries/redistribute_ai_categorizations_correction.py --users "$USER_ID"

# --------------------------------------------------------------------------
# Stage 8 - Post-AI regex correction (final catch-all) - scoped to USER_ID only
# --------------------------------------------------------------------------
section "STAGE 8 - POST-AI REGEX CORRECTION (preview) - $USER_ID only"
python3 scripts_countries/dry_run_regex_post_ai_correction.py --users "$USER_ID"

section "STAGE 8 - POST-AI REGEX CORRECTION (apply) - $USER_ID only"
python3 scripts_countries/apply_regex_post_ai_correction.py --users "$USER_ID"

section "CATEGORIZATION PIPELINE COMPLETE FOR $USER_ID"
echo "$USER_ID is now categorized/corrected to the same state as the other countries."
echo "The other countries in countries_config.py's USERS list were never touched above."

# --------------------------------------------------------------------------
# Downstream analysis & risk scoring - deliberately UNSCOPED (full USERS
# list from countries_config.py) so every comparison/report/figure is
# regenerated to include the new country. These stages are pure derived
# computation: they recompute their own output from scratch, so re-running
# them for the already-finalized countries is safe and does not touch any
# categorized data.
# --------------------------------------------------------------------------
section "ANALYSIS - COOKIE/STORAGE STATS (all countries)"
python3 analysis_countries/run_all.py
python3 analysis_countries/country_comparative_summary.py

section "ANALYSIS - GDPR PROFILE AGGREGATION & REPORT (all countries)"
python3 analysis_gdpr_profiles_countries/run_all.py

section "RISK ANALYSIS - PxI SCORING & FIGURES (all countries)"
python3 risk_analysis_PxI_countries/run_all.py

section "PIPELINE COMPLETE - $(date)"
echo "$USER_ID onboarded and all cross-country analysis/risk outputs regenerated."
echo "Full log: $LOG_FILE"
