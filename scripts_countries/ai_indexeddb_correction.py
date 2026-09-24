#!/usr/bin/env python3
"""
AI CATEGORIZATION CORRECTION FOR INDEXEDDB - country extension.

; this script only targets the fields
that pipeline silently dropped.

Root cause being corrected: ai_parallel_indexededdb.py batches by RECORD
(10 records/prompt) with no cap on how many fields a single record can
contribute. Records with 50+ uncategorized fields (some have 3,000+ -
e.g. gamesnacks.com's flattened module-hash arrays) blow past the model's
output token limit in one response; the model returns a partial JSON array
and every field past that point is silently missing from
ai_categorizations.json, with no error raised.

Fix: batch by FIELD instead of by record, with a hard cap
(FIELD_BATCH_SIZE) on the total number of field-verdicts requested per API
call, regardless of how many distinct records those fields belong to. A
giant record's fields are simply split across as many chunks as needed.
Each chunk still includes, once per record represented in it, the same
"complete record context" (a handful of the record's already-known fields,
regex-categorized or previously AI-categorized) that
ai_parallel_indexededdb.py used - grounding is preserved, only the
batching unit changes.

Targets identified as a 3-way diff (no API calls needed for this part):
  1. hierarchical_reconstruction.json  -> the full field map per record,
     as of Stage 4 aggregation (regex-categorized + still-uncategorized).
  2. Every real category file currently in
     data/user_countries/{auth}/{user}/PARTIAL/indexeddb/*.json (excludes
     UNCATEGORIZED.json/INTERNAL_IDB_KEYS.json, already relocated to
     data/user_countries_raws/ by clean_user_folder.py) -> fields that are
     ALREADY correctly resolved (by regex, or by the original AI pass).
  3. The original ai_categorizations.json -> fields the original AI pass
     actually returned a verdict for (including ones it reviewed and kept
     UNCATEGORIZED - those are a real "no evidence" review, not a
     truncation victim, and are intentionally left alone here).

A field only becomes a correction target if it is (a) still sitting in
UNCATEGORIZED.json, (b) not already resolved anywhere else (this excludes
the ~41k fields the original redistribute script left duplicated - see
redistribute_ai_categorizations.py's docstring, "Does NOT modify
UNCATEGORIZED.json"), and (c) never appeared in the original AI pass's
output at all - i.e. genuinely never reviewed, not reviewed-and-rejected.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count
import traceback

try:
    from openai import OpenAI
    from openai import RateLimitError, APIError
except ImportError:
    print("Installing openai...")
    os.system("pip install openai")
    from openai import OpenAI
    from openai import RateLimitError, APIError

sys.path.insert(0, str(Path(__file__).parent))
from regex_merged_v3 import TRACKING_PATTERNS_COMPLETE
from aggregate_indexeddb import extract_record_index_from_path, generate_record_id

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from countries_config import add_users_arg, resolve_users

USER_PROFILES_FILE = Path(__file__).parent / "user_profiles_countries.json"
if USER_PROFILES_FILE.exists():
    with open(USER_PROFILES_FILE, "r", encoding="utf-8") as f:
        USER_PROFILES = {p["id"]: p for p in json.load(f)}
else:
    print("Warning: user_profiles_countries.json not found.")
    USER_PROFILES = {}

# Hard cap on how many field-verdicts a single API call is asked for,
# regardless of how many distinct records those fields belong to. This is
# the actual fix: the original pipeline capped by record count (10), which
# put no ceiling on fields-per-record and let oversized records blow the
# output budget on their own.
FIELD_BATCH_SIZE = 25

# =====================================================================
# UTILITIES (shared wording with ai_parallel_indexededdb.py)
# =====================================================================

def get_available_categories() -> List[str]:
    return [
        cat for cat in TRACKING_PATTERNS_COMPLETE.keys()
        if cat not in ["DIRECT_PII_KEYS", "INFRASTRUCTURE", "INTERNAL_IDB_KEYS"]
    ]

def format_categories_with_details() -> str:
    categories_text = "AVAILABLE CATEGORIES (with subcategories):\n\n"
    for category, subcats in TRACKING_PATTERNS_COMPLETE.items():
        if category in ["DIRECT_PII_KEYS", "INFRASTRUCTURE", "INTERNAL_IDB_KEYS"]:
            continue
        categories_text += f"## {category}\n"
        if isinstance(subcats, dict):
            subcat_list = list(subcats.keys())[:10]
            for subcat in subcat_list:
                categories_text += f"  - {subcat}\n"
            if len(subcats) > 10:
                categories_text += f"  ... and {len(subcats) - 10} more\n"
        categories_text += "\n"
    return categories_text

def load_json(path: Path):
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"  Error loading {path}: {e}")
        return None

# =====================================================================
# TARGET IDENTIFICATION (no API calls)
# =====================================================================

def build_record_context_map(reconstruction: Dict) -> Dict[str, Dict[str, Dict]]:
    """record_id -> {field_path: {category, subcategory, value, name}}"""
    context_map = {}
    for source_file, file_data in reconstruction.items():
        for record_key, record_data in file_data.get("records", {}).items():
            rid = record_data.get("record_id", "")
            context_map[rid] = record_data.get("fields", {})
    return context_map

def find_correction_targets(idb_dir: Path, raws_uncat_path: Path,
                             ai_categorizations_path: Path) -> List[Dict]:
    """
    Returns a list of {record_id, field_path, value, name, source_file}
    for fields that were never reviewed by the original AI pass
    (truncated out of a batch, or the whole batch failed).
    """
    # Fields already resolved somewhere real (regex categories, or the
    # original AI pass's successful redistributions) - excludes the
    # duplication-bug fields still lingering in UNCATEGORIZED.json.
    resolved_keys = set()
    if idb_dir.exists():
        for f in idb_dir.glob("*.json"):
            items = load_json(f) or []
            for it in items:
                fp = it.get("field_path")
                if not fp:
                    continue
                src = it.get("source_file", "")
                rid = it.get("record_id") or generate_record_id(src, extract_record_index_from_path(fp))
                resolved_keys.add((rid, fp))

    raw_items = load_json(raws_uncat_path) or []
    true_unresolved = []
    for it in raw_items:
        fp = it.get("field_path")
        if not fp:
            continue
        src = it.get("source_file", "")
        rid = generate_record_id(src, extract_record_index_from_path(fp))
        if (rid, fp) not in resolved_keys:
            true_unresolved.append({
                "record_id": rid, "field_path": fp,
                "value": it.get("value"), "name": it.get("name"),
                "source_file": src,
            })

    returned_keys = set()
    ai_out = load_json(ai_categorizations_path) or []
    for rec in ai_out:
        rid = rec.get("record_id")
        for field in rec.get("fields", []):
            fp = field.get("field_path")
            if fp:
                returned_keys.add((rid, fp))

    return [t for t in true_unresolved if (t["record_id"], t["field_path"]) not in returned_keys]

# =====================================================================
# PROMPT + AI CALL (field-capped batches)
# =====================================================================

def build_correction_prompt(chunk: List[Dict], context_map: Dict[str, Dict],
                             user_id: str) -> str:
    prompt = f"""[SYSTEM: ROLE = GDPR_INDEXEDDB_EXPERT]

USER PROFILE:
{json.dumps(USER_PROFILES.get(user_id, {}), ensure_ascii=False, indent=2)}

{format_categories_with_details()}

TASK:
This is a CORRECTION PASS. The fields below were never reviewed in the
first pass because they belonged to records too large to enumerate fully
in one response. Analyze each one using the record context provided.

STRICT RULES:
- You MUST select exactly ONE category from the provided list.
- You MUST NOT infer intent, user behavior, or legal meaning beyond explicit evidence.
- You MUST NOT use assumptions.
- If there is insufficient evidence, choose UNCATEGORIZED.
- You MUST provide a short, factual explanation based only on:
  - field name
  - value format
  - immediate technical context

CATEGORIZATION GUIDELINES:
1. If the VALUE contains user profile data -> DIRECT_PII
2. If it's a tracking identifier (UUID, hash, ID) -> IDENTITY_TRACKING
3. If it's behavioral data (clicks, views, PageViewEvent) -> BEHAVIORAL_DATA
4. If it's a configuration/preference -> USER_PREFERENCES
5. If it's clearly bulk technical/application data (cached source code,
   asset module hashes, structural buffers) -> keep UNCATEGORIZED
6. If no clear evidence -> keep UNCATEGORIZED
etc.

FIELDS TO ANALYZE (grouped by record):
"""

    by_record = defaultdict(list)
    for item in chunk:
        by_record[item["record_id"]].append(item)

    for rid, items in by_record.items():
        prompt += f"\n--- RECORD (ID: {rid}) ---\n"
        prompt += f"Source: {items[0].get('source_file', '')}\n\n"

        record_fields = context_map.get(rid, {})
        prompt += "Complete record context (already-known fields, for grounding):\n"
        for field_path, field_info in list(record_fields.items())[:5]:
            value_str = str(field_info.get("value"))[:50] if field_info.get("value") else "null"
            prompt += f"   {field_path}: {field_info.get('category')} = {value_str}\n"

        prompt += "\nFields to categorize in this batch (subset of this record's missing fields):\n"
        for item in items:
            value_str = str(item.get("value"))[:200] if item.get("value") else "null"
            prompt += f"  - {item['field_path']}: {value_str}\n"

    prompt += """\n\nRESPOND IN JSON ONLY:
{
  "records": [
    {
      "record_id": "record ID",
      "fields": [
        {
          "field_path": "complete path",
          "category": "CATEGORY_NAME or UNCATEGORIZED",
          "confidence": 0.0-1.0,
          "explanation": "Technical evidence"
        }
      ]
    }
  ]
}
"""
    return prompt


def analyze_chunk_with_ai(chunk: List[Dict], context_map: Dict, user_id: str,
                           client: OpenAI, max_retries: int = 5) -> Optional[Dict]:
    prompt = build_correction_prompt(chunk, context_map, user_id)

    for attempt in range(max_retries):
        try:
            completion = client.chat.completions.create(
                model="gpt-4.1-mini",
                temperature=0.0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "You are a GDPR expert. Respond ONLY in valid JSON."},
                    {"role": "user", "content": prompt}
                ]
            )
            return json.loads(completion.choices[0].message.content)

        except RateLimitError as e:
            wait_time = 2 ** attempt
            print(f"    Warning: Rate limit hit (attempt {attempt+1}/{max_retries}), waiting {wait_time}s...")
            if attempt < max_retries - 1:
                time.sleep(wait_time)
            else:
                print(f"    Error: Max retries reached, chunk failed")
                return None

        except APIError as e:
            wait_time = 2 ** attempt
            print(f"    Warning: API Error: {e} (attempt {attempt+1}/{max_retries}), waiting {wait_time}s...")
            if attempt < max_retries - 1:
                time.sleep(wait_time)
            else:
                print(f"    Error: Max retries reached, chunk failed")
                return None

        except Exception as e:
            print(f"    Error: Unrecoverable error: {e}")
            return None

    return None

# =====================================================================
# WORKER
# =====================================================================

def process_single_configuration(config: Dict) -> Dict:
    auth = config['auth']
    user = config['user']
    policy = config['policy']
    idb_dir = Path(config['idb_dir'])
    raws_uncat_path = Path(config['raws_uncat_path'])
    reconstruction_path = Path(config['reconstruction_path'])
    ai_categorizations_path = Path(config['ai_categorizations_path'])
    output_path = Path(config['output_path'])
    api_key = config['api_key']

    config_name = f"{auth}/{user}/{policy}"

    try:
        print(f"\n[{config_name}] Identifying correction targets...")

        targets = find_correction_targets(idb_dir, raws_uncat_path, ai_categorizations_path)

        if not targets:
            return {'config': config_name, 'status': 'skipped', 'reason': 'No correction targets'}

        print(f"[{config_name}] {len(targets)} fields never reviewed (truncated/failed)")

        reconstruction = load_json(reconstruction_path) or {}
        context_map = build_record_context_map(reconstruction)

        client = OpenAI(api_key=api_key)

        all_categorizations = []
        failed_chunks = 0

        for start in range(0, len(targets), FIELD_BATCH_SIZE):
            chunk = targets[start:start + FIELD_BATCH_SIZE]
            end = min(start + FIELD_BATCH_SIZE, len(targets))

            print(f"[{config_name}] Chunk [{start+1}-{end}/{len(targets)}]...", end=" ")

            response = analyze_chunk_with_ai(chunk, context_map, user, client, max_retries=5)

            if response and "records" in response:
                batch_results = response["records"]
                all_categorizations.extend(batch_results)
                total_fields = sum(len(r.get("fields", [])) for r in batch_results)
                print(f"OK ({len(batch_results)} records, {total_fields} fields)")
            else:
                failed_chunks += 1
                print("FAILED")

            if end < len(targets):
                wait_time = 2.0 if failed_chunks > 0 else 1.0
                time.sleep(wait_time)

        # Merge records that appear in multiple chunks (same record split
        # across several field-batches) into one entry per record_id.
        merged: Dict[str, List[Dict]] = defaultdict(list)
        for rec in all_categorizations:
            merged[rec.get("record_id", "")].extend(rec.get("fields", []))
        merged_records = [{"record_id": rid, "fields": fields} for rid, fields in merged.items()]

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(merged_records, f, indent=2, ensure_ascii=False)

        total_fields_out = sum(len(r["fields"]) for r in merged_records)
        print(f"[{config_name}] Saved {total_fields_out} corrected field verdicts -> {output_path}")

        return {
            'config': config_name,
            'status': 'success' if failed_chunks == 0 else 'partial',
            'targets': len(targets),
            'fields_corrected': total_fields_out,
            'failed_chunks': failed_chunks,
        }

    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"[{config_name}] Error: {e}")
        print(error_trace)
        return {'config': config_name, 'status': 'error', 'error': str(e), 'traceback': error_trace}

# =====================================================================
# MAIN
# =====================================================================

def main(users=None):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY missing")
        return

    base_dir = Path(__file__).resolve().parent.parent / "data"
    aggregates_base = base_dir / "aggregates_countries" / "indexeddb"
    ai_complete_base = base_dir / "aggregates_ai_complete_countries" / "indexeddb"
    user_base = base_dir / "user_countries"
    raws_base = base_dir / "user_countries_raws"
    output_base = base_dir / "aggregates_ai_complete_countries" / "indexeddb"

    print("=" * 80)
    print("AI CATEGORIZATION CORRECTION - INDEXEDDB TRUNCATED FIELDS")
    print(f"Field batch size: {FIELD_BATCH_SIZE} (vs. original's uncapped per-record batching)")
    print("=" * 80)

    users = users or resolve_users(None)
    print(f"Scoped to users: {users}")
    configurations = []

    for auth in ["AUTH", "NOTAUTH"]:
        for user in users:
            for policy in ["PARTIAL"]:
                idb_dir = user_base / auth / user / policy / "indexeddb"
                raws_uncat_path = raws_base / auth / user / policy / "indexeddb" / "UNCATEGORIZED.json"
                reconstruction_path = aggregates_base / auth / user / policy / "hierarchical_reconstruction.json"
                ai_categorizations_path = ai_complete_base / auth / user / policy / "ai_categorizations.json"
                output_path = output_base / auth / user / policy / "ai_categorizations_correction.json"

                if not raws_uncat_path.exists():
                    continue

                configurations.append({
                    'auth': auth, 'user': user, 'policy': policy,
                    'idb_dir': str(idb_dir),
                    'raws_uncat_path': str(raws_uncat_path),
                    'reconstruction_path': str(reconstruction_path),
                    'ai_categorizations_path': str(ai_categorizations_path),
                    'output_path': str(output_path),
                    'api_key': api_key,
                })

    if not configurations:
        print("Warning: No configurations to process")
        return

    print(f"\nFound {len(configurations)} configurations to process")

    num_workers = min(11, cpu_count(), len(configurations))
    print(f"Using {num_workers} parallel workers (CPU cores: {cpu_count()})")

    start_time = time.time()
    with Pool(processes=num_workers) as pool:
        results = pool.map(process_single_configuration, configurations)
    elapsed_time = time.time() - start_time

    print(f"\n{'='*80}")
    print("CORRECTION PASS SUMMARY")
    print(f"{'='*80}\n")

    total_targets = 0
    total_corrected = 0
    for r in results:
        if r['status'] in ('success', 'partial'):
            total_targets += r.get('targets', 0)
            total_corrected += r.get('fields_corrected', 0)
            print(f"{r['status'].upper():8s} {r['config']}: {r.get('fields_corrected', 0)}/{r.get('targets', 0)} fields")
        elif r['status'] == 'skipped':
            print(f"SKIPPED  {r['config']}: {r['reason']}")
        else:
            print(f"ERROR    {r['config']}: {r.get('error')}")

    print(f"\nTotal targets identified : {total_targets}")
    print(f"Total fields corrected   : {total_corrected}")
    print(f"Time: {elapsed_time:.2f}s")
    print(f"{'='*80}")
    print("\nRun redistribute_ai_categorizations_correction.py next to merge these results.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
