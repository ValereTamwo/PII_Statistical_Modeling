#!/usr/bin/env python3
"""
AI CATEGORIZATION FOR INDEXEDDB - CONTEXT-AWARE STRATEGY (PARALLELIZED + RATE LIMIT HANDLING)

Uses hierarchical_reconstruction.json files to provide complete record context
to the AI model, improving categorization accuracy for UNCATEGORIZED items.

PARALLELIZATION: One process per configuration (Auth/User/Policy) to avoid conflicts.
RATE LIMIT HANDLING: Exponential backoff with retry on 429 errors.
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

# OpenAI API
try:
    from openai import OpenAI
    from openai import RateLimitError, APIError
except ImportError:
    print("Installing openai...")
    os.system("pip install openai")
    from openai import OpenAI
    from openai import RateLimitError, APIError

# Import configurations
sys.path.insert(0, str(Path(__file__).parent))
from regex import TRACKING_PATTERNS_COMPLETE

# User configuration
USER_ID_TO_INDEX = {
    "FR_0417": 0,
    "FR_0446": 1,
    "FR_0458": 2
}

# Load user profiles
USER_PROFILES_FILE = Path(__file__).parent / "user_profiles.json"
if USER_PROFILES_FILE.exists():
    with open(USER_PROFILES_FILE, "r", encoding="utf-8") as f:
        USER_PROFILES = {p["id"]: p for p in json.load(f)}
else:
    print("Warning: user_profiles.json not found.")
    USER_PROFILES = {}

# =====================================================================
# UTILITIES
# =====================================================================

def get_available_categories() -> List[str]:
    """Returns the list of available categories (without INFRASTRUCTURE)."""
    return [
        cat for cat in TRACKING_PATTERNS_COMPLETE.keys()
        if cat not in ["DIRECT_PII_KEYS", "INFRASTRUCTURE", "INTERNAL_IDB_KEYS"]
    ]

def format_categories_with_details() -> str:
    """Formats categories with their subcategories from regex.py."""
    categories_text = "AVAILABLE CATEGORIES (with subcategories):\n\n"
    
    for category, subcats in TRACKING_PATTERNS_COMPLETE.items():
        if category in ["DIRECT_PII_KEYS", "INFRASTRUCTURE", "INTERNAL_IDB_KEYS"]:
            continue
        
        categories_text += f"## {category}\n"
        
        if isinstance(subcats, dict):
            # Limit to 10 subcategories to avoid overloading the prompt
            subcat_list = list(subcats.keys())[:10]
            for subcat in subcat_list:
                categories_text += f"  - {subcat}\n"
            if len(subcats) > 10:
                categories_text += f"  ... and {len(subcats) - 10} more\n"
        
        categories_text += "\n"
    
    return categories_text

# =====================================================================
# DATA LOADING
# =====================================================================

def load_hierarchical_reconstruction(reconstruction_file: Path) -> Dict:
    """Loads the hierarchical_reconstruction.json file."""
    if not reconstruction_file.exists():
        return {}
    
    with open(reconstruction_file, "r", encoding="utf-8") as f:
        return json.load(f)

def load_categorized_files(indexeddb_dir: Path) -> Dict[str, List[Dict]]:
    """Loads all IndexedDB category files."""
    categorized = {}
    
    if not indexeddb_dir.exists():
        return categorized
    
    for json_file in indexeddb_dir.glob("*.json"):
        category = json_file.stem
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                items = json.load(f)
                if items:
                    categorized[category] = items
        except Exception as e:
            print(f"  Error loading {json_file}: {e}")
    
    return categorized

# =====================================================================
# EXTRACTION OF RECORDS WITH UNCATEGORIZED
# =====================================================================

def extract_records_with_uncategorized(
    reconstruction: Dict,
    categorized_data: Dict[str, List[Dict]]
) -> List[Dict]:
    """
    Extracts records that contain UNCATEGORIZED fields.
    
    Returns:
        List of records with context: {
            'record_id': str,
            'source_file': str,
            'all_fields': {field_path: {category, value, ...}},
            'uncategorized_fields': [field_paths]
        }
    """
    records_with_uncat = []
    
    # Create a mapping field_path -> category from categorized data
    field_categories = {}
    for category, items in categorized_data.items():
        for item in items:
            field_path = item.get("field_path", "")
            if field_path:
                field_categories[field_path] = {
                    "category": category,
                    "subcategory": item.get("matched_subcategory", "unknown"),
                    "value": item.get("value")
                }
    
    # Browse hierarchical reconstruction
    for source_file, file_data in reconstruction.items():
        records = file_data.get("records", {})
        
        for record_key, record_data in records.items():
            record_id = record_data.get("record_id", "")
            fields = record_data.get("fields", {})
            
            # Identify UNCATEGORIZED fields
            uncategorized_fields = []
            all_fields_info = {}
            
            for field_path, field_info in fields.items():
                category = field_info.get("category", "UNKNOWN")
                
                all_fields_info[field_path] = {
                    "category": category,
                    "subcategory": field_info.get("subcategory", "unknown"),
                    "value": field_info.get("value"),
                    "name": field_info.get("name", field_path.split(".")[-1])
                }
                
                if category == "UNCATEGORIZED":
                    uncategorized_fields.append(field_path)
            
            # If the record contains UNCATEGORIZED, add it
            if uncategorized_fields:
                records_with_uncat.append({
                    "record_id": record_id,
                    "source_file": source_file,
                    "all_fields": all_fields_info,
                    "uncategorized_fields": uncategorized_fields
                })
    
    return records_with_uncat

# =====================================================================
# AI ANALYSIS WITH RETRY + EXPONENTIAL BACKOFF
# =====================================================================

def analyze_records_batch_with_ai(
    records_batch: List[Dict],
    user_id: str,
    available_categories: List[str],
    client: OpenAI,
    max_retries: int = 5
) -> Optional[Dict]:
    """
    Analyzes a batch of records with AI using complete context.
    Implements exponential backoff for rate limit errors.
    
    Args:
        max_retries: Maximum number of retry attempts (default: 5)
    """
    
    # Build the prompt
    combined_prompt = f"""[SYSTEM: ROLE = GDPR_INDEXEDDB_EXPERT]

USER PROFILE:
{json.dumps(USER_PROFILES.get(user_id, {}), ensure_ascii=False, indent=2)}

{format_categories_with_details()}

TASK:
Analyze the UNCATEGORIZED fields of {len(records_batch)} records.
For each record, use the COMPLETE CONTEXT to determine the category.

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
1. If the VALUE contains user profile data  DIRECT_PII
2. If it's a tracking identifier (UUID, hash, ID)  IDENTITY_TRACKING
3. If it's behavioral data (clicks, views, PageViewEvent)  BEHAVIORAL_DATA
4. If it's a configuration/preference  USER_PREFERENCES
5. If no clear evidence  keep UNCATEGORIZED
etc.

RECORDS TO ANALYZE:
"""
    
    for idx, record in enumerate(records_batch, 1):
        combined_prompt += f"\n--- RECORD {idx} (ID: {record['record_id']}) ---\n"
        combined_prompt += f"Source: {record['source_file']}\n\n"
        
        # Record context
        combined_prompt += "Complete record context:\n"
        for field_path, field_info in list(record['all_fields'].items())[:5]:  # Limit to 5 fields for context
            value_str = str(field_info['value'])[:50] if field_info['value'] else "null"
            combined_prompt += f"   {field_path}: {field_info['category']} = {value_str}\n"
        
        # Fields to categorize
        combined_prompt += "\nUNCATEGORIZED fields to categorize:\n"
        for field_path in record['uncategorized_fields']:
            field_info = record['all_fields'][field_path]
            value_str = str(field_info['value'])[:200] if field_info['value'] else "null"
            combined_prompt += f"  - {field_path}: {value_str}\n"
    
    combined_prompt += """\n\nRESPOND IN JSON ONLY:
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
    
    # Retry logic with exponential backoff
    for attempt in range(max_retries):
        try:
            completion = client.chat.completions.create(
                model="gpt-4.1-mini",
                temperature=0.0,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": "You are a GDPR expert. Respond ONLY in valid JSON."
                    },
                    {
                        "role": "user",
                        "content": combined_prompt
                    }
                ]
            )
            
            response = json.loads(completion.choices[0].message.content)
            return response
            
        except RateLimitError as e:
            # Calculate exponential backoff: 2^attempt seconds
            wait_time = 2 ** attempt
            print(f"    Warning: Rate limit hit (attempt {attempt+1}/{max_retries}), waiting {wait_time}s...")
            
            if attempt < max_retries - 1:
                time.sleep(wait_time)
            else:
                print(f"    Error: Max retries reached, batch failed")
                return None
                
        except APIError as e:
            # Other API errors (500, 503, etc.)
            wait_time = 2 ** attempt
            print(f"    Warning: API Error: {e} (attempt {attempt+1}/{max_retries}), waiting {wait_time}s...")
            
            if attempt < max_retries - 1:
                time.sleep(wait_time)
            else:
                print(f"    Error: Max retries reached, batch failed")
                return None
                
        except Exception as e:
            # Unrecoverable errors (JSON parsing, etc.)
            print(f"    Error: Unrecoverable error: {e}")
            return None
    
    return None

# =====================================================================
# SAVE AI CATEGORIZATIONS (INTERMEDIATE)
# =====================================================================

def save_ai_categorizations_intermediate(
    all_categorizations: List[Dict],
    output_dir: Path
):
    """
    Saves AI categorizations to an intermediate file.
    A separate script will handle redistribution.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    ai_results_file = output_dir / "ai_categorizations.json"
    
    with open(ai_results_file, "w", encoding="utf-8") as f:
        json.dump(all_categorizations, f, indent=2, ensure_ascii=False)
    
    print(f"   Saved: {len(all_categorizations)} AI categorizations")
    print(f"      {ai_results_file}")
    
    # Statistics
    stats = {
        "total_records": len(all_categorizations),
        "total_fields": sum(len(r.get("fields", [])) for r in all_categorizations),
        "categories_distribution": Counter()
    }
    
    for record_cat in all_categorizations:
        for field in record_cat.get("fields", []):
            category = field.get("category", "UNCATEGORIZED")
            stats["categories_distribution"][category] += 1
    
    # Save stats
    stats_file = output_dir / "ai_categorization_stats.json"
    with open(stats_file, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    
    return stats

# =====================================================================
# WORKER FUNCTION FOR PARALLEL PROCESSING
# =====================================================================

def process_single_configuration(config: Dict) -> Dict:
    """
    Worker function to process a single configuration.
    This runs in a separate process.
    
    Args:
        config: {
            'auth': str,
            'user': str,
            'policy': str,
            'aggregates_dir': Path,
            'user_dir': Path,
            'output_dir': Path,
            'api_key': str
        }
    
    Returns:
        Dict with processing results
    """
    auth = config['auth']
    user = config['user']
    policy = config['policy']
    aggregates_dir = Path(config['aggregates_dir'])
    user_dir = Path(config['user_dir'])
    output_dir = Path(config['output_dir'])
    api_key = config['api_key']
    
    config_name = f"{auth}/{user}/{policy}"
    
    try:
        print(f"\n[{config_name}]  Starting...")
        
        # Initialize OpenAI client in this process
        client = OpenAI(api_key=api_key)
        
        # Load hierarchical reconstruction
        reconstruction_file = aggregates_dir / "hierarchical_reconstruction.json"
        reconstruction = load_hierarchical_reconstruction(reconstruction_file)
        
        if not reconstruction:
            return {
                'config': config_name,
                'status': 'skipped',
                'reason': 'No reconstruction found'
            }
        
        # Load categorized data
        categorized_data = load_categorized_files(user_dir)
        
        if "UNCATEGORIZED" not in categorized_data:
            return {
                'config': config_name,
                'status': 'skipped',
                'reason': 'No UNCATEGORIZED to process'
            }
        
        # Extract records with UNCATEGORIZED
        records_with_uncat = extract_records_with_uncategorized(
            reconstruction,
            categorized_data
        )
        
        if not records_with_uncat:
            return {
                'config': config_name,
                'status': 'skipped',
                'reason': 'No records with UNCATEGORIZED'
            }
        
        print(f"[{config_name}] {len(records_with_uncat)} records with UNCATEGORIZED")
        
        # Available categories
        available_categories = get_available_categories()
        
        # Analyze in batches of 10 records
        batch_size = 10
        all_categorizations = []
        failed_batches = 0
        
        for batch_start in range(0, len(records_with_uncat), batch_size):
            batch_end = min(batch_start + batch_size, len(records_with_uncat))
            records_batch = records_with_uncat[batch_start:batch_end]
            
            print(f"[{config_name}] Batch [{batch_start+1}-{batch_end}/{len(records_with_uncat)}]...", end=" ")
            
            # Analyze the batch with retry logic
            batch_response = analyze_records_batch_with_ai(
                records_batch,
                user,
                available_categories,
                client,
                max_retries=5
            )
            
            if batch_response and "records" in batch_response:
                batch_results = batch_response["records"]
                all_categorizations.extend(batch_results)
                total_fields = sum(len(r.get("fields", [])) for r in batch_results)
                print(f"OK ({len(batch_results)} records, {total_fields} fields)")
            else:
                failed_batches += 1
                print("FAILED")
            
            # Rate limiting between batches (adaptive)
            if batch_end < len(records_with_uncat):
                # If we had recent failures, wait longer
                wait_time = 2.0 if failed_batches > 0 else 1.0
                time.sleep(wait_time)
        
        # Save AI categorizations
        print(f"[{config_name}]  Saving AI categorizations...")
        stats = save_ai_categorizations_intermediate(
            all_categorizations,
            output_dir
        )
        
        if failed_batches > 0:
            print(f"[{config_name}] Warning: Completed with {failed_batches} failed batches")
        
        print(f"[{config_name}] SUCCESS: Completed - {stats['total_records']} records, {stats['total_fields']} fields")
        
        return {
            'config': config_name,
            'status': 'success' if failed_batches == 0 else 'partial',
            'stats': stats,
            'failed_batches': failed_batches
        }
        
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"[{config_name}] Error: {e}")
        print(error_trace)
        return {
            'config': config_name,
            'status': 'error',
            'error': str(e),
            'traceback': error_trace
        }

# =====================================================================
# MAIN PARALLEL PROCESSING
# =====================================================================

def main():
    """Main entry point with parallel processing."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY missing")
        return

    base_dir = Path(__file__).resolve().parent.parent / "data"
    aggregates_base = base_dir / "aggregates" / "indexeddb"
    user_base = base_dir / "user"
    output_base = base_dir / "aggregates_ai_complete" / "indexeddb"
    
    print("=" * 80)
    print("AI CATEGORIZATION - INDEXEDDB (CONTEXT-AWARE - PARALLELIZED)")
    print("=" * 80)
    
    # Collect all configurations to process
    configurations = []
    users = ["FR_0446"]
    
    
    for auth in ["UnAuth"]:
        for user in users:
            for policy in ["ALL", "PARTIAL", "NONE"]:
                aggregates_dir = aggregates_base / auth / user / policy
                user_dir = user_base / auth / user / policy / "indexeddb"
                output_dir = output_base / auth / user / policy
                
                if not aggregates_dir.exists() or not user_dir.exists():
                    continue
                
                configurations.append({
                    'auth': auth,
                    'user': user,
                    'policy': policy,
                    'aggregates_dir': str(aggregates_dir),
                    'user_dir': str(user_dir),
                    'output_dir': str(output_dir),
                    'api_key': api_key
                })
    
    if not configurations:
        print("Warning: No configurations to process")
        return
    
    print(f"\nFound {len(configurations)} configurations to process")
    
    # Determine number of workers (limit to avoid overwhelming API)
    # Use fewer workers to reduce rate limit pressure
    num_workers = min(11, cpu_count(), len(configurations))  # Max 11 workers
    print(f"Using {num_workers} parallel workers (CPU cores: {cpu_count()})")
    print(f"Warning: Limited to 11 workers to avoid OpenAI rate limits")

    # Process configurations in parallel
    print(f"\n{'='*80}")
    print("STARTING PARALLEL PROCESSING")
    print(f"{'='*80}\n")
    
    start_time = time.time()
    
    with Pool(processes=num_workers) as pool:
        results = pool.map(process_single_configuration, configurations)
    
    elapsed_time = time.time() - start_time
    
    # Summary
    print(f"\n{'='*80}")
    print("PROCESSING SUMMARY")
    print(f"{'='*80}\n")
    
    success_count = sum(1 for r in results if r['status'] == 'success')
    partial_count = sum(1 for r in results if r['status'] == 'partial')
    skipped_count = sum(1 for r in results if r['status'] == 'skipped')
    error_count = sum(1 for r in results if r['status'] == 'error')
    
    total_records = 0
    total_fields = 0
    total_failed_batches = 0
    
    for result in results:
        if result['status'] in ['success', 'partial']:
            stats = result.get('stats', {})
            failed = result.get('failed_batches', 0)
            total_records += stats.get('total_records', 0)
            total_fields += stats.get('total_fields', 0)
            total_failed_batches += failed
            
            status_icon = "SUCCESS" if result['status'] == 'success' else "WARN"
            failed_info = f" ({failed} failed batches)" if failed > 0 else ""
            print(f"{status_icon} {result['config']}: {stats.get('total_records', 0)} records, {stats.get('total_fields', 0)} fields{failed_info}")
        elif result['status'] == 'skipped':
            print(f"SKIPPED {result['config']}: {result['reason']}")
        elif result['status'] == 'error':
            print(f"Error {result['config']}: {result['error']}")
    
    print(f"\n{'='*80}")
    print(f"Full Success: {success_count}")
    print(f"Partial Success: {partial_count}")
    print(f"Skipped: {skipped_count}")
    print(f"Errors: {error_count}")
    print(f" Total: {total_records} records, {total_fields} fields categorized")
    if total_failed_batches > 0:
        print(f"Warning: Total failed batches: {total_failed_batches}")
    print(f"  Time: {elapsed_time:.2f}s")
    print(f"{'='*80}")
    print("\n  Use redistribute_ai_categorizations.py to redistribute")

if __name__ == "__main__":
    main()