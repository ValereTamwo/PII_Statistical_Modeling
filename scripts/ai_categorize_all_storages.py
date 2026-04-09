"""
AI CATEGORIZATION FOR COOKIES/STORAGE - PARALLELIZED VERSION

Parallel processing of UNCATEGORIZED items for cookies, localStorage, and sessionStorage.
One process per configuration to avoid conflicts and maximize CPU usage.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter
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

def get_item_id(item: Dict) -> str:
    """Generates a unique identifier for an item."""
    return str(
        item.get("field_path")
        or item.get("cookie_key")
        or item.get("key")
        or item.get("name")
    )

# =====================================================================
# TASK DISCOVERY
# =====================================================================

def discover_uncategorized_tasks(base_path: Path) -> List[Dict]:
    """
    Discovers all UNCATEGORIZED.json files in the data/user structure.
    Skips IndexedDB (has its own specialized pipeline).
    """
    tasks = []
    
    if not base_path.exists():
        return tasks
    
    for auth_dir in base_path.iterdir():
        if not auth_dir.is_dir():
            continue
        auth_mode = auth_dir.name
        
        for user_dir in auth_dir.iterdir():
            if not user_dir.is_dir():
                continue
            user_id = user_dir.name
            
            for policy_dir in user_dir.iterdir():
                if not policy_dir.is_dir():
                    continue
                policy = policy_dir.name
                
                for storage_dir in policy_dir.iterdir():
                    if not storage_dir.is_dir():
                        continue
                    storage_type = storage_dir.name
                    
                    # Skip IndexedDB (has its own specialized pipeline)
                    if storage_type == "indexeddb":
                        continue
                    
                    # For cookies, localstorage, sessionstorage
                    for lifecycle_dir in storage_dir.iterdir():
                        if not lifecycle_dir.is_dir():
                            continue
                        lifecycle = lifecycle_dir.name
                        
                        uncategorized_file = lifecycle_dir / "UNCATEGORIZED.json"
                        if uncategorized_file.exists():
                            tasks.append({
                                "auth": auth_mode,
                                "user": user_id,
                                "policy": policy,
                                "storage": storage_type,
                                "lifecycle": lifecycle,
                                "path": uncategorized_file
                            })
    
    return tasks

# =====================================================================
# PROMPT CONSTRUCTION
# =====================================================================

def build_batch_prompt(
    items_batch: List[Dict],
    storage_type: str,
    user_id: str,
    available_categories: List[str]
) -> str:
    """
    Builds a prompt for analyzing a batch of items.
    Aligned with IndexedDB prompt style but adapted for cookies/storage.
    """
    user_info = USER_PROFILES.get(user_id, {})
    
    # User context
    user_context = f"""
USER PROFILE (for DIRECT_PII detection):
{json.dumps(user_info, ensure_ascii=False, indent=2)}
"""
    
    # Items to categorize
    items_text = f"""
ITEMS TO CATEGORIZE ({len(items_batch)} items from {storage_type.upper()}):
"""
    
    for i, item in enumerate(items_batch, 1):
        key = item.get("key", item.get("name", item.get("cookie_key", "")))
        value = item.get("value", "")
        domain = item.get("domain", "N/A")
        
        # Check if it's a modified item
        is_modified = "value_from" in item
        
        items_text += f"""
ITEM {i}:
  Type: {storage_type}
  Key/Name: {key}
  Domain: {domain}
"""
        
        if is_modified:
            items_text += f"""  State: MODIFIED
  Old Value: {str(item.get("value_from"))[:150]}
  New Value: {str(value)[:500]}
"""
        else:
            items_text += f"""  Value: {str(value)[:500]}
"""
        
        # Additional cookie attributes
        if storage_type == "cookies":
            items_text += f"""  HttpOnly: {item.get("httpOnly", False)}
  Secure: {item.get("secure", False)}
  SameSite: {item.get("sameSite", "None")}
"""
        
        items_text += "---\n"
    
    prompt = f"""[SYSTEM: ROLE = GDPR_STORAGE_EXPERT]

{user_context}

{format_categories_with_details()}

{items_text}

TASK:
Analyze the {len(items_batch)} items above from {storage_type.upper()}.
For each item, determine the appropriate category.

STRICT RULES:
- You MUST select exactly ONE category from the provided list.
- You MUST NOT infer intent, user behavior, or legal meaning beyond explicit evidence.
- You MUST NOT use external knowledge or assumptions.
- If there is insufficient evidence, choose UNCATEGORIZED.
- You MUST provide a short, factual explanation based only on:
  - key/cookie name
  - value format
  - domain context
  - immediate technical context

CATEGORIZATION GUIDELINES:
1. If the VALUE contains user profile data  DIRECT_PII
2. If it's a tracking identifier (UUID, hash, ID)  IDENTITY_TRACKING
3. If it's behavioral data (clicks, views, session tracking)  BEHAVIORAL_DATA
4. If it's a configuration/preference  USER_PREFERENCES
5. If it's a technical counter (version, sequence)  INFRASTRUCTURE
6. If no clear evidence  keep UNCATEGORIZED

RESPOND IN JSON ONLY:
{{
  "items": [
    {{
      "item_number": 1,
      "key": "exact key/name from item",
      "category": "CATEGORY_NAME or UNCATEGORIZED",
      "confidence": 0.0-1.0,
      "explanation": "Technical evidence based on key/value/domain"
    }}
  ]
}}
"""
    
    return prompt

# =====================================================================
# AI ANALYSIS WITH RETRY
# =====================================================================

def analyze_batch_with_ai(
    items_batch: List[Dict],
    storage_type: str,
    user_id: str,
    available_categories: List[str],
    client: OpenAI,
    max_retries: int = 5
) -> Optional[Dict]:
    """
    Analyzes a batch of items with AI using retry logic.
    """
    prompt = build_batch_prompt(items_batch, storage_type, user_id, available_categories)
    
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
                        "content": prompt
                    }
                ]
            )
            
            response = json.loads(completion.choices[0].message.content)
            return response
            
        except RateLimitError as e:
            wait_time = 2 ** attempt
            print(f"      Rate limit hit (attempt {attempt+1}/{max_retries}), waiting {wait_time}s...")
            
            if attempt < max_retries - 1:
                time.sleep(wait_time)
            else:
                print(f"     Max retries reached, batch failed")
                return None
                
        except APIError as e:
            wait_time = 2 ** attempt
            print(f"      API Error: {e} (attempt {attempt+1}/{max_retries}), waiting {wait_time}s...")
            
            if attempt < max_retries - 1:
                time.sleep(wait_time)
            else:
                print(f"     Max retries reached, batch failed")
                return None
                
        except Exception as e:
            print(f"     Unrecoverable error: {e}")
            return None
    
    return None

# =====================================================================
# SAVE CATEGORIZED ITEMS
# =====================================================================

def save_categorized_items(
    items_batch: List[Dict],
    analyses: List[Dict],
    file_path: Path,
    storage_type: str
):
    """
    Saves categorized items to appropriate category files.
    """
    output_dir = file_path.parent
    keep_uncat = []
    
    # Create mapping of analyses by item key
    analysis_map = {}
    for analysis in analyses:
        item_num = analysis.get("item_number", 0)
        if 1 <= item_num <= len(items_batch):
            analysis_map[item_num] = analysis
    
    for i, original in enumerate(items_batch, 1):
        analysis = analysis_map.get(i, {})
        cat = analysis.get("category", "UNCATEGORIZED")
        
        enriched = original.copy()
        enriched["ai_processed"] = True
        enriched["ai_categorized"] = True
        enriched["ai_confidence"] = analysis.get("confidence", 0.0)
        enriched["ai_explanation"] = analysis.get("explanation", "")
        
        if cat != "UNCATEGORIZED":
            # Format specific attributes
            if storage_type == "cookies":
                enriched.update({
                    "matched_subcategory": "ai_refined",
                    "match_type": "llm_context"
                })
            else:
                enriched.update({
                    "_primary_category": cat,
                    "_matched_subcategory": "ai_refined"
                })
            
            # Save to category file
            target_file = output_dir / f"{cat}.json"
            data = []
            
            if target_file.exists():
                try:
                    with open(target_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except:
                    data = []
            
            data.append(enriched)
            
            with open(target_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            keep_uncat.append(enriched)
    
    # Clean UNCATEGORIZED file
    with open(file_path, "r", encoding="utf-8") as f:
        full_list = json.load(f)
    
    batch_ids = {get_item_id(x) for x in items_batch}
    new_uncat = [x for x in full_list if get_item_id(x) not in batch_ids]
    new_uncat.extend(keep_uncat)
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(new_uncat, f, indent=2, ensure_ascii=False)

# =====================================================================
# WORKER FUNCTION FOR PARALLEL PROCESSING
# =====================================================================

def process_single_configuration(config: Dict) -> Dict:
    """
    Worker function to process a single configuration.
    This runs in a separate process.
    """
    auth = config['auth']
    user = config['user']
    policy = config['policy']
    storage = config['storage']
    lifecycle = config['lifecycle']
    file_path = Path(config['path'])
    api_key = config['api_key']
    
    config_name = f"{auth}/{user}/{policy}/{storage}/{lifecycle}"
    
    try:
        print(f"\n[{config_name}] Starting...")
        
        # Initialize OpenAI client in this process
        client = OpenAI(api_key=api_key)
        
        # Load items
        with open(file_path, "r", encoding="utf-8") as f:
            all_items = json.load(f)
        
        # Filter items not yet processed
        items_to_do = [x for x in all_items if not x.get("ai_processed")]
        
        if not items_to_do:
            return {
                'config': config_name,
                'status': 'skipped',
                'reason': 'All items already processed'
            }
        
        print(f"[{config_name}] {len(items_to_do)} items to process")
        
        # Available categories
        available_categories = get_available_categories()

        # Analyze in batches of 10 items
        batch_size = 10
        all_categorizations = []
        failed_batches = 0
        
        for batch_start in range(0, len(items_to_do), batch_size):
            batch_end = min(batch_start + batch_size, len(items_to_do))
            items_batch = items_to_do[batch_start:batch_end]
            
            print(f"[{config_name}] Batch [{batch_start+1}-{batch_end}/{len(items_to_do)}]...", end=" ")
            
            # Analyze the batch with retry logic
            batch_response = analyze_batch_with_ai(
                items_batch,
                storage,
                user,
                available_categories,
                client,
                max_retries=5
            )
            
            if batch_response and "items" in batch_response:
                analyses = batch_response["items"]
                
                if len(analyses) == len(items_batch):
                    save_categorized_items(items_batch, analyses, file_path, storage)
                    all_categorizations.extend(analyses)
                    print(f"OK ({len(analyses)} items)")
                else:
                    failed_batches += 1
                    print(f"FAILED (expected {len(items_batch)}, got {len(analyses)})")
            else:
                failed_batches += 1
                print("FAILED")
            
            # Rate limiting between batches
            if batch_end < len(items_to_do):
                wait_time = 2.0 if failed_batches > 0 else 1.0
                time.sleep(wait_time)
        
        # Statistics
        stats = {
            "total_processed": len(all_categorizations),
            "categories_distribution": Counter()
        }
        
        for analysis in all_categorizations:
            category = analysis.get("category", "UNCATEGORIZED")
            stats["categories_distribution"][category] += 1
        
        if failed_batches > 0:
            print(f"[{config_name}] Completed with {failed_batches} failed batches")
        
        print(f"[{config_name}] Completed - {stats['total_processed']} items categorized")
        
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
        print(" OPENAI_API_KEY missing")
        return

    base_path = Path(__file__).resolve().parent.parent / "data" / "user"
    
    print("=" * 80)
    print("AI CATEGORIZATION - COOKIES/STORAGE (PARALLELIZED)")
    print("=" * 80)
    
    # Discover all tasks
    print("\nDiscovering UNCATEGORIZED files...")
    raw_tasks = discover_uncategorized_tasks(base_path)
    
    if not raw_tasks:
        print("No UNCATEGORIZED files to process")
        return
    
    print(f"Found {len(raw_tasks)} UNCATEGORIZED files")
    
    # Prepare configurations for parallel processing
    configurations = []
    for task in raw_tasks:
        configurations.append({
            'auth': task['auth'],
            'user': task['user'],
            'policy': task['policy'],
            'storage': task['storage'],
            'lifecycle': task['lifecycle'],
            'path': str(task['path']),
            'api_key': api_key
        })
    
    # Determine number of workers (limit to avoid overwhelming API)
    num_workers = min(11, cpu_count(), len(configurations))
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
    
    total_items = 0
    total_failed_batches = 0
    global_categories = Counter()
    
    for result in results:
        if result['status'] in ['success', 'partial']:
            stats = result.get('stats', {})
            failed = result.get('failed_batches', 0)
            total_items += stats.get('total_processed', 0)
            total_failed_batches += failed
            global_categories.update(stats.get('categories_distribution', {}))
            
            status_icon = "SUCCESS" if result['status'] == 'success' else "WARN"
            failed_info = f" ({failed} failed batches)" if failed > 0 else ""
            print(f"{status_icon} {result['config']}: {stats.get('total_processed', 0)} items{failed_info}")
        elif result['status'] == 'skipped':
            print(f"  {result['config']}: {result['reason']}")
        elif result['status'] == 'error':
            print(f"Error {result['config']}: {result['error']}")
    
    print(f"\n{'='*80}")
    print(f" Full Success: {success_count}")
    print(f"  Partial Success: {partial_count}")
    print(f"  Skipped: {skipped_count}")
    print(f" Errors: {error_count}")
    print(f" Total items categorized: {total_items}")
    if total_failed_batches > 0:
        print(f"  Total failed batches: {total_failed_batches}")
    
    if global_categories:
        print(f"\n Category distribution (top 10):")
        for cat, count in global_categories.most_common(10):
            pct = count / total_items * 100 if total_items > 0 else 0
            print(f"  {cat}: {count} ({pct:.1f}%)")
    
    print(f"\nTotal time: {elapsed_time:.2f}s")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()