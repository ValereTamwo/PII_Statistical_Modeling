# Country-Extension Classification Pipeline

Reproduction guide for the PII classification pipeline covering the 6
country personas (`IT_0573`, `LU_0634`, `PT_0838`, `SE_0964`, `ES_0290`,
`DE_0018`), each under two authentication states (`AUTH` / `NOTAUTH`) and a
single consent policy (`PARTIAL`).




## Pipeline stages

Stage numbers below match what `scripts_countries/run_all.py` itself
prints to the console (it starts at Stage 2, reserving Stage 1 for
preprocessing, which it doesn't run). Each stage reads the previous
stage's output. `run_all.py` automates Stages 2–6 in one command; Stage 1
and Stages 7–8 are separate, manual steps (see "Quick start" below).

### Stage 1 — Preprocessing

Extracts raw cookies/localStorage/sessionStorage/IndexedDB captures per
persona into a normalized structure.

```
python3 preprocessing_countries/run_all.py
```

- Reads: `data/Countries_data/Users/{user}/...`
- Writes: `data/preprocessing_countries/{AUTH|NOTAUTH}/{user}/PARTIAL/{storage}/...`

### Stage 2 — Regex-based categorization

Labels items into PII categories using `regex_merged_v3.py`'s patterns
(literal ground-truth matches for the personas' identity fields, plus
generic tracking-keyword patterns).

```
python3 scripts_countries/categorize_cookies.py
python3 scripts_countries/categorize_localstorage.py
python3 scripts_countries/categorize_indexeddb.py
```

- Reads: `data/preprocessing_countries/...`
- Writes: `data/user_countries/{AUTH|NOTAUTH}/{user}/PARTIAL/{storage}/[{lifecycle}/]{CATEGORY}.json`
- Anything not matched lands in `UNCATEGORIZED.json` in the same folder.

### Stage 3 — Cleaning

Filters IndexedDB structural noise and removes known false positives
(e.g. `1.1.*`-style IP false positives, timestamp-key false positives).

```
python3 scripts_countries/clean_idb.py
python3 scripts_countries/clean_pii.py
```

- Reads/writes `data/user_countries/...` in place.
- Also writes removed false positives to `data_false_positives_countries/`.

### Stage 4 — IndexedDB aggregation

Builds per-record PII cards and a hierarchical field reconstruction, used
as context by the IndexedDB AI pass in Stage 5.

```
python3 scripts_countries/aggregate_indexeddb.py
```

- Reads: `data/user_countries/{AUTH|NOTAUTH}/{user}/PARTIAL/indexeddb/*.json`
- Writes: `data/aggregates_countries/indexeddb/{AUTH|NOTAUTH}/{user}/PARTIAL/*.json`
  (`hierarchical_reconstruction.json` is the one later stages depend on)
- **Hard prerequisite for Stage 5's IndexedDB pass** — nothing to review without it.

### Stage 5 — AI categorization (needs `OPENAI_API_KEY`)

Sends whatever Stage 2 left `UNCATEGORIZED` through an LLM pass
(`gpt-4.1-mini`). Cookies/localStorage/sessionStorage and IndexedDB use
separate scripts because IndexedDB needs the Stage 4 record context.

```
OPENAI_API_KEY=sk-... python3 scripts_countries/ai_categorize_all_storages.py
OPENAI_API_KEY=sk-... python3 scripts_countries/ai_parallel_indexededdb.py
```

- Reads: `UNCATEGORIZED.json` (+ `hierarchical_reconstruction.json` for IndexedDB)
- Writes: recategorized items directly into `data/user_countries/.../{storage}` (cookies/LS/SS)
  and an intermediate `data/aggregates_ai_complete_countries/indexeddb/{AUTH|NOTAUTH}/{user}/PARTIAL/ai_categorizations.json` (IndexedDB — not yet merged)
- **Known limitation**: IndexedDB records with 50+ uncategorized fields can
  exceed the model's per-response output limit; overflow fields are
  silently dropped from `ai_categorizations.json`. Stage 7 recovers these.

### Stage 6 — Redistribution & finalization

Merges the IndexedDB AI results into real category files, then moves
whatever is still `UNCATEGORIZED`/`INTERNAL_IDB_KEYS` out of the working
tree.

```
python3 scripts_countries/redistribute_ai_categorizations.py
python3 scripts_countries/clean_user_folder.py
```

- Writes: `data/user_countries/...` (now the finalized categorized state
  for this pass)
- `clean_user_folder.py` moves `UNCATEGORIZED.json` /
  `INTERNAL_IDB_KEYS.json` to `data/user_countries_raws/` — treat
  `data/user_countries/` as frozen input from here down.
- **Note**: `redistribute_ai_categorizations.py` does not remove
  successfully-recategorized fields from `UNCATEGORIZED.json` before it's
  moved — this is a known, intentional-by-inheritance quirk from the FR
  original. It means a small fraction of `UNCATEGORIZED.json` entries are
  stale duplicates of items that actually did get categorized; Stage 7's
  redistribution step does clean this up for the fields it touches.

**Stages 2–6 above are automated end-to-end by:**
```
OPENAI_API_KEY=sk-... python3 scripts_countries/run_all.py
```
(run Stage 1 separately first — `run_all.py` does not run preprocessing)

### Stage 7 — AI IndexedDB truncation correction (needs `OPENAI_API_KEY`, optional but recommended)

Finds the exact fields Stage 5 silently dropped (identified as a pure
diff — no API calls needed for this part) and re-queries just those,
batched by field count instead of by record so no single call can ever
overflow again.

```
OPENAI_API_KEY=sk-... python3 scripts_countries/ai_indexeddb_correction.py
python3 scripts_countries/redistribute_ai_categorizations_correction.py
```

- Writes: `data/aggregates_ai_complete_countries/indexeddb/{AUTH|NOTAUTH}/{user}/PARTIAL/ai_categorizations_correction.json`,
  then merges into `data/user_countries/.../indexeddb/{CATEGORY}.json` and
  **does** clean the corresponding entries out of
  `data/user_countries_raws/.../UNCATEGORIZED.json`.
- If any config comes back `PARTIAL` (a chunk hit an unrecoverable API
  error), just re-run both scripts — already-resolved fields are safely
  skipped (they're already gone from `UNCATEGORIZED.json`), so a re-run
  only costs API calls for the genuine remainder.
- Original Stage 5/6 scripts are never modified by this stage.

### Stage 8 — Post-AI regex correction (no API needed)

Final catch-all: a small, hand-audited set of regex rules
(`regex_post_ai_correction.py`) targeting third-party SDK field-naming
schemes (YouTube's log_event queue, OneSignal push IDs, session-replay
recorders, ad-demographic targeting tags, freshchat visitor tracking,
etc.) that neither Stage 2's general patterns nor the AI passes had
coverage for. Each rule matches on the full `field_path` (not just the
leaf key) to stay high-precision.

```
python3 scripts_countries/dry_run_regex_post_ai_correction.py   # read-only preview
python3 scripts_countries/apply_regex_post_ai_correction.py     # writes the result
```

- `dry_run_...` prints per-rule match counts + samples and modifies
  nothing — review before applying.
- `apply_...` moves matches directly into the right category file and
  removes them from `UNCATEGORIZED.json`.
- **This is the last stage.** Whatever remains in `UNCATEGORIZED.json`
  after this is treated as final, accepted uncategorized data — no
  further correction passes are planned on top of it.

## Quick start (full sequence from scratch)

```bash
python3 preprocessing_countries/run_all.py

OPENAI_API_KEY=sk-... python3 scripts_countries/run_all.py   # Stages 2-6

OPENAI_API_KEY=sk-... python3 scripts_countries/ai_indexeddb_correction.py
python3 scripts_countries/redistribute_ai_categorizations_correction.py

python3 scripts_countries/dry_run_regex_post_ai_correction.py
python3 scripts_countries/apply_regex_post_ai_correction.py
```

## What's out of scope here

- **Sensitivity analysis** on the risk-scoring weights — explicitly
  deferred, not part of this classification pipeline.
- **The FR pipeline** — `scripts/`, `data/user/`, `analysis/`,
  `analysis_gdpr_profiles/`, `risk_analysis_PxI/` are untouched by
  anything in this folder.

## Where the output goes next

Once this pipeline finishes, `data/user_countries/` is the input for the
downstream analysis pipelines (separate folders, not covered by this
README): `analysis_countries/` (cookie/storage/security stats),
`analysis_gdpr_profiles_countries/` (per-country PII aggregation + report),
and `risk_analysis_PxI_countries/` (exposure/impact/risk scoring). See
`scripts_countries/pipeline_map.html` (publish via the Artifact tool, or
open directly) for a visual map of the categorization stages above.
