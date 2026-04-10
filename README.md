# PII Privacy Risk Pipeline

Statistical modeling and GDPR compliance risk quantification of Personal Identifiable Information (PII) leakage in browser storage, based on the **PxI model** (Probability × Impact).

This repository provides an end-to-end pipeline — from raw browser trace categorization to advanced risk scoring across storage containers. It constitutes our model for studying real-world PII exposure under realistic browsing conditions.

---

## Overview

The pipeline is organized into **five sequential phases**, each independently executable via its own `run_all.py` orchestrator:

| Phase | Module | Purpose | Primary Output |
|:--|:--|:--|:--|
| **1 — Preprocessing** | `preprocessing/`&`scripts/`  | Raw trace structuring & PII categorization (regex + AI) | `preprocessing/` (nested added/modifed/delete per user config) & `data/user/` |
| **2 — Analysis** | `analysis/` | Per-profile lifecycle, security flags & storage metrics | `results/` (nested `analysis.json`) |
| **3 — Statistical Modeling** | `statistical_model/` | Cross-user aggregation & transition matrices | `results/aggregated_data/summary_tables/` |
| **4 — PII Profiles** | `analysis_gdpr_profiles/` | PII density reporting  | `analysis_gdpr_profiles/reports/` |
| **5 — Risk Analysis** | `risk_analysis_PxI/` | PxI risk scores (Pᵢ, Iᵢ, Rᵢ) per storage item | `risk_analysis_PxI/src/outputs/figures/` |

---

## Quick Start (Recommended)

The repository ships with a pre-computed `data.tar.xz` archive at the root, containing the **complete output of Phase 1** — i.e., all browser traces cleaned and categorized via both regex and AI-assisted pipelines. This allows immediate reproduction of the published results without re-running the categorization step.

### Step 1 — Extract the pre-computed data

```bash
tar -xf data.tar.xz
```

This populates the root `data/` directory with all categorized JSON files produced by Phase 1.

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Run Phases 2 through 5

```bash
python analysis/run_all.py
python statistical_model/run_all.py
python analysis_gdpr_profiles/run_all.py
python risk_analysis_PxI/run_all.py
```

---

## Full Reproduction from Phase 1

To re-execute the **complete pipeline from raw browser traces**, including PII categorization, run Phase 1 prior to the steps above:

```bash
python scripts/run_all.py
```

> [Warn] **This step is time-intensive.** The AI-assisted categorization sub-pipeline issues calls to the OpenAI API. A valid API key must be set in your environment before execution:
>
> ```bash
> export OPENAI_API_KEY="sk-..."
> ```
>
> The regex-based categorization path runs without an API key, but results will diverge from the published dataset.

**Input:** Raw storage dump files in `data/raw/`  
**Output:** Categorized JSON files in `data/user/<auth>/<user>/<policy>/`

Once Phase 1 completes, proceed with Steps 2–5 from the Quick Start section.

---

## Phase Reference

### Phase 2 — Consolidated Analysis
```bash
python analysis/run_all.py
```
Computes per-profile security flags, cookie and storage entry lifetimes, and storage-type-specific behavioral metrics.  
**Output:** Deeply nested `analysis.json` and `storage_analysis.json` inside the `results/` hierarchy (e.g., `results/Auth/FR_0417/ALL/cookies/added/consolidated/analysis.json`).

### Phase 3 — Statistical Aggregation
```bash
python statistical_model/run_all.py
```
Aggregates results across all user profiles, computes global transition matrices, and produces cross-user summary statistics for reporting.  
**Output:** Detailed JSONs in `results/aggregated_data/` and summary CSV tables in `results/aggregated_data/summary_tables/`.

### Phase 4 — GDPR Profile Reporting
```bash
python analysis_gdpr_profiles/run_all.py
```
Generates reproducible, high-level reports on PII density stratified by profile category.  
**Output:** `reproducibility_report.txt` and aggregate statistics in `analysis_gdpr_profiles/reports/`.

### Phase 5 — Risk Analysis (PxI Model)
```bash
python risk_analysis_PxI/run_all.py
```
Computes technical Exposure scores (Pᵢ), Impact scores (Iᵢ), and composite Risk scores (Rᵢ) per storage container and user profile, following the PxI methodology.  
**Output:** Boxplot visualizations in `risk_analysis_PxI/src/outputs/figures/` and full risk statistics in `risk_analysis_PxI/src/reports/risk_statistics.json`.

---

## Prerequisites

- **Python** 3.8+
- **Dependencies:** NumPy, Pandas, Scikit-learn, Matplotlib, OpenAI
```bash
  pip install -r requirements.txt
```
- **OpenAI API key** *(Phase 1 AI categorization only)*: set `OPENAI_API_KEY` in your environment.

---

## Related Artifacts

This repository is part of a broader experimental ecosystem. The following companion artifacts help reproduce the experimental setup or to re-collect raw data from scratch:

| Artifact | Description | Link |
|:--|:--|:--|
| **XArena** | Automated browser crawler used to collect raw storage traces under controlled browsing sessions | [GitHub — XArena]([PLACEHOLDER_XARENA_URL]) |
| **Site Classification Module** | Categorizes target websites by content type and GDPR relevance; produces the browsing task lists consumed by XArena | [GitHub — Site Classifier]([PLACEHOLDER_CLASSIFIER_URL]) |
| **Virtual Persona System** | Generates synthetic user personas with demographic and behavioral profiles used to drive XArena browsing sessions | [GitHub — Persona System]([PLACEHOLDER_PERSONA_SYSTEM_URL]) |
| **Persona Dataset** | Full dataset of virtual personas used in the study, including demographic attributes and assigned behavioral parameters | [Dataset]([PLACEHOLDER_PERSONA_DATA_URL]) |
| **Persona-to-Site Assignments** | Mapping of virtual personas to their attributed website sets, defining the browsing scope for each experimental subject | [Dataset]([PLACEHOLDER_SITE_ASSIGNMENTS_URL]) |

---

## License & Citation

This project is released under the **Open Science License**.

<!-- If you use this pipeline or dataset in your research, please cite:

```bibtex
@misc{[PLACEHOLDER_CITE_KEY],
  title  = {PII Statistical Modeling \& Privacy Risk Pipeline},
  author = {[PLACEHOLDER_AUTHORS]},
  year   = {[PLACEHOLDER_YEAR]},
  url    = {[PLACEHOLDER_REPO_URL]}
}
``` -->