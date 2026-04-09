# PII Statistical Modeling & Privacy Risk Pipeline

Categorization, and statistical modeling of Personal Identifiable Information (PII) leakage in browser storage. 

This repository implements the end-to-end methodology for quantifying GDPR compliance risks through storage container analysis (PxI model).

---

## Technical Architecture & Orchestration

The codebase is organized into five hierarchical phases. Each phase can be executed independently via its respective `run_all.py` orchestrator, or sequentially via the global orchestrator.

###  Execution Flow

| Phase | Orchestrator | Primary Purpose | Key Output Directory |
|:--- |:--- |:--- |:--- |
| **1. Preprocessing** | `scripts/run_all.py` | Raw data cleaning & PII categorization | `data/user/` |
| **2. Analysis** | `analysis/run_all.py` | Profile-level lifecycle & security metrics | `analysis.json` |
| **3. Stat-Modeling** | `statistical_model/run_all.py` | Global aggregation & transition matrices | `results/aggregated_data/` |
| **4. GDPR Profiles** | `analysis_gdpr_profiles/run_all.py` | Profiling-based PII density analysis | `analysis_gdpr_profiles/reports/` |
| **5. Risk Analysis** | `risk_analysis_PxI/run_all.py` | Advanced risk quantification (PxI Model) | `data/reports/risk_statistics.json` |

---

## Getting Started


###  Phase-Specific Execution

#### Phase 1: Preprocessing & Categorization
Cleans raw browser traces and executes regex + AI-assisted PII categorization.
```bash
python scripts/run_all.py
```
*   **Input**: Raw storage files in `data/raw/`
*   **Results**: Categorized JSON files in `data/user/<auth>/<user>/<policy>/`

#### Phase 2: Consolidated Analysis
Computes security flags, lifetimes, and storage-specific metrics.
```bash
python analysis/run_all.py
```
*   **Results**: `analysis.json` per profile and `storage_analysis.json`.

#### Phase 3: Statistical Aggregation
Compiles results across all users for global research findings.
```bash
python statistical_model/run_all.py
```
*   **Results**: Global CSV tables in `results/summary_tables/`.

#### Phase 4: GDPR Profile Reporting
Generates high-level reproducible reports on PII density.
```bash
python analysis_gdpr_profiles/run_all.py
```
*   **Results**: `reproducibility_report.md` and summary statistics.

#### Phase 5: Risk Analysis (PxI Model)
Calculates technical Exposure (Pi), Impact (Ii), and final Risk Scores (Ri).
```bash
python risk_analysis_PxI/run_all.py
```
*   **Results**: Advanced boxplots in `risk_analysis_PxI/visualizations/` and stats in `data/reports/`.

---




### How to use the Data
1.  **Download**: Obtain the data folder from [Zenodo DOI Link].
2.  **Placement**: Extract the folder and  replace the root `data/` directory.

---

## Prerequisites
- Python 3.8+
- Requirements: `pip install -r requirements.txt` (NumPy, Pandas, Scikit-learn, Matplotlib, OpenAI).

##  License & Citation
This project is released under the **Open Science License**. 
