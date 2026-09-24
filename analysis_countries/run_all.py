"""
GLOBAL ORCHESTRATOR FOR PROFILE-LEVEL ANALYSIS - country extension.

Adapted from analysis/run_all.py: same execution order (cookie consolidated
+ lifecycle, then storage consolidated + lifecycle), but runs the
analysis_countries/ scripts (data/user_countries/, results_countries/)
instead of analysis/'s FR-only scripts.
"""

import sys
import subprocess
from pathlib import Path

ANALYSIS_DIR = Path(__file__).resolve().parent

sys.path.insert(0, str(ANALYSIS_DIR.parent))
from countries_config import add_users_arg


def run_script(script_path, description, use_module=False, extra_args=None):
    print(f"\n" + "="*80)
    print(f" STEP: {description}")
    print(f" Executing: {script_path.name}")
    print("="*80)

    if not script_path.exists():
        print(f" Error: {script_path.name} not found in {script_path.parent}")
        return False

    try:
        if use_module:
            project_root = ANALYSIS_DIR.parent
            module_path = script_path.relative_to(project_root).with_suffix('')
            module_name = ".".join(module_path.parts)

            result = subprocess.run(
                [sys.executable, "-m", module_name] + (extra_args or []),
                cwd=project_root,
                check=True
            )
        else:
            result = subprocess.run(
                [sys.executable, str(script_path)] + (extra_args or []),
                cwd=script_path.parent,
                check=True
            )

        return result.returncode == 0

    except subprocess.CalledProcessError as e:
        print(f" Error executing {script_path.name}: {e}")
        return False
    except Exception as e:
        print(f" Unexpected error: {e}")
        return False


def main(extra_args=None):
    print("\n" + "#"*80)
    print("#" + " "*18 + "COUNTRY PROFILE-LEVEL ANALYSIS RUNNER" + " "*20 + "#")
    print("#"*80)
    if extra_args:
        print(f"Forwarding extra args to every stage: {extra_args}")

    print("\n--- PHASE 1: COOKIE ANALYSIS ---")
    run_script(ANALYSIS_DIR / "consolidated_analysis.py", "Cookie Consolidated Analysis", extra_args=extra_args)
    run_script(ANALYSIS_DIR / "lifecycle_analysis.py", "Cookie Lifecycle Analysis", extra_args=extra_args)

    print("\n--- PHASE 2: STORAGE ANALYSIS ---")
    storage_dir = ANALYSIS_DIR / "storage_analysis"
    run_script(
        storage_dir / "storage_consolidated_analysis.py",
        "Other Storages Consolidated Analysis",
        use_module=True,
        extra_args=extra_args
    )

    run_script(
        storage_dir / "storage_lifecycle_analysis.py",
        "Other Storages Lifecycle Analysis",
        use_module=True,
        extra_args=extra_args
    )

    print("\n" + "#"*80)
    print("#" + " "*24 + "ANALYSIS PIPELINE COMPLETED" + " "*27 + "#")
    print("#"*80 + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    extra_args = ["--users", args.users] if args.users else []
    main(extra_args=extra_args)
