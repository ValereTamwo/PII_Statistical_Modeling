import sys
import os
import argparse

# Add the parent directory to sys.path to allow running as a script from within the package or outside
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from statistical_model.data_loader import load_all_data
from statistical_model.metrics import calculate_metrics
from statistical_model.stats_analysis import run_comprehensive_analysis
from statistical_model.visualization import generate_plots
from statistical_model.aggregation import create_aggregations

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='PII Statistical Modeling and Analysis')
    parser.add_argument('--aggregate', action='store_true', 
                       help='Run aggregation mode to consolidate data across users, policies, and modes')
    args = parser.parse_args()
    
    # Assume results directory is parallel to statistical_model directory
    # i.e. /path/to/project/results
    # and /path/to/project/statistical_model
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_path = os.path.join(base_dir, 'results')
    
    print(f"Base Directory: {base_dir}")
    print(f"Results Path: {results_path}")
    
    # Run aggregation mode if requested
    if args.aggregate:
        print("\n=== AGGREGATION MODE ===")
        output_path = os.path.join(base_dir, 'analysis_outputs', 'aggregations')
        create_aggregations(results_path, output_path)
        print(f"\nAggregation complete! Results saved to {output_path}")
        return
    
    print("\n[1/5] Loading data...")
    df = load_all_data(results_path)

    df.to_csv(os.path.join(base_dir, 'loaded_data.csv'), index=False)
    
    if df.empty:
        print("No data found! Please check the results directory structure.")
        return

    print(f"Loaded {len(df)} rows of data.")

    print("\n[2/5] Calculating metrics...")
    df = calculate_metrics(df)
    
    print("\n[3/5] Running Comprehensive Statistical Analysis...")
    
    # Analyze Exposure Score (primary metric)
    run_comprehensive_analysis(df, 'exposure_score')
    
    # Analyze Volume (secondary metric)
    run_comprehensive_analysis(df, 'pii_count')
    
    # Analyze Lifecycle metrics if they have variance
    if df['rate_modification'].std() > 0:
        run_comprehensive_analysis(df, 'rate_modification')
    else:
        print("\nSkipping Modification Rate Analysis: No variance")
    
    if df['rate_persistence'].std() > 0:
        run_comprehensive_analysis(df, 'rate_persistence')
    else:
        print("\nSkipping Persistence Analysis: No variance in persistence rate (likely all 0 or 1).")
    
    print("\n[4/5] Generating Visualizations...")
    output_dir = os.path.join(base_dir, 'analysis_outputs')
    generate_plots(df, output_dir)
    
    print(f"\n[5/5] Done. Check outputs in {output_dir}")

if __name__ == "__main__":
    main()
