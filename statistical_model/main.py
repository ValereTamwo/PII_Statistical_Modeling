import sys
import os
import argparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from statistical_model.data_loader import load_all_data
from statistical_model.metrics import calculate_metrics
from statistical_model.aggregation import create_aggregations

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='PII Statistical Modeling and Analysis')
    parser.add_argument('--aggregate', action='store_true', 
                       help='Run aggregation mode to consolidate data across users, policies, and modes')
    args = parser.parse_args()
    

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
    
    print("\n Loading data...")
    df = load_all_data(results_path)

    df.to_csv(os.path.join(base_dir, 'loaded_data.csv'), index=False)
    
    if df.empty:
        print("No data found! Please check the results directory structure.")
        return

    print(f"Loaded {len(df)} rows of data.")

    print("\n Calculating metrics...")
    df = calculate_metrics(df)
    df.to_csv(os.path.join(base_dir, 'data_with_metrics.csv'), index=False)

if __name__ == "__main__":
    main()
