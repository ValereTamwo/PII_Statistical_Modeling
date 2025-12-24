import seaborn as sns
import matplotlib.pyplot as plt
import os

def generate_plots(df, output_dir='.'):
    """
    Generate and save visualizations:
    1. Interaction Plot (Policy x Auth)
    2. Boxplot (Storage x Policy)
    3. Correlation Matrix
    """
    sns.set_theme(style="whitegrid")
    
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 1. Interaction Plot (H3)
    try:
        plt.figure(figsize=(10, 6))
        sns.pointplot(data=df, x='policy', y='exposure_score', hue='auth', capsize=.1, palette='Set2')
        plt.title('Interaction Effect: Policy x Auth on Exposure Score')
        plt.savefig(os.path.join(output_dir, 'interaction_plot.png'))
        plt.close()
        print(f"Saved interaction_plot.png to {output_dir}")
    except Exception as e:
        print(f"Error generating interaction plot: {e}")
    
    # 2. Main Effects (H1, H5)
    try:
        plt.figure(figsize=(12, 6))
        sns.boxplot(data=df, x='storage', y='exposure_score', hue='policy')
        plt.title('Exposure Score by Storage and Policy')
        plt.savefig(os.path.join(output_dir, 'storage_policy_boxplot.png'))
        plt.close()
        print(f"Saved storage_policy_boxplot.png to {output_dir}")
    except Exception as e:
        print(f"Error generating boxplot: {e}")
    
    # 3. Correlation Matrix
    try:
        numeric_cols = ['l_added', 'l_modified', 'l_deleted', 'pii_count', 'exposure_score', 'rate_modification', 'rate_persistence']
        # Filter only existing columns
        cols_to_use = [c for c in numeric_cols if c in df.columns]
        
        corr = df[cols_to_use].corr()
        plt.figure(figsize=(10, 8))
        sns.heatmap(corr, annot=True, cmap='coolwarm', vmin=-1, vmax=1)
        plt.title('Correlation Matrix of Metrics')
        plt.savefig(os.path.join(output_dir, 'correlation_matrix.png'))
        plt.close()
        print(f"Saved correlation_matrix.png to {output_dir}")
    except Exception as e:
        print(f"Error generating correlation matrix: {e}")
