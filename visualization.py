import matplotlib
matplotlib.use('Agg')  # Set the backend to non-interactive 'Agg'
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime
import os
import logging

logger = logging.getLogger(__name__)

def normalize_metric(series):
    """Normalize a metric to 0-1 scale"""
    min_val = series.min()
    max_val = series.max()
    if max_val == min_val:
        return pd.Series([0.5] * len(series))
    return (series - min_val) / (max_val - min_val)

def create_scatter_plots(df, output_dir):
    """Create PSNR vs File Size and SSIM vs Capacity scatter plots"""
    try:
        if df.empty or not all(col in df.columns for col in ['file_size', 'psnr', 'capacity', 'ssim']):
            logger.warning("DataFrame is empty or missing required columns for scatter plots.")
            plt.figure(figsize=(15, 6))
            plt.text(0.5, 0.5, 'Insufficient data for Scatter Plots', ha='center', va='center')
            plt.axis('off')
            output_path = os.path.join(output_dir, 'scatter_plots.png')
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            return True

        plt.figure(figsize=(15, 6))
        # PSNR vs File Size
        plt.subplot(1, 2, 1)
        sns.scatterplot(data=df, x='file_size', y='psnr')
        plt.title('PSNR vs File Size')
        plt.xlabel('File Size (KB)')
        plt.ylabel('PSNR (dB)')
        # SSIM vs Capacity
        plt.subplot(1, 2, 2)
        sns.scatterplot(data=df, x='capacity', y='ssim')
        plt.title('SSIM vs Capacity')
        plt.xlabel('Capacity (bits)')
        plt.ylabel('SSIM')
        plt.tight_layout()
        output_path = os.path.join(output_dir, 'scatter_plots.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        return True
    except Exception as e:
        logger.error(f"Error creating scatter plots: {e}")
        return False

def create_radar_chart(df, output_dir):
    """Create radar chart for overall performance profile"""
    try:
        if df.empty or not all(col in df.columns for col in ['psnr', 'ssim', 'capacity', 'ber']):
            logger.warning("DataFrame is empty or missing required columns for radar chart.")
            plt.figure(figsize=(8, 8))
            plt.text(0.5, 0.5, 'Insufficient data for Radar Chart', ha='center', va='center')
            plt.axis('off')
            output_path = os.path.join(output_dir, 'radar_chart.png')
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            return True

        means = {
            'PSNR': df['psnr'].mean(),
            'SSIM': df['ssim'].mean(),
            'Capacity': df['capacity'].mean(),
            'Success': 1 - df['ber'].mean()
        }
        max_vals = {'PSNR': 50, 'SSIM': 1, 'Capacity': df['capacity'].max() or 1, 'Success': 1}
        values = [means[m] / max_vals[m] for m in means.keys()]
        angles = np.linspace(0, 2*np.pi, len(means), endpoint=False)
        values = np.concatenate((values, [values[0]]))
        angles = np.concatenate((angles, [angles[0]]))
        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(projection='polar'))
        ax.plot(angles, values, 'o-')
        ax.fill(angles, values, alpha=0.25)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(means.keys())
        plt.title('Performance Profile Radar Chart')
        output_path = os.path.join(output_dir, 'radar_chart.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        return True
    except Exception as e:
        logger.error(f"Error creating radar chart: {e}")
        return False

def create_multi_metric_line(df, output_dir):
    """Create multi-metric line graph with normalized values"""
    try:
        if df.empty or not all(col in df.columns for col in ['psnr', 'ssim', 'ber', 'capacity']):
             logger.warning("DataFrame is empty or missing required metric columns for multi-metric line graph.")
             # Create an empty plot or return False
             plt.figure(figsize=(12, 6))
             plt.text(0.5, 0.5, 'Insufficient data for Multi-Metric Line Graph', ha='center', va='center')
             plt.axis('off')
             plt.tight_layout()
             output_path = os.path.join(output_dir, 'multi_metric_line.png')
             plt.savefig(output_path, dpi=300, bbox_inches='tight')
             plt.close()
             return True # Saved a placeholder

        plt.figure(figsize=(12, 6))

        df_norm = df.copy()
        metrics_to_normalize = ['psnr', 'ssim', 'capacity']
        normalized_labels = {'psnr': 'Norm PSNR', 'ssim': 'Norm SSIM', 'capacity': 'Norm Capacity'}

        # Normalize metrics where range exists
        for col in metrics_to_normalize:
            min_val, max_val = df_norm[col].min(), df_norm[col].max()
            if max_val > min_val:
                df_norm[col + '_norm'] = (df_norm[col] - min_val) / (max_val - min_val)
            else:
                df_norm[col + '_norm'] = 0.5 # Assign mid-value if all values are the same

        # Normalize Success Rate (1 - BER)
        df_norm['success_rate'] = 1 - df_norm['ber']
        min_sr, max_sr = df_norm['success_rate'].min(), df_norm['success_rate'].max()
        if max_sr > min_sr:
             df_norm['success_rate_norm'] = (df_norm['success_rate'] - min_sr) / (max_sr - min_sr)
        else:
             # Assign 1.0 if BER is always 0 (always success), 0.0 if always 1 (always fail)
             df_norm['success_rate_norm'] = 1.0 if df_norm['ber'].iloc[0] == 0 else 0.0


        # Plot normalized values
        plt.plot(df_norm.index, df_norm['psnr_norm'], 'o-', label=normalized_labels['psnr'])
        plt.plot(df_norm.index, df_norm['ssim_norm'], 's-', label=normalized_labels['ssim'])
        plt.plot(df_norm.index, df_norm['capacity_norm'], '^-', label=normalized_labels['capacity'])
        plt.plot(df_norm.index, df_norm['success_rate_norm'], 'v-', label='Norm Success Rate (1-BER)')

        plt.title('Normalized Multi-Metric Performance Comparison')
        plt.xlabel('File Index')
        plt.ylabel('Normalized Value (0-1)')
        plt.legend(loc='best') # Let matplotlib choose best location
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.ylim(-0.05, 1.05) # Ensure scale is 0-1 with padding

        plt.tight_layout()
        output_path = os.path.join(output_dir, 'multi_metric_line.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        logger.info(f"Saved multi-metric line graph to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Error creating multi-metric line graph: {e}", exc_info=True)
        return False

def generate_all_graphs(batch_results, output_dir):
    """Generate all visualization graphs for batch processing results"""
    try:
        # Convert results list of dictionaries to DataFrame
        df = pd.DataFrame(batch_results)

        # --- Data Extraction/Cleaning ---
        # Handle potential nested 'metrics' dictionary
        if 'metrics' in df.columns:
            # Create a normalized DataFrame from the 'metrics' column
            # Handle potential non-dict entries gracefully
            metrics_list = [item if isinstance(item, dict) else {} for item in df['metrics']]
            metrics_df = pd.json_normalize(metrics_list).fillna(0.0) # Fill NaNs immediately

            # Combine original df with normalized metrics
            # Prioritize columns from metrics_df if names overlap
            # Use merge for safer combination based on index
            df = df.drop(columns=['metrics'], errors='ignore').merge(metrics_df, left_index=True, right_index=True, how='left')

        # Ensure required columns exist and handle potential NaNs introduced by merge or missing data
        required_columns = ['psnr', 'ssim', 'ber', 'capacity']
        # Add file_size if it exists, otherwise default to 0.0
        if 'file_size' not in df.columns:
            df['file_size'] = 0.0
        else:
            df['file_size'] = pd.to_numeric(df['file_size'], errors='coerce').fillna(0.0)

        for col in required_columns:
            if col not in df.columns:
                logger.warning(f"Missing essential column '{col}' for graphing, adding with default 0.0")
                df[col] = 0.0
            else:
                # Convert to numeric, coerce errors to NaN, then fill NaN with 0.0
                # Special handling for BER: fill NaN with 1.0 (worst case)
                fill_value = 1.0 if col == 'ber' else 0.0
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(fill_value)
        # --- End Data Extraction/Cleaning ---


        logger.info(f"Processing data for graphs: {df.shape[0]} rows")
        # Select only relevant columns for logging head to avoid excessive output
        log_cols = ['filename'] + required_columns + ['file_size']
        logger.debug(f"DataFrame head for graphing:\n{df[log_cols].head()}")

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Generate each graph type
        generated_graphs = []
        success_flags = {}

        # Call each plotting function and store success status
        # Assume plotting functions return True on success, False on failure
        success_flags['scatter'] = create_scatter_plots(df.copy(), output_dir) # Pass copy to avoid modifying df
        success_flags['line'] = create_multi_metric_line(df.copy(), output_dir) # Calls the updated function
        success_flags['radar'] = create_radar_chart(df.copy(), output_dir)

        # Collect names of successfully generated graphs
        if success_flags.get('scatter'): generated_graphs.append('scatter_plots.png')
        if success_flags.get('line'): generated_graphs.append('multi_metric_line.png')
        if success_flags.get('radar'): generated_graphs.append('radar_chart.png')

        if not generated_graphs:
            logger.error("No graphs were generated successfully")
            return {
                'success': False,
                'error': 'Failed to generate any graphs. Check logs for details.'
            }

        logger.info(f"Successfully generated {len(generated_graphs)} graphs: {', '.join(generated_graphs)}")
        return {
            'success': True,
            'graphs': generated_graphs # Return only the filenames
        }

    except Exception as e:
        # Use exc_info=True for full traceback in logs
        logger.error(f"Critical Error in generate_all_graphs: {str(e)}", exc_info=True)
        return {
            'success': False,
            'error': f'Unexpected error preparing data or generating graphs: {str(e)}'
        }