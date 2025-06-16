import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def plot_capacity_comparison_5ms(mitigated_csv_filepath, non_mitigated_csv_filepath, target_jitter=5.0):
    """
    Generates a single capacity comparison plot for a specific jitter value (default 5ms).
    It compares mitigated capacity, non-mitigated capacity, and theoretical capacity.
    """
    try:
        df_mitigated = pd.read_csv(mitigated_csv_filepath)
        df_non_mitigated = pd.read_csv(non_mitigated_csv_filepath)
    except FileNotFoundError as e:
        print(f"Error: File not found. {e}")
        return
    except Exception as e:
        print(f"Error reading CSV files: {e}")
        return

    required_cols = ['jitter', 'k', 'bps', 'capacity', 'ber']
    if not all(col in df_mitigated.columns for col in required_cols) or \
       not all(col in df_non_mitigated.columns for col in required_cols):
        print(f"Error: Both CSVs must contain {required_cols} columns.")
        return

    # Filter for the target jitter
    df_mitigated_jitter = df_mitigated[df_mitigated['jitter'] == target_jitter].copy()
    df_non_mitigated_jitter = df_non_mitigated[df_non_mitigated['jitter'] == target_jitter].copy()

    if df_mitigated_jitter.empty:
        print(f"No data found for jitter = {target_jitter}ms in {mitigated_csv_filepath}. Cannot generate comparison plot.")
        return

    # Merge the two dataframes on k and bps
    # We use the mitigated data as the base for (K,BPS) pairs
    df_comparison = pd.merge(
        df_mitigated_jitter,
        df_non_mitigated_jitter[['k', 'bps', 'capacity']],
        on=['k', 'bps'],
        suffixes=('_mitigated', '_non_mitigated'),
        how='left' # Keep all (K,BPS) from mitigated data
    )
    
    # Handle cases where non-mitigated data might be missing for a (K,BPS) pair
    df_comparison['capacity_non_mitigated'] = df_comparison['capacity_non_mitigated'].fillna(0)


    # Create x-axis labels and indices
    x_labels = [f"K={int(row['k'])}, BPS={int(row['bps'])}" for _, row in df_comparison.iterrows()]
    x_indices = np.arange(len(x_labels))

    # Calculate theoretical capacity
    df_comparison['theoretical_capacity'] = df_comparison.apply(
        lambda row: row['bps'] / row['k'] if row['k'] != 0 else 0, axis=1
    )

    mitigated_cap = df_comparison['capacity_mitigated']
    non_mitigated_cap = df_comparison['capacity_non_mitigated']
    theoretical_cap = df_comparison['theoretical_capacity']

    # --- Combined Capacity Bar Plot ---
    plt.figure(figsize=(18, 10)) # Adjusted figure size for potentially more labels
    bar_width = 0.25 # Adjusted for three bars

    plt.bar(x_indices - bar_width, mitigated_cap, bar_width, label='Mitigated Capacity', color='mediumpurple')
    plt.bar(x_indices, non_mitigated_cap, bar_width, label='Non-Mitigated Capacity', color='cornflowerblue')
    plt.bar(x_indices + bar_width, theoretical_cap, bar_width, label='Theoretical Capacity (bps/k)', color='sandybrown')
    
    plt.xlabel('(K, BPS) Combination')
    plt.ylabel('Capacity (Bits per Packet)')
    plt.title(f'Capacity Comparison (Jitter = {target_jitter}ms): Mitigated vs. Non-Mitigated vs. Theoretical')
    plt.xticks(x_indices, x_labels, rotation=45, ha="right")
    plt.legend()
    plt.grid(True, axis='y')
    plt.tight_layout()
    
    comparison_filename = f"capacity_comparison_jitter_{target_jitter}ms.png"
    plt.savefig(comparison_filename)
    print(f"Saved comparison plot to {comparison_filename}")
    plt.show()
    plt.close()


def plot_results_as_bars(csv_filepath='covert_channel_results.csv'):
    """
    Reads covert channel results and generates bar plots for capacity
    (measured vs. theoretical) and BER, with (K, BPS) combinations
    on the x-axis, separated by jitter.
    """
    try:
        df = pd.read_csv(csv_filepath)
    except FileNotFoundError:
        print(f"Error: The file {csv_filepath} was not found.")
        return
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return

    if not all(col in df.columns for col in ['jitter', 'k', 'bps', 'capacity', 'ber']):
        print("Error: CSV must contain 'jitter', 'k', 'bps', 'capacity', and 'ber' columns.")
        return

    jitters = df['jitter'].unique()

    for jitter_val in jitters:
        df_jitter = df[df['jitter'] == jitter_val].copy()

        if df_jitter.empty:
            print(f"No data found for jitter = {jitter_val}ms. Skipping plots.")
            continue

        # Create x-axis labels for (K, BPS) combinations, ensuring K and BPS are integers
        x_labels = [f"K={int(row['k'])}, BPS={int(row['bps'])}" for _, row in df_jitter.iterrows()]
        x_indices = np.arange(len(x_labels))

        # --- Capacity Bar Plot ---
        plt.figure(figsize=(15, 8))
        bar_width = 0.35

        measured_capacity = df_jitter['capacity']
        # Calculate theoretical capacity (bps / k)
        # Ensure k is not zero to avoid division by zero, though k should be > 0
        df_jitter['theoretical_capacity'] = df_jitter.apply(
            lambda row: row['bps'] / row['k'] if row['k'] != 0 else 0, axis=1
        )
        theoretical_capacity = df_jitter['theoretical_capacity']

        plt.bar(x_indices - bar_width/2, measured_capacity, bar_width, label='Measured Capacity', color='cornflowerblue')
        plt.bar(x_indices + bar_width/2, theoretical_capacity, bar_width, label='Theoretical Capacity (bps/k)', color='sandybrown')
        
        plt.xlabel('(K, BPS) Combination')
        plt.ylabel('Capacity (Bits per Packet)')
        plt.title(f'Covert Channel Capacity (Jitter = {jitter_val}ms)')
        plt.xticks(x_indices, x_labels, rotation=45, ha="right")
        plt.legend()
        plt.grid(True, axis='y')
        plt.tight_layout()
        # Modified filename prefix based on input csv for clarity if used
        base_filename = csv_filepath.split('/')[-1].replace('.csv', '')
        capacity_filename = f"{base_filename}_capacity_jitter_{jitter_val}ms.png"
        plt.savefig(capacity_filename)
        print(f"Saved capacity plot to {capacity_filename}")
        plt.show()
        plt.close() # Close the figure to free memory

        # --- BER Bar Plot ---
        plt.figure(figsize=(15, 8))
        
        ber_values = df_jitter['ber']
        
        plt.bar(x_indices, ber_values, bar_width, label='BER', color='mediumseagreen')
            
        plt.xlabel('(K, BPS) Combination')
        plt.ylabel('Bit Error Rate (BER)')
        plt.title(f'Bit Error Rate (BER) (Jitter = {jitter_val}ms)')
        plt.xticks(x_indices, x_labels, rotation=45, ha="right")
        plt.legend()
        plt.grid(True, axis='y')
        plt.tight_layout()
        ber_filename = f"{base_filename}_ber_jitter_{jitter_val}ms.png"
        plt.savefig(ber_filename)
        print(f"Saved BER plot to {ber_filename}")
        plt.show()
        plt.close() # Close the figure to free memory

if __name__ == '__main__':
    # plot_results_as_bars('covert_channel_results.csv')
    # plot_results_as_bars('mitigated_covert_channel_results.csv')
    
    # Call the new comparison function
    plot_capacity_comparison_5ms(
        mitigated_csv_filepath='mitigated_covert_channel_results.csv',
        non_mitigated_csv_filepath='covert_channel_results.csv'
    )
