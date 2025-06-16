import os
import csv
import re
from collections import defaultdict

def analyze_detection_results():
    """
    Reads detection results from CSV files in subdirectories,
    stores the data, and calculates detection statistics.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, '.', 'data')

    all_data = {}
    detection_stats = defaultdict(lambda: {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0})

    if not os.path.isdir(data_dir):
        print(f"Error: Data directory not found at {data_dir}")
        return

    # Regex to parse K and BPS from folder names like K0_BPS0
    folder_pattern = re.compile(r"K(\d+)_BPS(\d+)")

    for subfolder_name in os.listdir(data_dir):
        match = folder_pattern.fullmatch(subfolder_name)
        if not match:
            # print(f"Skipping folder (does not match pattern K<num>_BPS<num>): {subfolder_name}")
            continue

        k_val = int(match.group(1))
        bps_val = int(match.group(2))
        config_key = (k_val, bps_val)
        
        current_subfolder_path = os.path.join(data_dir, subfolder_name)
        if not os.path.isdir(current_subfolder_path):
            continue

        csv_file_found = False
        for file_name in os.listdir(current_subfolder_path):
            if file_name.startswith("detection_results") and file_name.endswith(".csv"):
                csv_file_path = os.path.join(current_subfolder_path, file_name)
                
                frames_data = []
                try:
                    with open(csv_file_path, mode='r', newline='') as infile:
                        reader = csv.DictReader(infile)
                        for row in reader:
                            frames_data.append(row)
                    all_data[config_key] = frames_data
                    csv_file_found = True
                    # print(f"Successfully read {len(frames_data)} frames from {csv_file_path} for config {config_key}")
                    break 
                except Exception as e:
                    print(f"Error reading CSV file {csv_file_path}: {e}")
                    continue
        
        if not csv_file_found:
            print(f"Warning: No 'detection_results*.csv' file found in {current_subfolder_path}")

    # Calculate statistics
    for config_key, frames in all_data.items():
        k_val, bps_val = config_key
        
        # Ground truth: Covert channel is present unless K=0 and BPS=0
        is_actually_covert = not (k_val == 0 and bps_val == 0)
        
        stats = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0}
        
        if not frames:
            print(f"Warning: No data frames found for config {config_key} to calculate stats.")
            detection_stats[config_key] = stats
            continue

        for frame in frames:
            try:
                detected_covert_val = int(frame.get('DetectedCovertChannel', 0)) # Default to 0 if missing
                detected_covert = (detected_covert_val == 1)
            except ValueError:
                print(f"Warning: Invalid 'DetectedCovertChannel' value '{frame.get('DetectedCovertChannel')}' in a frame for {config_key}. Skipping frame for stats.")
                continue

            if is_actually_covert: # Actual Positive case
                if detected_covert:
                    stats['TP'] += 1
                else:
                    stats['FN'] += 1
            else: # Actual Negative case (K0_BPS0)
                if detected_covert:
                    stats['FP'] += 1
                else:
                    stats['TN'] += 1
        
        detection_stats[config_key] = stats

    # Print the results
    print("\n--- Detection Data Summary ---")
    if not all_data:
        print("No data was loaded.")
    # for config, data_rows in all_data.items():
    #     print(f"Config {config}: {len(data_rows)} frames loaded.")
        # For brevity, not printing all rows. User can inspect `all_data` if needed.

    print("\n--- Detection Statistics ---")
    if not detection_stats:
        print("No statistics calculated.")
    
    sorted_stats = sorted(detection_stats.items())

    for config, stats in sorted_stats:
        print(f"Config (K={config[0]}, BPS={config[1]}):")
        print(f"  True Positives (TP):  {stats['TP']}")
        print(f"  False Positives (FP): {stats['FP']}")
        print(f"  True Negatives (TN):  {stats['TN']}")
        print(f"  False Negatives (FN): {stats['FN']}")
        total_frames = stats['TP'] + stats['FN'] + stats['FP'] + stats['TN']
        print(f"  Total Frames Processed: {total_frames}")

        precision = 0.0
        recall = 0.0
        f1_score = 0.0

        if (stats['TP'] + stats['FP']) > 0:
            precision = stats['TP'] / (stats['TP'] + stats['FP'])
            print(f"  Precision:            {precision:.4f}")
        else:
            print(f"  Precision:            N/A (TP+FP=0)")

        if (stats['TP'] + stats['FN']) > 0:
            recall = stats['TP'] / (stats['TP'] + stats['FN']) # Also Sensitivity
            print(f"  Recall (Sensitivity): {recall:.4f}")
        else:
            print(f"  Recall (Sensitivity): N/A (TP+FN=0)")

        if (stats['TN'] + stats['FP']) > 0:
            specificity = stats['TN'] / (stats['TN'] + stats['FP'])
            print(f"  Specificity:          {specificity:.4f}")
        else:
            print(f"  Specificity:          N/A (TN+FP=0)")

        if (precision + recall) > 0:
            f1_score = 2 * (precision * recall) / (precision + recall)
            print(f"  F1-Score:             {f1_score:.4f}")
        else:
            print(f"  F1-Score:             N/A (Precision+Recall=0)")
        
        print("-" * 20)

    return all_data, detection_stats

if __name__ == "__main__":
    all_data_loaded, calculated_stats = analyze_detection_results()
    # You can further process all_data_loaded and calculated_stats if needed
    print("\nScript finished.")
