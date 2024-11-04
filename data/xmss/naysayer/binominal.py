import os
import csv
from scipy.stats import binom

def binomial_pmf(n, p, k):
    """
    Calculate the probability of getting exactly k successes in n trials
    with success probability p using the binomial distribution.
    
    Parameters:
    n (int): Number of trials
    p (float): Probability of success on each trial
    k (int): Number of successes
    
    Returns:
    float: Probability of getting exactly k successes
    """
    return binom.pmf(k, n, p)

def weighted_average_verify(file_path, n, p, min_i=100, max_i=156, column_index=5):
    """
    Calculate the weighted average of specific values using the binomial distribution probabilities.
    
    Parameters:
    file_path (str): Path to the CSV file
    n (int): Number of trials (e.g., 256 for WOTS+)
    p (float): Probability of success (e.g., 0.5)
    min_i (int): Minimum i value to consider (e.g., 100)
    max_i (int): Maximum i value to consider (e.g., 156)
    column_index (int): The index of the column containing the values to average (e.g., 'naysayerHT')
    
    Returns:
    float: Weighted average of values in the specified column
    """
    total_weighted_value = 0
    total_probability = 0

    with open(file_path, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        header = next(csvreader)  # Skip the header row
        for row in csvreader:
            i = int(row[2])  # 'i' is in the third column (index 2)
            value = int(row[column_index])  # Get the specific column value (e.g., 'naysayerHT')

            # Only consider rows with i in the range [min_i, max_i]
            if min_i <= i <= max_i:
                k = i - min_i  # Adjust k relative to min_i
                prob = binomial_pmf(n, p, k)

                # Update total weighted value and total probability
                total_weighted_value += value * prob
                total_probability += prob

    # Return the weighted average
    return total_weighted_value / total_probability if total_probability > 0 else 0

def main():
    # Define the folder path
    script_dir = os.path.dirname(os.path.realpath(__file__))
    folder_path = os.path.join(script_dir,'')  # Replace with the correct folder path
    n = 256  # Number of trials (based on your description)
    p = 0.5  # Probability of success (e.g., 0.5 for uniform distribution)

    # Define w and h values
    w_values = [4, 16]  # Adjust the w values as needed
    h_values = [4, 8, 16, 20]  # Adjust the h values as needed

    for w in w_values:
        avg_ht_str = f"w = {w} avg_ht: "
        avg_ltree_str = f"w = {w} avg_ltree: "
        avg_wots_str = f"w = {w} avg_wots: "

        for h in h_values:
            file_path = os.path.join(folder_path, f'w_{w}_h_{h}.csv')


            if os.path.exists(file_path):
                # Calculate the weighted averages for each of the three columns
                avg_ht = weighted_average_verify(file_path, n, p, column_index=5)
                avg_ltree = weighted_average_verify(file_path, n, p, column_index=6)
                avg_wots = weighted_average_verify(file_path, n, p, column_index=7)

                # Append the results to the respective strings
                avg_ht_str += f"${round(avg_ht):,}$&"
                avg_ltree_str += f"${round(avg_ltree):,}$&"
                avg_wots_str += f"${round(avg_wots):,}$&"
            else:
                print(f"File not found: w_{w}_h_{h}.csv")

        # Remove the trailing '&' and print the final strings for each `w`
        print(avg_ht_str.rstrip('&'))
        print(avg_ltree_str.rstrip('&'))
        print(avg_wots_str.rstrip('&'))

if __name__ == "__main__":
    main()
