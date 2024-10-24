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

def weighted_average_verify(file_path, n, p, min_i=100, max_i=156):
    """
    Calculate the weighted average of verify values using the binomial distribution probabilities.
    
    Parameters:
    file_path (str): Path to the CSV file
    n (int): Number of trials (e.g., 256 for WOTS+)
    p (float): Probability of success (e.g., 0.5)
    min_i (int): Minimum i value to consider (e.g., 100)
    max_i (int): Maximum i value to consider (e.g., 156)
    
    Returns:
    float: Weighted average of verification values
    """
    total_weighted_verify = 0
    total_probability = 0

    with open(file_path, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        header = next(csvreader)  # Skip the header row
        for row in csvreader:
            i = int(row[2])  # 'i' is in the third column (index 2)
            verify_value = int(row[5])  # 'verify' is in the sixth column (index 5)

            # Only consider rows with i in the range [min_i, max_i]
            if min_i <= i <= max_i:
                k = i - min_i  # Adjust k relative to min_i
                prob = binomial_pmf(n, p, k)

                # Update total weighted verify and total probability
                total_weighted_verify += verify_value * prob
                total_probability += prob

    # Return the weighted average
    return total_weighted_verify / total_probability if total_probability > 0 else 0

def main():
    # Define the folder path
    folder_path = './xmss_data/'  # Replace with the correct folder path
    n = 256  # Number of trials (based on your description)
    p = 0.5  # Probability of success (e.g., 0.5 for uniform distribution)

    # Loop through all w and h values (adjust if needed)
    w_values = [4, 16]  # Adjust the w values as needed
    h_values = [4, 8, 16, 20]    # Adjust the h values as needed

    for w in w_values:
        for h in h_values:
            file_path = os.path.join(folder_path, f'w_{w}_h_{h}.csv')

            if os.path.exists(file_path):
                # Calculate the weighted average for the given w and h
                avg_verify = weighted_average_verify(file_path, n, p)

                # Print the results
                print(f"Average verification cost for w={w}, h={h}: {round(avg_verify)}")
            else:
                print(f"File not found: w_{w}_h{h}.csv")

if __name__ == "__main__":
    main()
