import math
import os
from scipy.stats import binom
import csv

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
    # Using scipy.stats.binom.pmf
    return binom.pmf(k, n, p)

def weighted_average_verify(file_path, n, p):
    """
    Calculate the weighted average of verify values using the binomial distribution probabilities.
    
    Parameters:
    file_path (str): Path to the CSV file
    n (int): Number of trials (e.g., 256 for WOTS+)
    p (float): Probability of success (e.g., 0.5)
    
    Returns:
    float: Weighted average of verification values
    """
    total_weighted_verify = 0
    total_probability = 0

    with open(file_path, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        header = next(csvreader)  # Skip the header row
        for row in csvreader:
            k = int(row[0])  # This assumes that 'k' (Hamming weight) is in the first column
            verify_value = int(row[3])  # Assuming verification value is in the fourth column

            # Calculate binomial probability for this k
            prob = binomial_pmf(n, p, k)

            # Update total weighted verify and total probability
            total_weighted_verify += verify_value * prob
            total_probability += prob

    # Return the weighted average
    return total_weighted_verify / total_probability if total_probability > 0 else 0

def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    # Define the prefix path
    prefix_path = os.path.join(script_dir,'')  # Replace with the correct folder path
    n = 256  # For example, WOTS+ uses n = 256
    p = 0.5  # Probability of success (e.g., 0.5 for uniform distribution)

    # File paths for different w values
    file_paths = {
        'w4': os.path.join(prefix_path, '4.csv'),
        'w8': os.path.join(prefix_path, '8.csv'),
        'w16': os.path.join(prefix_path, '16.csv'),
        'w256': os.path.join(prefix_path, '256.csv')
    }
    
    # Calculate the average verification cost for each w value
    avg_w4 = weighted_average_verify(file_paths['w4'], n, p)
    avg_w8 = weighted_average_verify(file_paths['w8'], n, p)
    avg_w16 = weighted_average_verify(file_paths['w16'], n, p)
    avg_w256 = weighted_average_verify(file_paths['w256'], n, p)
    
    # Print the average verification values
    print(f"Average verification cost using binominal for w=4: {avg_w4}")
    print(f"Average verification cost using binominal for w=8: {avg_w8}")
    print(f"Average verification cost using binominal for w=16: {avg_w16}")
    print(f"Average verification cost using binominal for w=256: {avg_w256}")

if __name__ == "__main__":
    main()
