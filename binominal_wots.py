import math
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
    # Using scipy.stats.binom.pmf
    probability = binom.pmf(k, n, p)
    return probability

# Example usage
n = 256
p = 0.5
k = 100  # Replace with the number of successes you want to calculate

# Calculate using scipy
# prob_scipy = binomial_pmf(n, p, k)



import csv

def sum_verify_values(file_path):
    verify_values_sum = 0

    with open(file_path, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        header = next(csvreader)  # Skip the header row
        for row in csvreader:
            verify_value = int(row[3])
            verify_values_sum += verify_value * binomial_pmf(n,p,int(row[0]))
    
    return verify_values_sum

def calculate_efficiency_improvement(sum_w1, sum_w2):
    if sum_w1 == 0:
        raise ValueError("Sum of verify_values for w1 is zero, cannot calculate improvement.")
    improvement = ((sum_w1 - sum_w2) / sum_w1) * 100
    return improvement

def main():
    # File paths for different w values
    file_path_w8 = '256.csv'
    file_path_w16 = '16.csv'
    file_path_w4 = '4.csv'
    # Calculate the sum of verify_values for each w
    sum_w8 = sum_verify_values(file_path_w8)
    sum_w16 = sum_verify_values(file_path_w16)
    sum_w4 = sum_verify_values(file_path_w4)
    
    print(f"Sum of verify_values using binominal for w=8: {sum_w8}")
    print(f"Sum of verify_values using binominal for w=16: {sum_w16}")
    print(f"Sum of verify_values using binominal for w=4: {sum_w4}")

    print("w=8 is",sum_w16/ (sum_w8/100.0) - 100,"% more efficient than w=16")
    print("w=8 is",sum_w4/ (sum_w8/100.0) - 100,"% more efficient than w=4")
if __name__ == "__main__":
    main()