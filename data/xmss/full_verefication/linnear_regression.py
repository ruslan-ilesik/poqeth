import os
import csv
import numpy as np
from sklearn.linear_model import LinearRegression

def read_csv_for_regression(file_path):
    """
    Reads the CSV file and extracts the verify values.

    Parameters:
    file_path (str): Path to the CSV file

    Returns:
    list: List of verify values
    """
    verify_values = []

    with open(file_path, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        header = next(csvreader)  # Skip the header row

        for row in csvreader:
            verify = int(row[5])  # 'verify' is in the sixth column (index 5)
            verify_values.append(verify)

    return verify_values

def perform_linear_regression(verify_values):
    """
    Performs linear regression on the verify values using the position as an implicit independent variable.

    Parameters:
    verify_values (list): List of verify values

    Returns:
    tuple: The slope (coefficient) and intercept of the linear regression
    """
    # Generate indices (0, 1, 2, ...) for the verify values
    indices = np.arange(len(verify_values)).reshape(-1, 1)
    verify_values = np.array(verify_values)

    # Create and fit the linear regression model
    model = LinearRegression()
    model.fit(indices, verify_values)

    # Return the slope (coefficient) and intercept
    return model.coef_[0], model.intercept_

def main():
    # Get the directory of the current script
    script_dir = os.path.dirname(os.path.realpath(__file__))

    # Define the relative file path
    file_name = 'w_4_h_20.csv'  # Replace with your actual CSV file name
    file_path = os.path.join(script_dir, file_name)

    # Read the CSV file to get the verify values
    verify_values = read_csv_for_regression(file_path)

    # Perform linear regression
    slope, intercept = perform_linear_regression(verify_values)

    # Print the regression coefficients
    print(f"Linear Regression Coefficients:")
    print(f"Slope (Coefficient): {slope}")
    print(f"Intercept: {intercept}")

if __name__ == "__main__":
    main()
