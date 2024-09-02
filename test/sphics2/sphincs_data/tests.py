import os
import pandas as pd
import numpy as np

script_dir = os.path.dirname(os.path.abspath(__file__))

# Load the CSV file into a DataFrame
df = pd.read_csv(os.path.join(script_dir, 'results.csv'))

# Filter out rows where 'verify_value' is not numeric
df['verify_value'] = pd.to_numeric(df['verify_value'], errors='coerce')

# Drop rows where 'verify_value' is NaN (which were non-numeric originally)
df = df.dropna(subset=['verify_value'])

# Convert 'verify_value' to integer (if necessary)
df['verify_value'] = df['verify_value'].astype(int)

# Print the minimum value in the 'verify_value' column
print(df['verify_value'].min())
