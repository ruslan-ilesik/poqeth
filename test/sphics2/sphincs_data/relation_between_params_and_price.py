import pandas as pd
import matplotlib.pyplot as plt
import os

# Load data from results.csv based on the script location
script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, 'results.csv')
df = pd.read_csv(file_path)
df = df[df['verify_value'] != 'not found']
# Ensure correct data types for calculations
df = df.astype({'h': int, 'd': int, 'a': int, 'k': int, 'verify_value': int})

# Initialize a figure for subplots
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
parameters = ['h', 'd', 'a', 'k']
axes = axes.flatten()

# Plot average verify_value for each parameter
for i, param in enumerate(parameters):
    # Group by the parameter and calculate the average verify_value
    avg_values = df.groupby(param)['verify_value'].mean()
    
    # Plotting
    axes[i].plot(avg_values.index, avg_values.values, marker='o', color='blue', linestyle='-')
    axes[i].set_xlabel(param)
    axes[i].set_ylabel('Average verify_value')
    axes[i].set_title(f'Impact of {param} on Average verify_value')
    axes[i].grid(True)

plt.tight_layout()
plt.show()


# Filter data to only include rows with the minimum value of 'd'
min_d_value = df['d'].min()
filtered_df = df[df['d'] == min_d_value]

# Initialize a figure for subplots
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
parameters = ['h', 'a', 'k']

# Plot average verify_value for each parameter with the minimum value of 'd'
for i, param in enumerate(parameters):
    # Group by the parameter and calculate the average verify_value
    avg_values = filtered_df.groupby(param)['verify_value'].mean()
    
    # Plotting
    axes[i].plot(avg_values.index, avg_values.values, marker='o', color='blue', linestyle='-')
    axes[i].set_xlabel(param)
    axes[i].set_ylabel('Average verify_value')
    axes[i].set_title(f'Impact of {param} on Average verify_value (d = {min_d_value})')
    axes[i].grid(True)

plt.tight_layout()
plt.show()