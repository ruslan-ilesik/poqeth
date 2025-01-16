import pandas as pd
import os
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# Load the CSV file into a DataFrame
script_dir = os.path.dirname(os.path.abspath(__file__))
df = pd.read_csv(os.path.join(script_dir, 'results.csv'))

# Remove rows where verify_value is 'not found'
df = df[df['verify_value'] != 'not found']

# Convert columns to appropriate data types

df = df.astype({'h': int, 'd': int, 'a': int, 'k': int, 'setPk_max': int, 'verify_value': int})

# Determine the global color scale for verify_value
global_min_verify = df['verify_value'].min()
global_max_verify = df['verify_value'].max()
df_d_2_8 = df[df['d'].isin([2, 8])]

# Generate plots for d=2 and d=8
def generate_specific_d_plots(x_param, y_param, z_param, file_name):
    # Create a figure for the grid of 3D scatter plots
    fig = plt.figure(figsize=(20, 10))  # Adjust the figure size
    #fig.suptitle(f'3D Scatter Plots of verify_value for d=2 and d=8', fontsize=24)
    
    # Generate 3D scatter plots for d=2 and d=8
    d_values = [2, 8]
    for i, value in enumerate(d_values):
        # Filter the data for the current d value
        df_filtered = df_d_2_8[df_d_2_8['d'] == value]
        
        # Create a 3D subplot
        ax = fig.add_subplot(1, 2, i + 1, projection='3d')  # Two subplots: one for d=2, one for d=8
        
        # Plot the scatter plot with x_param, y_param, z_param as axes and verify_value as color
        scatter = ax.scatter(df_filtered[x_param], df_filtered[y_param], df_filtered[z_param], 
                             c=df_filtered['verify_value'], cmap='viridis', vmin=global_min_verify, vmax=global_max_verify)
        
        # Set plot labels and title
        ax.set_title(f'd={value}', fontsize=16)
        ax.set_xlabel(x_param, fontsize=14)
        ax.set_ylabel(y_param, fontsize=14)
        ax.set_zlabel(z_param, fontsize=14)

        # Add color bar to represent verify_value
        cbar = fig.colorbar(scatter, ax=ax, shrink=0.5)
        cbar.set_label('Gas', fontsize=14)

    # Adjust layout to prevent overlapping
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    # Save the plot as an image file
    output_file = os.path.join(script_dir, file_name)
    plt.savefig(output_file, dpi=300)  # Save with high resolution
    plt.close()

    print(f"Saved the 3D scatter plot for d=2 and d=8 to {output_file}")

# Function to generate 3D scatter plots for each parameter
def generate_plots(param, param_values, x_param, y_param, z_param, file_name):
    # Create a figure for the grid of 3D scatter plots
    fig = plt.figure(figsize=(40, 40))  # Large figure size
    #fig.suptitle(f'3D Scatter Plots of verify_value for each value of {param}', fontsize=24)
    
    # Number of subplots per row and column
    cols = 3
    rows = (len(param_values) + cols - 1) // cols  # Calculate the number of rows needed
    
    # Generate 3D scatter plots for each unique value of the parameter
    for i, value in enumerate(param_values):
        # Filter the data for the current parameter value
        df_filtered = df[df[param] == value]
        
        # Create a 3D subplot
        ax = fig.add_subplot(rows, cols, i + 1, projection='3d')
        
        # Plot the scatter plot with x_param, y_param, z_param as axes and verify_value as color
        scatter = ax.scatter(df_filtered[x_param], df_filtered[y_param], df_filtered[z_param], 
                             c=df_filtered['verify_value'], cmap='viridis', vmin=global_min_verify, vmax=global_max_verify)
        
        # Set plot labels and title
        ax.set_title(f'{param}={value}', fontsize=16)
        ax.set_xlabel(x_param, fontsize=14)
        ax.set_ylabel(y_param, fontsize=14)
        ax.set_zlabel(z_param, fontsize=14)

        # Add color bar to represent verify_value
        cbar = fig.colorbar(scatter, ax=ax, shrink=0.5)
        cbar.set_label('Gas', fontsize=14)

    # Adjust layout to prevent overlapping
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    # Save the plot as an image file
    output_file = os.path.join(script_dir, file_name)
    plt.savefig(output_file, dpi=300)  # Save with high resolution
    plt.close()

    print(f"Saved the 3D scatter plot grid to {output_file}")

# Unique values for each parameter
unique_a_values = sorted(df['a'].unique())
unique_h_values = sorted(df['h'].unique())
unique_d_values = sorted(df['d'].unique())
unique_k_values = sorted(df['k'].unique())


# Generate plots for specific k values
def generate_plots_specific_k(k_values, x_param, y_param, z_param, file_name):
    # Create a figure for the grid of 3D scatter plots
    fig = plt.figure(figsize=(20, 20))
    
    # Number of subplots per row and column
    cols = 2
    rows = (len(k_values) + cols - 1) // cols  # Calculate the number of rows needed
    
    # Generate 3D scatter plots for each specific value of k
    for i, k in enumerate(k_values):
        # Filter the data for the current k value
        df_filtered = df[df['k'] == k]
        
        # Create a 3D subplot
        ax = fig.add_subplot(rows, cols, i + 1, projection='3d')
        
        # Plot the scatter plot with x_param, y_param, z_param as axes and verify_value as color
        scatter = ax.scatter(df_filtered[x_param], df_filtered[y_param], df_filtered[z_param], 
                             c=df_filtered['verify_value'], cmap='viridis', vmin=global_min_verify, vmax=global_max_verify)
        
        # Set plot labels and title
        ax.set_title(f'k={k}', fontsize=16)
        ax.set_xlabel(x_param, fontsize=14)
        ax.set_ylabel(y_param, fontsize=14)
        ax.set_zlabel(z_param, fontsize=14)

        # Add color bar to represent verify_value
        cbar = fig.colorbar(scatter, ax=ax, shrink=0.5)
        cbar.set_label('Gas', fontsize=14)

    # Adjust layout to prevent overlapping
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    # Save the plot as an image file
    output_file = os.path.join(script_dir, file_name)
    plt.savefig(output_file, dpi=300)  # Save with high resolution
    plt.close()

    print(f"Saved the 3D scatter plot grid for specific k values to {output_file}")



# Generate plots for specific a values
def generate_plots_specific_a(a_values, x_param, y_param, z_param, file_name):
    # Create a figure for the grid of 3D scatter plots
    fig = plt.figure(figsize=(20, 20))
    
    # Number of subplots per row and column
    cols = 2
    rows = (len(a_values) + cols - 1) // cols  # Calculate the number of rows needed
    
    # Generate 3D scatter plots for each specific value of a
    for i, a in enumerate(a_values):
        # Filter the data for the current a value
        df_filtered = df[df['a'] == a]
        
        # Create a 3D subplot
        ax = fig.add_subplot(rows, cols, i + 1, projection='3d')
        
        # Plot the scatter plot with x_param, y_param, z_param as axes and verify_value as color
        scatter = ax.scatter(df_filtered[x_param], df_filtered[y_param], df_filtered[z_param], 
                             c=df_filtered['verify_value'], cmap='viridis', vmin=global_min_verify, vmax=global_max_verify)
        
        # Set plot labels and title
        ax.set_title(f'a={a}', fontsize=16)
        ax.set_xlabel(x_param, fontsize=14)
        ax.set_ylabel(y_param, fontsize=14)
        ax.set_zlabel(z_param, fontsize=14)

        # Add color bar to represent verify_value
        cbar = fig.colorbar(scatter, ax=ax, shrink=0.5)
        cbar.set_label('Gas', fontsize=14)

    # Adjust layout to prevent overlapping
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    # Save the plot as an image file
    output_file = os.path.join(script_dir, file_name)
    plt.savefig(output_file, dpi=300)  # Save with high resolution
    plt.close()

    print(f"Saved the 3D scatter plot grid for specific a values to {output_file}")

# Generate plots for specific h values
def generate_plots_specific_h(h_values, x_param, y_param, z_param, file_name):
    # Create a figure for the grid of 3D scatter plots
    fig = plt.figure(figsize=(20, 20))
    
    # Number of subplots per row and column
    cols = 2
    rows = (len(h_values) + cols - 1) // cols  # Calculate the number of rows needed
    
    # Generate 3D scatter plots for each specific value of h
    for i, h in enumerate(h_values):
        # Filter the data for the current h value
        df_filtered = df[df['h'] == h]
        
        # Create a 3D subplot
        ax = fig.add_subplot(rows, cols, i + 1, projection='3d')
        
        # Plot the scatter plot with x_param, y_param, z_param as axes and verify_value as color
        scatter = ax.scatter(df_filtered[x_param], df_filtered[y_param], df_filtered[z_param], 
                             c=df_filtered['verify_value'], cmap='viridis', vmin=global_min_verify, vmax=global_max_verify)
        
        # Set plot labels and title
        ax.set_title(f'h={h}', fontsize=16)
        ax.set_xlabel(x_param, fontsize=14)
        ax.set_ylabel(y_param, fontsize=14)
        ax.set_zlabel(z_param, fontsize=14)

        # Add color bar to represent verify_value
        cbar = fig.colorbar(scatter, ax=ax, shrink=0.5)
        cbar.set_label('Gas', fontsize=14)

    # Adjust layout to prevent overlapping
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    # Save the plot as an image file
    output_file = os.path.join(script_dir, file_name)
    plt.savefig(output_file, dpi=300)  # Save with high resolution
    plt.close()

    print(f"Saved the 3D scatter plot grid for specific h values to {output_file}")



#do for a h k specific parameters
# Generate plots for each parameter
generate_plots('a', unique_a_values, 'h', 'd', 'k', '3d_scatter_plots_grid_a.png')
generate_plots('h', unique_h_values, 'a', 'd', 'k', '3d_scatter_plots_grid_h.png')
generate_plots('d', unique_d_values, 'a', 'h', 'k', '3d_scatter_plots_grid_d.png')
generate_plots('k', unique_k_values, 'a', 'h', 'd', '3d_scatter_plots_grid_k.png')

generate_specific_d_plots('a', 'h', 'k', '3d_scatter_plots_d_2_8.png')

specific_k_values = [7, 23, 40, 60]
generate_plots_specific_k(specific_k_values, 'a', 'h', 'd', '3d_scatter_plots_specific_k.png')
specific_a_values = [4, 8, 16, 32]  # Example values, update as needed
specific_h_values = [3, 7, 13, 19]  #
generate_plots_specific_a(specific_a_values, 'h', 'd', 'k', '3d_scatter_plots_specific_a.png')
generate_plots_specific_h(specific_h_values, 'a', 'd', 'k', '3d_scatter_plots_specific_h.png')
