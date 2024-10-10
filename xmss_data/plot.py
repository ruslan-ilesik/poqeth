import os
import pandas as pd
import matplotlib.pyplot as plt

def read_csv_files(folder_path):
    data_frames = []
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.csv'):
            file_path = os.path.join(folder_path, file_name)
            df = pd.read_csv(file_path)
            
            # Filter for h values 4, 8, 16, and 20
            df = df[df['h'].isin([4, 8, 16, 20])]
            
            data_frames.append(df)
    
    return pd.concat(data_frames, ignore_index=True)

def plot_graphs_grouped_by_w(data):
    unique_w_values = data['w'].unique()
    
    # Initialize dictionaries to store the cheapest and most expensive lines
    cheapest_lines = []
    most_expensive_lines = []
    
    for w in unique_w_values:
        subset = data[data['w'] == w]
        
        # Plot for each w value
        plt.figure(figsize=(12, 6))
        grouped = subset.groupby('h')
        for h, group in grouped:
            plt.plot(group['i'], group['verify'], marker='o', linestyle='-', label=f'h={h}')
        
        plt.xlabel('Hamming weight')
        plt.ylabel('verify')
        plt.title(f'Verification cost vs i for w={w}')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.show()
        
        # Identify cheapest and most expensive for this w
        min_verify_row = subset.loc[subset['verify'].idxmin()]
        max_verify_row = subset.loc[subset['verify'].idxmax()]
        
        cheapest_lines.append((w, subset[subset['verify'] == min_verify_row['verify']]))
        most_expensive_lines.append((w, subset[subset['verify'] == max_verify_row['verify']]))
    
    return cheapest_lines, most_expensive_lines


def plot_graphs_for_min_max_h(data):
    unique_w_values = data['w'].unique()
    
    plt.figure(figsize=(12, 6))
    
    for w in unique_w_values:
        subset = data[data['w'] == w]
        
        if not subset.empty:
            # Find minimum and maximum h for this subset
            min_h = subset['h'].min()
            max_h = subset['h'].max()
            
            # Filter rows where h is minimum or maximum
            min_h_subset = subset[subset['h'] == min_h]
            max_h_subset = subset[subset['h'] == max_h]
            
            # Plot lines for min_h and max_h
            if not min_h_subset.empty:
                plt.plot(min_h_subset['i'], min_h_subset['verify'], marker='o', linestyle='-', label=f'w={w}, h=min')
            if not max_h_subset.empty:
                plt.plot(max_h_subset['i'], max_h_subset['verify'], marker='x', linestyle='--', label=f'w={w}, h=max')

    plt.xlabel('Hamming weight')
    plt.ylabel('Gas')
    
    #plt.title('Verification Cost vs i for min and max h values across all w')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()


def plot_graphs_for_w4_and_w8(data):
    # Filter the data for w=4 and w=8
    subset_w4 = data[data['w'] == 4]
    subset_w16 = data[data['w'] == 16]

    # Plot for w=4
    plt.figure(figsize=(12, 6))
    
    grouped_w4 = subset_w4.groupby('h')
    markers=['o','v','d','+']
    cnt = 0
    for h, group in grouped_w4:
        plt.plot(group['i'], group['verify'], marker=markers[cnt], linestyle='-', label=f'w=4, h={h}')
        cnt+=1
    # Plot for w=8
    grouped_w16 = subset_w16.groupby('h')
    markers=['x','D','h','*']
    cnt = 0
    for h, group in grouped_w16:
        plt.plot(group['i'], group['verify'], marker=markers[cnt], linestyle='--', label=f'w=16, h={h}')
        cnt+=1

    # Set labels and title
    plt.xlabel('$\\vert\\vert M \\vert\\vert _1$')
    plt.ylabel('Gas')
    plt.yscale("log")
    
    # Show the legend, grid, and plot
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()



if __name__ == '__main__':
    folder_path = './xmss_data'  # Replace with the path to your folder
    data = read_csv_files(folder_path)
    
    # Extract only the required columns
    data = data[['w', 'h', 'i', 'verify']]
    # Plot w=4 and w=8 on the same plot
    plot_graphs_for_w4_and_w8(data)
    exit()
    # Plot graphs grouped by w and get lines for cheapest and most expensive
    cheapest_lines, most_expensive_lines = plot_graphs_grouped_by_w(data)
    plot_graphs_for_min_max_h(data)
