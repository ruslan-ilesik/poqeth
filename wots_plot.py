import csv
import matplotlib.pyplot as plt
import matplotlib



def read_csv(file_path):
    i_values = []
    verify_values = []

    with open(file_path, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        header = next(csvreader)  # Skip the header row
        for row in csvreader:
            i = int(row[0])
            verify_value = int(row[3])
            i_values.append(i)
            verify_values.append(verify_value)
    
    return i_values, verify_values

def plot_graphs(i_values_dict, file_name):
    plt.figure(figsize=(12, 6))
    
    # Plot each dataset with a different color
    for w, (i_values, verify_values) in i_values_dict.items():
        plt.plot(i_values, verify_values, marker='o', linestyle='-', label=f'verify_value for w={w}')
    
    plt.xlabel('i')
    plt.ylabel('verify_value')
    plt.title('Graph of verify_value vs. i for different w values')
    plt.legend()
    plt.grid(True)
    plt.show()

def main():
    i_values_dict = {}
    
    # Read the data for each value of w
    for w in [8, 16]:
        file_path = f'{w}.csv'
        i_values, verify_values = read_csv(file_path)
        i_values_dict[w] = (i_values, verify_values)
    
    # Plot the graphs on the same plot
    plot_graphs(i_values_dict, 'combined_plot.png')

if __name__ == "__main__":
    main()
