import csv
import matplotlib.pyplot as plt
import matplotlib
import math



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
    markers = {
        4 : "o",
        8: "s",
        16:"d",
        256:"p"
    }
    
    # Plot each dataset with a different color
    for w, (i_values, verify_values) in i_values_dict.items():
        # Use slicing to select every 5th element
        i_values_sliced = i_values[::5]
        verify_values_sliced = [math.log2(i) for i in verify_values[::5]]
        #plt.plot(i_values, verify_values, linestyle='-', label=f'w={w}') # Plot full line
        plt.plot(i_values_sliced, verify_values_sliced, marker=markers[w], linestyle='-', label=f'w={w}') # Plot every 5th dot
    
    
    plt.xlabel('Hamming weight of M')
    plt.ylabel('$log_2$(Gas cost)')
    plt.title('Verefication cost for WOTS+ with w={4, 8, 16, 256}')
    plt.legend()
    plt.grid(True)
    plt.show()

def main():
    i_values_dict = {}
    
    # Read the data for each value of w
    for w in [4, 8, 16, 256]:
        file_path = f'{w}.csv'
        i_values, verify_values = read_csv(file_path)
        i_values_dict[w] = (i_values, verify_values)
    
    # Plot the graphs on the same plot
    plot_graphs(i_values_dict, 'combined_plot.png')

if __name__ == "__main__":
    main()
